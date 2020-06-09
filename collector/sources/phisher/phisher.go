package phisher

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/PuerkitoBio/goquery"
	"github.com/pimmytrousers/melk/collector/malware"
)

const (
	src             = "kitphishr"
	maxDownloadSize = 100 * 1024 * 1024
)

type Phisher struct {
	httpCli              *http.Client
	ExternalSampleStream chan *malware.Malware
	SeenQueue            *keyQueue
	urlStream            chan *PhishTankElement
	getFinalURLStream    chan *PhishKit
	phishKitStream       chan *PhishKit
	timeout              int
}

// MalwareChannel Source of malware from malbazaar
func (p *Phisher) MalwareChannel() chan *malware.Malware {
	if p.ExternalSampleStream == nil {
		p.ExternalSampleStream = make(chan *malware.Malware)
	}
	return p.ExternalSampleStream
}

// Start just pumps mock samples for now
func (p *Phisher) Start(logger *log.Logger) error {

	var tr = &http.Transport{
		MaxConnsPerHost:   50,
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Second * time.Duration(p.timeout),
			DualStack: true,
		}).DialContext,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * time.Duration(p.timeout),
	}

	p.httpCli = client

	q := newKeyQueue(1000)
	p.SeenQueue = q

	p.getFinalURLStream = make(chan *PhishKit)
	p.phishKitStream = make(chan *PhishKit)
	p.urlStream = make(chan *PhishTankElement)
	p.ExternalSampleStream = make(chan *malware.Malware)

	go p.startURLChurn()

	go p.getFinalURL()

	go p.actuallyGetZip(logger)

	for s := range p.phishKitStream {
		mockSample := make([]byte, 4)
		_, err := rand.Read(mockSample)
		if err != nil {
			return err
		}
		// time.Sleep(time.Millisecond * 250)
		sample := &malware.Malware{}
		sample.Src = src
		sample.RawBytes = s.Content
		sample.FileType = "zip"

		tags := []string{}
		if s.URLEntry.URL != "" {
			tags = append(tags, "src-"+s.URLEntry.URL)
		}
		if s.URLEntry.Target != "" {
			tags = append(tags, "target-"+s.URLEntry.Target)
		}
		if s.URLEntry.PhishID != "" {
			tags = append(tags, "phishID-"+s.URLEntry.PhishID)
		}

		sample.Tags = tags
		fmt.Printf("sending %v into pipe unified malware pipe", sample)
		p.ExternalSampleStream <- sample
	}

	return nil
}

func (p *Phisher) actuallyGetZip(logger *log.Logger) {
	wg := sync.WaitGroup{}
	for i := 0; i < 45; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			for resp := range p.getFinalURLStream {

				requrl := resp.URLEntry.URL

				logger.WithFields(log.Fields{
					"status": resp.URLEntry.Online,
					"target": resp.URLEntry.Target,
				}).Warnf("phish URL: %s", requrl)

				// if we found a zip from a URL path
				if strings.HasSuffix(requrl, ".zip") {

					// make sure it's a valid zip

					if resp.Size > 0 && resp.Size < maxDownloadSize && strings.Contains(resp.ContentType, "zip") {
						logger.Infof("sending kit %s", requrl)
						p.phishKitStream <- resp
					}
				}

				href, err := zipFromDir(*resp)
				if err != nil {
					continue
				}
				if href != "" {
					hurl := ""
					if strings.HasSuffix(requrl, "/") {
						hurl = requrl + href
					} else {
						hurl = requrl + "/" + href
					}

					resp2, err := p.attemptTarget(hurl)
					if err != nil {
						continue
					}

					resp2.URLEntry = resp.URLEntry
					logger.Infof("sending kit %s", requrl)
					p.phishKitStream <- resp2
					continue

				}
			}
		}()

	}
}

func (p *Phisher) getFinalURL() {
	wg := sync.WaitGroup{}
	for i := 0; i < 45; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			for entry := range p.urlStream {
				requrl := entry.URL
				res, err := p.attemptTarget(requrl)
				if err != nil {
					continue
				}

				res.URLEntry = entry

				p.getFinalURLStream <- res
			}
		}()

	}
}

func (p *Phisher) startURLChurn() {
	pturl := "http://data.phishtank.com/data/online-valid.json"

	// if the user has their own phishtank api key, use it
	apiKey := os.Getenv("PT_API_KEY")
	if apiKey != "" {
		pturl = fmt.Sprintf("http://data.phishtank.com/data/%s/online-valid.json", apiKey)
	}

	for {
		resp, err := http.Get(pturl)
		if err != nil {
			return
		}

		defer resp.Body.Close()
		var phishingSites []PhishTankElement

		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		respByte := buf.Bytes()
		if err := json.Unmarshal(respByte, &phishingSites); err != nil {
			return
		}

		for _, entry := range phishingSites {
			p.urlStream <- &entry
		}

		time.Sleep(10 * time.Minute)
	}
}

func (p *Phisher) attemptTarget(url string) (*PhishKit, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36")
	req.Header.Add("Connection", "close")
	req.Close = true

	httpresp, err := p.httpCli.Do(req)
	if err != nil {
		return nil, err
	}

	defer httpresp.Body.Close()

	resp := &PhishKit{}

	if respbody, err := ioutil.ReadAll(httpresp.Body); err == nil {
		resp.Content = respbody
	}

	resp.Size = httpresp.ContentLength
	resp.ContentType = httpresp.Header.Get("Content-Type")

	return resp, nil

}

func zipFromDir(resp PhishKit) (string, error) {

	ziphref := ""

	// read body for hrefs
	data := bytes.NewReader(resp.Content)
	doc, err := goquery.NewDocumentFromReader(data)
	if err != nil {
		return ziphref, err
	}

	title := doc.Find("title").Text()

	if strings.Contains(title, "Index of /") {
		doc.Find("a").Each(func(i int, s *goquery.Selection) {
			if strings.Contains(s.Text(), ".zip") {
				ziphref = s.Text()
			}
		})
	}

	return ziphref, nil
}
