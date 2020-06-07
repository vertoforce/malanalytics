package malbazaar

import (
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pimmytrousers/melk/collector/malware"
)

type MalbazaarResp struct {
	QueryStatus string            `json:"query_status"`
	Samples     []MalBazaarSample `json:"data"`
}

type MalBazaarSample struct {
	Sha256Hash   string   `json:"sha256_hash"`
	Sha1Hash     string   `json:"sha1_hash"`
	Md5Hash      string   `json:"md5_hash"`
	FirstSeen    string   `json:"first_seen"`
	LastSeen     string   `json:"last_seen"`
	FileName     string   `json:"file_name"`
	FileSize     int      `json:"file_size"`
	FileTypeMIME string   `json:"file_type_mime"`
	FileType     string   `json:"file_type"`
	Reporter     string   `json:"reporter"`
	Anonymous    int      `json:"anonymous"`
	Signature    string   `json:"signature"`
	Imphash      string   `json:"imphash"`
	Tlsh         string   `json:"tlsh"`
	Ssdeep       string   `json:"ssdeep"`
	Tags         []string `json:"tags"`
}

const (
	src = "malbazaar"
)

type Malbazaar struct {
	ExternalSampleStream chan *malware.Malware
	stream               chan *MalBazaarSample
	SeenQueue            *keyQueue
}

// MalwareChannel Source of malware from malbazaar
func (m *Malbazaar) MalwareChannel() chan *malware.Malware {
	if m.ExternalSampleStream == nil {
		m.ExternalSampleStream = make(chan *malware.Malware)
	}
	return m.ExternalSampleStream
}

// Start just pumps mock samples for now
func (m *Malbazaar) Start() error {
	q := newKeyQueue(1000)
	m.SeenQueue = q

	m.stream = make(chan *MalBazaarSample)
	go m.startSampleChurn()

	for s := range m.stream {

		mockSample := make([]byte, 4)
		_, err := rand.Read(mockSample)
		if err != nil {
			return err
		}
		// time.Sleep(time.Millisecond * 250)
		sample := &malware.Malware{}
		sample.Src = src
		sample.RawBytes = mockSample
		sample.Tags = s.Tags
		sample.FileName = s.FileName
		sample.FileType = s.FileType
		sample.SsDeep = s.Ssdeep
		m.ExternalSampleStream <- sample
	}

	return nil
}

func (m *Malbazaar) startSampleChurn() error {
	baseUrl := "https://mb-api.abuse.ch/api/v1/"
	vals := url.Values{}

	vals.Add("query", "get_recent")
	vals.Add("selector", "100")

	for {
		resp, err := http.Post(baseUrl, "application/x-www-form-urlencoded", strings.NewReader(vals.Encode()))
		if err != nil {
			return err
		}

		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		queryResults := MalbazaarResp{}

		err = json.Unmarshal(content, &queryResults)
		if err != nil {
			return err
		}

		for _, s := range queryResults.Samples {
			if !m.SeenQueue.doesExist(s.Sha256Hash) {
				m.stream <- &s
				m.SeenQueue.add(s.Sha256Hash)
			}
		}
		time.Sleep(10 * time.Second)
	}

}
