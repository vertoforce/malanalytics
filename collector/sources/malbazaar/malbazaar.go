package malbazaar

import (
	"context"
	"io/ioutil"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pimmytrousers/melk/collector/malware"
	baz "github.com/vertoforce/go-malwarebazaar"
)

const (
	src = "malbazaar"
)

type Malbazaar struct {
	ExternalSampleStream chan *malware.Malware
	stream               chan *baz.Entry
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
func (m *Malbazaar) Start(logger *log.Logger) error {
	q := newKeyQueue(1000)
	m.SeenQueue = q

	m.stream = make(chan *baz.Entry)
	go m.startSampleChurn()

	for s := range m.stream {
		rc, err := baz.Download(context.Background(), s.Sha256Hash)
		if err != nil {
			continue
		}

		decryptedCloser, err := baz.GetRawFile(rc)
		if err != nil {
			continue
		}

		rawBytes, err := ioutil.ReadAll(decryptedCloser)
		if err != nil {
			continue
		}

		sample := &malware.Malware{}
		sample.Src = src
		sample.RawBytes = rawBytes
		sample.Tags = s.Tags
		sample.FileName = s.FileName
		sample.Family = s.Signature
		sample.FileType = s.FileType
		sample.SsDeep = s.Ssdeep
		m.ExternalSampleStream <- sample
	}

	return nil
}

func (m *Malbazaar) startSampleChurn() error {
	for {
		entries, err := baz.QueryLatest(context.Background(), baz.CountSelect)
		if err != nil {
			return err
		}

		for _, s := range entries {
			if !m.SeenQueue.doesExist(s.Sha256Hash) {
				m.stream <- &s
				m.SeenQueue.add(s.Sha256Hash)
			}
		}
		time.Sleep(10 * time.Minute)
	}
}
