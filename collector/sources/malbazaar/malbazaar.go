package malbazaar

import (
	"crypto/rand"
	"time"

	"github.com/pimmytrousers/malanalytics/collector/malware"
)

type Malbazaar struct {
	SampleStream chan *malware.Malware
}

// MalwareChannel Source of malware from malbazaar
func (m *Malbazaar) MalwareChannel() chan *malware.Malware {
	if m.SampleStream == nil {
		m.SampleStream = make(chan *malware.Malware)
	}
	return m.SampleStream
}

// Start just pumps mock samples for now
func (m *Malbazaar) Start() error {
	for {
		mockSample := make([]byte, 4)
		_, err := rand.Read(mockSample)
		if err != nil {
			return err
		}
		time.Sleep(time.Second * 1)
		sample := &malware.Malware{}
		sample.RawBytes = mockSample
		m.SampleStream <- sample
	}
}
