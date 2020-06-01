package malbazaar

import (
	"crypto/rand"
	"time"

	"github.com/pimmytrousers/malanalytics/collector/malware"
	log "github.com/sirupsen/logrus"
)

type Malbazaar struct {
	SampleStream chan *malware.Malware
}

// ShareMalChannel SHOULD share set the channel to the same one being used by the collector struct
func (m *Malbazaar) GetChan() chan *malware.Malware {
	if m.SampleStream == nil {
		m.SampleStream = make(chan *malware.Malware)
	}
	return m.SampleStream
}

// GetSamples is a mock of how the samples will be pushed through the pipe
func (m *Malbazaar) GetSamples() error {
	for {
		mockSample := make([]byte, 4)
		_, err := rand.Read(mockSample)
		if err != nil {
			return err
		}
		time.Sleep(time.Second * 1)
		sample := &malware.Malware{}
		sample.RawBytes = mockSample
		log.Debugf("sending sample %v through chan", sample.RawBytes)
		m.SampleStream <- sample
	}
}
