package mock

import (
	"crypto/rand"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pimmytrousers/melk/collector/malware"
)

const (
	src = "mock"
)

type Mock struct {
	ExternalSampleStream chan *malware.Malware
}

// MalwareChannel Source of malware from malbazaar
func (m *Mock) MalwareChannel() chan *malware.Malware {
	if m.ExternalSampleStream == nil {
		m.ExternalSampleStream = make(chan *malware.Malware)
	}
	return m.ExternalSampleStream
}

// Start just pumps mock samples for now
func (m *Mock) Start(logger *log.Logger) error {
	for {
		token := make([]byte, 4)
		rand.Read(token)

		sample := &malware.Malware{}
		sample.Src = src
		sample.RawBytes = token
		m.ExternalSampleStream <- sample

		time.Sleep(time.Second * 3)
	}

	return nil
}
