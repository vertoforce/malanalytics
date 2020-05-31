package sources

import (
	"crypto/rand"
	"time"

	log "github.com/sirupsen/logrus"
)

type Malbazaar struct {
	SampleStream chan *Malware
}

// ShareMalChannel SHOULD share set the channel to the same one being used by the collector struct
func (m Malbazaar) GetChan() chan *Malware {
	return m.SampleStream
}

// GetSamples is a mock of how the samples will be pushed through the pipe
func (m Malbazaar) GetSamples() error {
	for {

		mockSample := make([]byte, 4)
		_, err := rand.Read(mockSample)
		if err != nil {
			return err
		}
		time.Sleep(time.Second * 1)
		sample := &Malware{}
		sample.RawBytes = mockSample
		log.Debugf("sending sample %v through chan", sample.RawBytes)
		m.SampleStream <- sample
	}
}
