package collector

import (
	"math/rand"
	"time"
)

type Source int

const (
	Malbazaar Source = iota
)

type Collector struct {
	SampleStream chan []byte
}

func New(sources []Source, maxSamples int) (*Collector, error) {
	c := &Collector{}
	ch := make(chan []byte, maxSamples)
	c.SampleStream = ch
	return c, nil
}

// function meant to run as a go routine
func (c *Collector) GetSamples() error {
	for {
		mockSample := make([]byte, 4)
		_, err := rand.Read(mockSample)
		if err != nil {
			return err
		}
		time.Sleep(time.Second * 1)
		c.SampleStream <- mockSample
	}

}
