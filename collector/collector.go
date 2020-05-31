package collector

import (
	"github.com/pimmytrousers/malanalytics/collector/malware"
	log "github.com/sirupsen/logrus"
)

// Collector is the main type that is returned, the channel under Collector is the pipe where all the malware goes
type Collector struct {
	selectedSources []MalwareSource
	SampleStream    chan *malware.Malware
}

// Start gets malware from each malware source and aggregates to one channel
func (c *Collector) Start() error {
	malwareChannels := []chan *malware.Malware{}
	for _, src := range c.selectedSources {
		malwareChannels = append(malwareChannels, src.MalwareChannel())
	}
	masterMalwareChannel := merge(malwareChannels...)

	c.SampleStream = masterMalwareChannel

	for k, src := range c.selectedSources {
		log.Debugf("starting go routine for %s", k)
		go src.Start()
	}

	return nil
}

// New returns a collector object with the built in sources
func New(sources []MalwareSource) (*Collector, error) {
	c := &Collector{
		selectedSources: sources,
		SampleStream:    make(chan *malware.Malware),
	}

	return c, nil
}
