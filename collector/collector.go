package collector

import (
	"fmt"
	"sync"

	"github.com/pimmytrousers/malanalytics/collector/sources"
	log "github.com/sirupsen/logrus"
)

type SourceID int

//go:generate stringer -type=SourceID
const (
	Malbazaar SourceID = iota
)

type malwareSource interface {
	GetSamples() error
	GetChan() chan *sources.Malware
}

// Collector is the main type that is returned, the channel under Collector is the pipe where all the malware goes
type Collector struct {
	differentSources map[SourceID]malwareSource
	orderedKeys      []SourceID
	SampleStream     chan *sources.Malware
}

var totalSources map[SourceID]malwareSource

func init() {
	totalSources = map[SourceID]malwareSource{
		Malbazaar: sources.Malbazaar{},
	}
}

func merge(cs ...chan *sources.Malware) chan *sources.Malware {
	out := make(chan *sources.Malware)
	var wg sync.WaitGroup
	wg.Add(len(cs))
	for _, c := range cs {
		go func(c <-chan *sources.Malware) {
			for v := range c {
				out <- v
			}
			wg.Done()
		}(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// GetSamples starts each sources GetSample in a goroutine. These goroutines will start sending malware samples through the channel
func (c *Collector) GetSamples() error {
	chans := []chan *sources.Malware{}
	for _, src := range c.differentSources {
		chans = append(chans, src.GetChan())
	}
	singleChan := merge(chans...)

	c.SampleStream = singleChan

	for k, src := range c.differentSources {
		log.Debugf("starting go routine for %s", k)
		go src.GetSamples()
	}

	return nil
}

// New returns a collector object with the built in sources
func New(sourceIDs []SourceID, maxSamples int) (*Collector, error) {
	c := &Collector{}

	ch := make(chan *sources.Malware, maxSamples)
	c.SampleStream = ch

	c.differentSources = map[SourceID]malwareSource{}

	for _, sourceKey := range sourceIDs {
		if _, ok := totalSources[sourceKey]; ok {
			log.Debugf("initializing source %s", sourceKey)
			c.orderedKeys = append(c.orderedKeys, sourceKey)
			c.differentSources[sourceKey] = totalSources[sourceKey]
		} else {
			return nil, fmt.Errorf("unknown parser type %d", sourceKey)
		}
	}

	return c, nil
}
