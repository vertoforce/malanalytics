package collector

import (
	"fmt"
	"sync"

	"github.com/pimmytrousers/malanalytics/collector/malware"
	"github.com/pimmytrousers/malanalytics/collector/sources/malbazaar"
	log "github.com/sirupsen/logrus"
)

type SourceID int

//go:generate stringer -type=SourceID
const (
	Malbazaar SourceID = iota
)

type malwareSource interface {
	GetSamples() error
	GetChan() chan *malware.Malware
}

// Collector is the main type that is returned, the channel under Collector is the pipe where all the malware goes
type Collector struct {
	selectedSources map[SourceID]malwareSource
	SampleStream    chan *malware.Malware
}

// allSources is a map of all our sources by source id
var allSources map[SourceID]malwareSource

func init() {
	allSources = map[SourceID]malwareSource{
		Malbazaar: &malbazaar.Malbazaar{},
	}
}

func merge(cs ...chan *malware.Malware) chan *malware.Malware {
	out := make(chan *malware.Malware)
	var wg sync.WaitGroup
	wg.Add(len(cs))
	for _, c := range cs {
		go func(c <-chan *malware.Malware) {
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
	chans := []chan *malware.Malware{}
	for _, src := range c.selectedSources {
		chans = append(chans, src.GetChan())
	}
	singleChan := merge(chans...)

	c.SampleStream = singleChan

	for k, src := range c.selectedSources {
		log.Debugf("starting go routine for %s", k)
		go src.GetSamples()
	}

	return nil
}

// New returns a collector object with the built in sources
func New(sourceIDs []SourceID, maxSamples int) (*Collector, error) {
	c := &Collector{}

	ch := make(chan *malware.Malware, maxSamples)
	c.SampleStream = ch

	c.selectedSources = map[SourceID]malwareSource{}

	for _, sourceKey := range sourceIDs {
		if _, ok := allSources[sourceKey]; ok {
			log.Debugf("initializing source %s", sourceKey)
			c.selectedSources[sourceKey] = allSources[sourceKey]
		} else {
			return nil, fmt.Errorf("unknown parser type %d", sourceKey)
		}
	}

	return c, nil
}
