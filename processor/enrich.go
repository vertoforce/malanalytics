package processor

import (
	"github.com/pimmytrousers/malanalytics/collector/malware"
	log "github.com/sirupsen/logrus"
)

type MalwareProcessor interface {
	Enrich(sample *malware.Malware) error
}

// Processor takes in the incoming samples from the channel, enriches them via various services and processes and returns the sample a processed channel
type EnrichmentEngine struct {
	selectedProcessors   []MalwareProcessor
	EnrichedSampleStream chan *malware.Malware
	incomingStream       <-chan *malware.Malware
}

func New(processors []MalwareProcessor, incomingStream chan *malware.Malware) (*EnrichmentEngine, error) {
	e := &EnrichmentEngine{
		selectedProcessors:   processors,
		EnrichedSampleStream: make(chan *malware.Malware),
		incomingStream:       incomingStream,
	}

	return e, nil
}

// GatherMetadata takes the incoming malware samples and runs analytics on those samples
func (e *EnrichmentEngine) Start() error {
	log.Debug("getting ready to process")
	for sample := range e.incomingStream {
		for _, processor := range e.selectedProcessors {
			err := processor.Enrich(sample)
			if err != nil {
				panic(err)
			}
		}
		// time.Sleep(time.Second * 10)
		e.EnrichedSampleStream <- sample
	}

	return nil
}
