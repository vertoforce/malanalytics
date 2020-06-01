package enrichment

import (
	"github.com/pimmytrousers/malanalytics/collector/malware"
	log "github.com/sirupsen/logrus"
)

type EnrichmentService interface {
	Enrich(sample *malware.Malware) error
}

type EnrichmentEngine struct {
	selectedServices     []EnrichmentService
	EnrichedSampleStream chan *malware.Malware
	incomingStream       <-chan *malware.Malware
}

func New(services []EnrichmentService, incomingStream chan *malware.Malware) (*EnrichmentEngine, error) {
	e := &EnrichmentEngine{
		selectedServices:     services,
		EnrichedSampleStream: make(chan *malware.Malware),
		incomingStream:       incomingStream,
	}

	return e, nil
}

func (e *EnrichmentEngine) Start() error {
	log.Debug("getting ready to process")
	for sample := range e.incomingStream {
		for _, processor := range e.selectedServices {
			err := processor.Enrich(sample)
			if err != nil {
				panic(err)
			}
		}

		e.EnrichedSampleStream <- sample
	}

	return nil
}
