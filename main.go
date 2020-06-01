package main

import (
	"github.com/pimmytrousers/malanalytics/collector"
	"github.com/pimmytrousers/malanalytics/enrichment"
	"github.com/pimmytrousers/malanalytics/postactions"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func main() {
	malsrc, err := collector.New(collector.Sources)
	if err != nil {
		panic(err)
	}

	// Start collecting samples
	malsrc.Start()

	proc, err := enrichment.New(enrichment.EnrichmentServices, malsrc.SampleStream)
	if err != nil {
		panic(err)
	}

	// Start enriching samples
	go proc.Start()

	postactions.PostActions(proc.EnrichedSampleStream)
}
