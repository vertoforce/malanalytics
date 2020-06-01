package main

import (
	"github.com/pimmytrousers/malanalytics/collector"
	"github.com/pimmytrousers/malanalytics/postactions"
	"github.com/pimmytrousers/malanalytics/processor"
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

	// Start processing samples
	malsrc.Start()

	proc, err := processor.New(processor.Processors, malsrc.SampleStream)
	if err != nil {
		panic(err)
	}

	go proc.Start()

	postactions.PostActions(proc.EnrichedSampleStream)
}
