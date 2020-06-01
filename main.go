package main

import (
	"github.com/pimmytrousers/malanalytics/collector"
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

	// Take our malware stream and process metadata for it
	err = processor.GatherMetadata(malsrc.SampleStream)
	if err != nil {
		panic(err)
	}
}
