package main

import (
	"time"

	"github.com/pimmytrousers/malanalytics/collector"
	"github.com/pimmytrousers/malanalytics/processor"
	log "github.com/sirupsen/logrus"
)

func init() {

	log.SetLevel(log.DebugLevel)
}

func main() {
	// ctx := context.Background()
	malsrc, err := collector.New([]collector.SourceID{collector.Malbazaar}, 100)
	if err != nil {
		panic(err)
	}

	go malsrc.GetSamples()
	time.Sleep(time.Second)

	err = processor.GatherMetadata(malsrc.SampleStream)
	if err != nil {
		panic(err)
	}
}
