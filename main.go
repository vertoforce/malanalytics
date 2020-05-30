package main

import (
	"github.com/pimmytrousers/malanalytics/collector"
	"github.com/pimmytrousers/malanalytics/processor"
)

func main() {
	// ctx := context.Background()
	malsrc, err := collector.New([]collector.Source{collector.Malbazaar}, 100)
	if err != nil {
		panic(err)
	}

	go malsrc.GetSamples()

	err = processor.GatherMetadata(malsrc.SampleStream)
	if err != nil {
		panic(err)
	}
}
