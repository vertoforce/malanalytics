package main

import (
	"flag"

	"github.com/pimmytrousers/melk/collector"
	"github.com/pimmytrousers/melk/enrichment"
	"github.com/pimmytrousers/melk/postactions"
	log "github.com/sirupsen/logrus"
)

var configPath string

func init() {
	log.SetLevel(log.DebugLevel)
	flag.StringVar(&configPath, "config", "./example.yml", "config file for the service")
}

func main() {
	flag.Parse()
	logger := log.New()

	c, err := getConf(configPath)

	logger.Info(c)

	if err != nil {
		log.Fatalf("failed to acquire config: %s", err)
	}

	malsrc, err := collector.New(collector.Sources)
	if err != nil {
		panic(err)
	}

	// Start collecting samples
	malsrc.Start(logger)

	proc, err := enrichment.New(enrichment.EnrichmentServices, malsrc.SampleStream)
	if err != nil {
		panic(err)
	}

	// Start enriching samples
	go proc.Start(logger)

	postactions.PostActions(logger, proc.EnrichedSampleStream)
}
