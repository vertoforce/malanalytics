package main

type config struct {
	OutputDir          string   `yaml:"outputdir"`
	Debug              bool     `yaml:"debug"`
	CollectionSources  []string `yaml:"collectSources"`
	EnrichmentServices []string `yaml:"enrichmentServices"`
}
