package processor

import (
	log "github.com/sirupsen/logrus"

	"github.com/pimmytrousers/malanalytics/collector/sources"
)

// GatherMetadata takes the incoming malware samples and runs analytics on those samples
func GatherMetadata(sampleSrc chan *sources.Malware) error {
	log.Debug("getting ready to process")
	for sample := range sampleSrc {
		// time.Sleep(time.Second * 10)
		log.Printf("Mock sample: %v\n", sample.RawBytes)
	}

	return nil
}
