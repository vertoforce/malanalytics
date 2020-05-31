package processor

import (
	"github.com/pimmytrousers/malanalytics/collector/malware"
	log "github.com/sirupsen/logrus"
)

// GatherMetadata takes the incoming malware samples and runs analytics on those samples
func GatherMetadata(sampleSrc chan *malware.Malware) error {
	log.Debug("getting ready to process")
	for sample := range sampleSrc {
		// time.Sleep(time.Second * 10)
		log.Printf("Mock sample: %v\n", sample.RawBytes)
	}

	return nil
}
