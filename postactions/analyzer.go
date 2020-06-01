package postactions

import (
	"github.com/pimmytrousers/malanalytics/collector/malware"
	log "github.com/sirupsen/logrus"
)

func PostActions(sampleSrc <-chan *malware.Malware) error {
	for sample := range sampleSrc {
		// time.Sleep(time.Second * 10)
		log.WithFields(log.Fields{
			"Content": sample.RawBytes,
			"MD5":     sample.MD5,
			"SHA1":    sample.SHA1,
			"SHA256":  sample.SHA256,
		}).Info("Placing sample in local storage and ELK")
	}

	return nil
}
