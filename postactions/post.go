package postactions

import (
	"github.com/pimmytrousers/melk/collector/malware"
	log "github.com/sirupsen/logrus"
)

func PostActions(logger *log.Logger, sampleSrc <-chan *malware.Malware) error {
	for sample := range sampleSrc {
		logger.WithFields(log.Fields{
			"Source":          sample.Src,
			"Content Preview": sample.RawBytes[:4],
			// "MD5":      sample.MD5,
			// "SHA1":     sample.SHA1,
			"SHA256":   sample.SHA256,
			"Tags":     sample.Tags,
			"FileName": sample.FileName,
			"FileType": sample.FileType,
			"Family":   sample.Family,
		}).Info("PostProcess")
	}

	return nil
}
