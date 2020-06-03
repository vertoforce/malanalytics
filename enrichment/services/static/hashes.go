package static

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/pimmytrousers/melk/collector/malware"
)

type Static struct{}

func (s *Static) Enrich(sample *malware.Malware) error {
	s1 := sha1.New()
	s256 := sha256.New()
	m5 := md5.New()

	mw := io.MultiWriter(s1, s256, m5)

	mw.Write(sample.RawBytes)

	sample.SHA1 = fmt.Sprintf("%x", s1.Sum(nil))
	sample.SHA256 = fmt.Sprintf("%x", s256.Sum(nil))
	sample.MD5 = fmt.Sprintf("%x", m5.Sum(nil))

	return nil
}
