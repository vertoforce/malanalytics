package collector

import (
	"sync"

	"github.com/pimmytrousers/malanalytics/collector/malware"
)

// merge merges multiple malware channels to one
func merge(cs ...chan *malware.Malware) chan *malware.Malware {
	out := make(chan *malware.Malware)
	var wg sync.WaitGroup
	wg.Add(len(cs))
	for _, c := range cs {
		go func(c <-chan *malware.Malware) {
			for v := range c {
				out <- v
			}
			wg.Done()
		}(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
