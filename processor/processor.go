package processor

import (
	"fmt"
)

func GatherMetadata(sampleSrc chan []byte) error {
	fmt.Println("getting ready to process")
	for sample := range sampleSrc {
		// time.Sleep(time.Second * 10)
		fmt.Printf("Mock sample: %v\n", sample)
	}

	return nil
}
