package sigurlx

import (
	"regexp"
	"sync"
)

var mutex = &sync.Mutex{}

func newRegex(pattern string) (*regexp.Regexp, error) {
	mutex.Lock()
	defer mutex.Unlock()

	extractor, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return extractor, nil
}
