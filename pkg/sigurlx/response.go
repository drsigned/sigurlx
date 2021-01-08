package sigurlx

import (
	"reflect"
	"strings"
)

type Response struct {
	StatusCode       int
	ContentType      string
	ContentLength    int
	RedirectLocation string
	Headers          map[string][]string
	Body             []byte
	Raw              string
}

func (response Response) IsEmpty() bool {
	return reflect.DeepEqual(response, Response{})
}

func (response Response) GetHeaderPart(header, sep string) string {
	value, ok := response.Headers[header]
	if ok && len(value) > 0 {
		tokens := strings.Split(strings.Join(value, " "), sep)
		return tokens[0]
	}

	return ""
}
