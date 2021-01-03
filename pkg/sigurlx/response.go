package sigurlx

import (
	"reflect"
)

type Response struct {
	StatusCode       int
	ContentType      string
	ContentLength    int64
	RedirectLocation string
	Headers          map[string][]string
	Body             []byte
	Raw              string
}

func (response Response) IsEmpty() bool {
	return reflect.DeepEqual(response, Response{})
}
