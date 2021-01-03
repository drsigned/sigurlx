package sigurlx

import (
	"io/ioutil"
	"net/http"
	"strings"
)

func (sigurlx *Sigurlx) DoHTTP(URL string) (Response, error) {
	response := Response{}

	res, err := sigurlx.httpRequest(URL, http.MethodGet, sigurlx.Client)
	if err != nil {
		return response, err
	}

	defer res.Body.Close()

	response.StatusCode = res.StatusCode
	response.ContentType = strings.Split(res.Header.Get("Content-Type"), ";")[0]

	// websockets don't have a readable body
	if res.StatusCode != http.StatusSwitchingProtocols {
		// always read the full body so we can re-use the tcp connection
		if response.Body, err = ioutil.ReadAll(res.Body); err != nil {
			return response, err
		}
	}

	return response, nil
}

func (sigurlx *Sigurlx) httpRequest(URL string, method string, client *http.Client) (res *http.Response, err error) {
	req, err := http.NewRequest(method, URL, nil)
	if err != nil {
		return res, err
	}

	req.Header.Set("User-Agent", sigurlx.Options.UserAgent)

	res, err = client.Do(req)
	if err != nil {
		return res, err
	}

	return res, nil
}
