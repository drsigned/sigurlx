package sigurlx

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (sigurlx *Sigurlx) initClient() error {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(sigurlx.Options.Timeout) * time.Second,
			KeepAlive: time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	if sigurlx.Options.HTTPProxy != "" {
		if proxyURL, err := url.Parse(sigurlx.Options.HTTPProxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	sigurlx.Client = &http.Client{
		Timeout:   time.Duration(sigurlx.Options.Timeout) * time.Second,
		Transport: transport,
	}

	return nil
}

func (sigurlx *Sigurlx) DoHTTP(URL string) (Response, error) {
	response := Response{}

	res, err := sigurlx.httpRequest(URL, http.MethodGet, sigurlx.Client)
	if err != nil {
		return response, err
	}

	// websockets don't have a readable body
	if res.StatusCode != http.StatusSwitchingProtocols {
		// always read the full body so we can re-use the tcp connection
		if response.Body, err = ioutil.ReadAll(res.Body); err != nil {
			return response, err
		}
	}

	if err := res.Body.Close(); err != nil {
		return response, err
	}

	response.StatusCode = res.StatusCode
	response.ContentType = strings.Split(res.Header.Get("Content-Type"), ";")[0]
	response.ContentLength = res.ContentLength

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
