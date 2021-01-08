package sigurlx

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"
	"unicode/utf8"
)

func (sigurlx *Sigurlx) initClient() error {
	tr := &http.Transport{
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
			tr.Proxy = http.ProxyURL(proxyURL)
		}
	}

	re := func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	if sigurlx.Options.FollowRedirects {
		re = nil
	}

	if sigurlx.Options.FollowHostRedirects {
		re = func(redirectedRequest *http.Request, previousRequest []*http.Request) error {
			newHost := redirectedRequest.URL.Host
			oldHost := previousRequest[0].URL.Host

			if newHost != oldHost {
				return http.ErrUseLastResponse
			}

			return nil
		}
	}

	sigurlx.Client = &http.Client{
		Timeout:       time.Duration(sigurlx.Options.Timeout) * time.Second,
		Transport:     tr,
		CheckRedirect: re,
	}

	return nil
}

func (sigurlx *Sigurlx) DoHTTP(URL string) (Response, error) {
	var response Response

	res, err := sigurlx.httpRequest(URL, http.MethodGet, sigurlx.Client)
	if err != nil {
		return response, err
	}

	response.Headers = res.Header.Clone()

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
	response.ContentType = response.GetHeaderPart("Content-Type", ";")
	response.ContentLength = utf8.RuneCountInString(string(response.Body))
	response.RedirectLocation = response.GetHeaderPart("Location", ";")

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
