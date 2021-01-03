package sigurlx

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

type Sigurlx struct {
	Client       *http.Client
	Params       []CommonVulnParam
	Options      *Options
	JSRegex      *regexp.Regexp
	DOCRegex     *regexp.Regexp
	DATARegex    *regexp.Regexp
	STYLERegex   *regexp.Regexp
	MEDIARegex   *regexp.Regexp
	ARCHIVERegex *regexp.Regexp
	DOMXSSRegex  *regexp.Regexp
}

func New(options *Options) (Sigurlx, error) {
	sigurlx := Sigurlx{}
	// options
	sigurlx.Options = options
	// Params
	sigurlx.initParams()
	// URL categories regex
	sigurlx.initCategories()
	// DOMXSS regex
	sigurlx.DOMXSSRegex, _ = newRegex(`/((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()/`)

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

	return sigurlx, nil
}

func (sigurlx *Sigurlx) Process(URL string) (result Result, err error) {
	var xyz Response

	parsedURL, err := url.Parse(URL)
	if err != nil {
		return result, err
	}

	result.URL = parsedURL.String()

	// 1. categorize
	if sigurlx.Options.C || sigurlx.Options.All {
		if result.Category, err = sigurlx.categorize(URL); err != nil {
			return result, err
		}
	}

	xq, _ := getQuery(result.URL)

	// 2. scan commonly vuln. parameters
	if sigurlx.Options.PV || sigurlx.Options.All {
		result.CommonVulnParams, _ = sigurlx.CommonVulnParamsProbe(xq)
	}

	// 3. scan reflected parameters
	if sigurlx.Options.PR || sigurlx.Options.All {
		result.ReflectedParams, _ = sigurlx.ReflectedParamsProbe(parsedURL, xq)
	}

	// 4. DOMXSS
	if sigurlx.Options.DX || sigurlx.Options.All {
		if xyz.IsEmpty() {
			xyz, _ = sigurlx.DoHTTP(parsedURL.String())
		}

		if result.Category == "js" || result.Category == "endpoint" {
			if match := sigurlx.DOMXSSRegex.FindStringSubmatch(string(xyz.Body)); match != nil {
				result.DOM = append(result.DOM, match...)
			}
		}
	}

	return result, nil
}
