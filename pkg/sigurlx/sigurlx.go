package sigurlx

import (
	"net/http"
	"net/url"
	"regexp"
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
	sigurlx.Options = options
	sigurlx.initCategories()
	sigurlx.initParams()
	sigurlx.initClient()

	return sigurlx, nil
}

func (sigurlx *Sigurlx) Process(URL string) (result Result, err error) {
	var res Response

	parsedURL, err := url.Parse(URL)
	if err != nil {
		return result, err
	}

	result.URL = parsedURL.String()

	if result.Category, err = sigurlx.categorize(URL); err != nil {
		return result, err
	}

	if res, err = sigurlx.DoHTTP(parsedURL.String()); err != nil {
		return result, err
	}

	result.StatusCode = res.StatusCode
	result.ContentType = res.ContentType
	result.ContentLength = res.ContentLength
	result.RedirectLocation = res.RedirectLocation

	query, err := getQuery(parsedURL.String())
	if err != nil {
		return result, err
	}

	if len(query) > 0 {
		if result.Category == "endpoint" {
			if result.CommonVulnParams, err = sigurlx.CommonVulnParamsProbe(query); err != nil {
				return result, err
			}

			if res.IsEmpty() {
				res, _ = sigurlx.DoHTTP(parsedURL.String())
			}

			if result.ReflectedParams, err = sigurlx.ReflectedParamsProbe(parsedURL, query, res); err != nil {
				return result, err
			}
		}
	}

	return result, nil
}
