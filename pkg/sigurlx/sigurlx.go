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

	// DOMXSS regex
	sigurlx.DOMXSSRegex, _ = newRegex(`/((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()/`)

	return sigurlx, nil
}

func (sigurlx *Sigurlx) Process(URL string) (result Result, err error) {
	var res Response

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

	query, err := getQuery(parsedURL.String())
	if err != nil {
		return result, err
	}

	// 2. scan commonly vuln. parameters
	if sigurlx.Options.PV || sigurlx.Options.All {
		result.CommonVulnParams, err = sigurlx.CommonVulnParamsProbe(query)
		if err != nil {
			return result, err
		}
	}

	// 3. scan reflected parameters
	if sigurlx.Options.PR || sigurlx.Options.All {
		result.ReflectedParams, err = sigurlx.ReflectedParamsProbe(parsedURL, query)
		if err != nil {
			return result, err
		}
	}

	// 4. DOMXSS
	if sigurlx.Options.DX || sigurlx.Options.All {
		if res.IsEmpty() {
			res, _ = sigurlx.DoHTTP(parsedURL.String())
		}

		if result.Category == "js" || result.Category == "endpoint" {
			if match := sigurlx.DOMXSSRegex.FindStringSubmatch(string(res.Body)); match != nil {
				result.DOM = append(result.DOM, match...)
			}
		}
	}

	// 5. Request
	if sigurlx.Options.R || sigurlx.Options.All {
		if res.IsEmpty() {
			res, _ = sigurlx.DoHTTP(parsedURL.String())
		}

		result.StatusCode = res.StatusCode
		result.ContentType = res.ContentType
		result.ContentLength = res.ContentLength
		result.RedirectLocation = res.RedirectLocation
		result.RedirectMode = res.RedirectMode
	}

	return result, nil
}
