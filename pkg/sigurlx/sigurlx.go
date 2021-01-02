package sigurlx

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/drsigned/sigurlx/pkg/params"
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
	// URL categories regex
	sigurlx.JSRegex, _ = newRegex(`(?m).*?\.(js)(\?.*?|)$`)
	sigurlx.DOCRegex, _ = newRegex(`(?m).*?\.(pdf|xlsx|doc|docx|txt)(\?.*?|)$`)
	sigurlx.DATARegex, _ = newRegex(`(?m).*?\.(json|xml|csv)(\?.*?|)$`)
	sigurlx.STYLERegex, _ = newRegex(`(?m).*?\.(css)(\?.*?|)$`)
	sigurlx.MEDIARegex, _ = newRegex(`(?m).*?\.(jpg|jpeg|png|ico|svg|gif|webp|mp3|mp4|woff|woff2|ttf|eot|tif|tiff)(\?.*?|)$`)
	sigurlx.ARCHIVERegex, _ = newRegex(`(?m).*?\.(zip|tar|tar\.gz)(\?.*?|)$`)
	// DOMXSS regex
	sigurlx.DOMXSSRegex, _ = newRegex(`/((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()/`)

	// Params
	raw, err := ioutil.ReadFile(params.File())
	if err != nil {
		return sigurlx, err
	}

	if err = json.Unmarshal(raw, &sigurlx.Params); err != nil {
		return sigurlx, err
	}

	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(sigurlx.Options.Timeout) * time.Second,
			KeepAlive: time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	if sigurlx.Options.Proxy != "" {
		if p, err := url.Parse(sigurlx.Options.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}

	sigurlx.Client = &http.Client{
		Timeout:   time.Duration(sigurlx.Options.Timeout) * time.Second,
		Transport: tr,
	}

	return sigurlx, nil
}

func (sigurlx *Sigurlx) Process(URL string) (result Result, err error) {
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

	queryUnescaped, err := url.QueryUnescape(result.URL)
	if err != nil {
		return result, err
	}

	parsedURL, err = url.Parse(queryUnescaped)
	if err != nil {
		return result, err
	}

	query, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		return result, err
	}

	if len(query) > 0 {
		// 2. scan commonly vuln. parameters
		if sigurlx.Options.P || sigurlx.Options.PV || sigurlx.Options.All {
			for parameter := range query {
				for i := range sigurlx.Params {
					if strings.ToLower(sigurlx.Params[i].Param) == strings.ToLower(parameter) {
						result.CommonVulnParams = append(result.CommonVulnParams, sigurlx.Params[i])
						break
					}
				}
			}
		}

		// 3. scan reflected parameters
		if sigurlx.Options.P || sigurlx.Options.PR || sigurlx.Options.All {
			var payload = "iy3j4h234hjb23234"

			for parameter, value := range query {
				tmp := value[0]

				query.Set(parameter, payload)

				parsedURL.RawQuery = query.Encode()

				res, err := sigurlx.httpRequest(parsedURL.String(), http.MethodGet, sigurlx.Client)
				if err != nil {
					return result, err
				}
				defer res.Body.Close()

				// always read the full body so we can re-use the tcp connection
				body, err := ioutil.ReadAll(res.Body)
				if err != nil {
					return result, err
				}

				re := regexp.MustCompile(payload)
				match := re.FindStringSubmatch(string(body))

				if match != nil {
					result.ReflectedParams = append(result.ReflectedParams, ReflectedParam{Param: parameter, URL: parsedURL.String()})
				}

				query.Set(parameter, tmp)
			}
		}
	}

	// 4. Request
	if sigurlx.Options.Request || sigurlx.Options.All {
		res, err := sigurlx.httpRequest(parsedURL.String(), http.MethodGet, sigurlx.Client)
		if err != nil {
			return result, err
		}
		defer res.Body.Close()

		// always read the full body so we can re-use the tcp connection
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return result, err
		}

		// 3. DOMXSS
		if result.Category == "js" || result.Category == "endpoint" {
			if match := sigurlx.DOMXSSRegex.FindStringSubmatch(string(body)); match != nil {
				result.DOM = append(result.DOM, match...)
			}
		}

		result.StatusCode = res.StatusCode
		result.ContentType = strings.Split(res.Header.Get("Content-Type"), ";")[0]
		result.ContentLength = res.ContentLength
	}

	return result, nil
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

func (sigurlx *Sigurlx) categorize(URL string) (category string, err error) {
	if match := sigurlx.JSRegex.MatchString(URL); match {
		category = "js"
	}

	if category == "" {
		if match := sigurlx.DOCRegex.MatchString(URL); match {
			category = "doc"
		}
	}

	if category == "" {
		if match := sigurlx.DATARegex.MatchString(URL); match {
			category = "data"
		}
	}

	if category == "" {
		if match := sigurlx.STYLERegex.MatchString(URL); match {
			category = "style"
		}
	}

	if category == "" {
		if match := sigurlx.MEDIARegex.MatchString(URL); match {
			category = "media"
		}
	}

	if category == "" {
		if match := sigurlx.ARCHIVERegex.MatchString(URL); match {
			category = "archive"
		}
	}

	if category == "" {
		category = "endpoint"
	}

	return category, nil
}
