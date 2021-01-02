package runner

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

type URLCategoriesRegex struct {
	JS      *regexp.Regexp
	DOC     *regexp.Regexp
	DATA    *regexp.Regexp
	STYLE   *regexp.Regexp
	MEDIA   *regexp.Regexp
	ARCHIVE *regexp.Regexp
}

type Runner struct {
	Client     *http.Client
	Params     []CommonVulnParam
	Options    *Options
	Categories URLCategoriesRegex
}

func New(options *Options) (runner Runner, err error) {
	runner.Options = options

	runner.Categories.JS, _ = newRegex(`(?m).*?\.(js)(\?.*?|)$`)
	runner.Categories.DOC, _ = newRegex(`(?m).*?\.(pdf|xlsx|doc|docx|txt)(\?.*?|)$`)
	runner.Categories.DATA, _ = newRegex(`(?m).*?\.(json|xml|csv)(\?.*?|)$`)
	runner.Categories.STYLE, _ = newRegex(`(?m).*?\.(css)(\?.*?|)$`)
	runner.Categories.MEDIA, _ = newRegex(`(?m).*?\.(jpg|jpeg|png|ico|svg|gif|webp|mp3|mp4|woff|woff2|ttf|eot|tif|tiff)(\?.*?|)$`)
	runner.Categories.ARCHIVE, _ = newRegex(`(?m).*?\.(zip|tar|tar\.gz)(\?.*?|)$`)

	// Params
	raw, err := ioutil.ReadFile(params.File())
	if err != nil {
		return runner, err
	}

	if err = json.Unmarshal(raw, &runner.Params); err != nil {
		return runner, err
	}

	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(runner.Options.Timeout) * time.Second,
			KeepAlive: time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	if runner.Options.Proxy != "" {
		if p, err := url.Parse(runner.Options.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}

	runner.Client = &http.Client{
		Timeout:   time.Duration(runner.Options.Timeout) * time.Second,
		Transport: tr,
	}

	return runner, nil
}

func (runner *Runner) Process(URL string) (result Result, err error) {
	parsedURL, err := url.Parse(URL)
	if err != nil {
		return result, err
	}

	result.URL = parsedURL.String()

	// 1. categorize
	if runner.Options.C || runner.Options.All {
		if result.Category, err = runner.categorize(URL); err != nil {
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
		if runner.Options.P || runner.Options.PV || runner.Options.All {
			for parameter := range query {
				for i := range runner.Params {
					if strings.ToLower(runner.Params[i].Param) == strings.ToLower(parameter) {
						result.CommonVulnParams = append(result.CommonVulnParams, runner.Params[i])
						break
					}
				}
			}
		}

		// 3. scan reflected parameters
		if runner.Options.P || runner.Options.PR || runner.Options.All {
			var payload = "iy3j4h234hjb23234"

			for parameter, value := range query {
				tmp := value[0]

				query.Set(parameter, payload)

				parsedURL.RawQuery = query.Encode()

				res, err := runner.httpRequest(parsedURL.String(), http.MethodGet, runner.Client)
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
	if runner.Options.Request || runner.Options.All {
		res, err := runner.httpRequest(parsedURL.String(), http.MethodGet, runner.Client)
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
			domXSS := regexp.MustCompile(`/((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()/`)
			match := domXSS.FindStringSubmatch(string(body))
			if match != nil {
				result.DOM = append(result.DOM, match...)
			}
		}

		result.StatusCode = res.StatusCode
		result.ContentType = strings.Split(res.Header.Get("Content-Type"), ";")[0]
		result.ContentLength = res.ContentLength
	}

	return result, nil
}

func (runner *Runner) httpRequest(URL string, method string, client *http.Client) (res *http.Response, err error) {
	req, err := http.NewRequest(method, URL, nil)
	if err != nil {
		return res, err
	}

	req.Header.Set("User-Agent", runner.Options.UserAgent)

	res, err = client.Do(req)
	if err != nil {
		return res, err
	}

	return res, nil
}

func (runner *Runner) categorize(URL string) (category string, err error) {
	if match := runner.Categories.JS.MatchString(URL); match {
		category = "js"
	}

	if category == "" {
		if match := runner.Categories.DOC.MatchString(URL); match {
			category = "doc"
		}
	}

	if category == "" {
		if match := runner.Categories.DATA.MatchString(URL); match {
			category = "data"
		}
	}

	if category == "" {
		if match := runner.Categories.STYLE.MatchString(URL); match {
			category = "style"
		}
	}

	if category == "" {
		if match := runner.Categories.MEDIA.MatchString(URL); match {
			category = "media"
		}
	}

	if category == "" {
		if match := runner.Categories.ARCHIVE.MatchString(URL); match {
			category = "archive"
		}
	}

	if category == "" {
		category = "endpoint"
	}

	return category, nil
}
