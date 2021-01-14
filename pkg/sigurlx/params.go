package sigurlx

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/drsigned/sigurlx/pkg/params"
)

func (sigurlx *Sigurlx) initParams() error {
	raw, err := ioutil.ReadFile(params.File())
	if err != nil {
		return err
	}

	if err = json.Unmarshal(raw, &sigurlx.Params); err != nil {
		return err
	}

	return nil
}

func (sigurlx *Sigurlx) CommonVulnParamsProbe(query url.Values) ([]CommonVulnParam, error) {
	var x []CommonVulnParam

	for parameter := range query {
		for i := range sigurlx.Params {
			if strings.ToLower(sigurlx.Params[i].Param) == strings.ToLower(parameter) {
				x = append(x, sigurlx.Params[i])
				break
			}
		}
	}

	return x, nil
}

func (sigurlx *Sigurlx) ReflectedParamsProbe(parsedURL *url.URL, query url.Values, res Response) ([]ReflectedParam, error) {
	var reflectedParams []ReflectedParam

	reflected, err := sigurlx.checkReflection(parsedURL.String(), query, res)
	if err != nil {
		return reflectedParams, err
	}

	if len(reflected) == 0 {
		return reflectedParams, nil
	}

	for _, param := range reflected {
		wasReflected, err := sigurlx.checkAppend(parsedURL, query, param, "iy3j4h234hjb23234")
		if err != nil {
			return reflectedParams, err
		}

		if wasReflected {
			for _, char := range []string{"\"", "'", "<", ">"} {
				wasReflected, err := sigurlx.checkAppend(parsedURL, query, param, "aprefix"+char+"asuffix")
				if err != nil {
					continue
				}

				if wasReflected {
					reflectedParams = append(reflectedParams, ReflectedParam{Param: param, URL: parsedURL.String()})
				}
			}
		}
	}

	return reflectedParams, nil
}

func getQuery(URL string) (url.Values, error) {
	var query url.Values

	queryUnescaped, err := url.QueryUnescape(URL)
	if err != nil {
		return query, err
	}

	parsedURL, err := url.Parse(queryUnescaped)
	if err != nil {
		return query, err
	}

	query, err = url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		return query, err
	}

	return query, nil
}

func (sigurlx *Sigurlx) checkReflection(URL string, query url.Values, res Response) ([]string, error) {
	var reflected []string

	if res.IsEmpty() {
		res, _ = sigurlx.DoHTTP(URL)
	}

	// nope (:
	if res.StatusCode >= http.StatusMultipleChoices && res.StatusCode < http.StatusBadRequest {
		return reflected, nil
	}

	// also nope
	ct := res.ContentType
	if ct != "" && !strings.Contains(ct, "html") {
		return reflected, nil
	}

	for param, value := range query {
		for _, v := range value {
			if !strings.Contains(string(res.Body), v) {
				continue
			}

			reflected = append(reflected, param)
		}
	}

	return reflected, nil
}

func (sigurlx *Sigurlx) checkAppend(parsedURL *url.URL, query url.Values, param, suffix string) (bool, error) {
	val := query.Get(param)

	query.Set(param, val+suffix)
	parsedURL.RawQuery = query.Encode()

	reflected, err := sigurlx.checkReflection(parsedURL.String(), query, Response{})
	if err != nil {
		return false, err
	}

	for _, r := range reflected {
		if r == param {
			return true, nil
		}
	}

	query.Set(param, val)

	return false, nil
}
