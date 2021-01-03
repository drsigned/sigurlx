package sigurlx

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
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

func (sigurlx *Sigurlx) ReflectedParamsProbe(parsedURL *url.URL, query url.Values) ([]ReflectedParam, error) {
	var x []ReflectedParam
	var payload = "iy3j4h234hjb23234"

	for parameter, value := range query {
		tmp := value[0]

		query.Set(parameter, payload)

		parsedURL.RawQuery = query.Encode()

		res, err := sigurlx.httpRequest(parsedURL.String(), http.MethodGet, sigurlx.Client)
		if err != nil {
			return x, err
		}
		defer res.Body.Close()

		// always read the full body so we can re-use the tcp connection
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return x, err
		}

		re := regexp.MustCompile(payload)
		match := re.FindStringSubmatch(string(body))

		if match != nil {
			x = append(x, ReflectedParam{Param: parameter, URL: parsedURL.String()})
		}

		query.Set(parameter, tmp)
	}

	return x, nil
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
