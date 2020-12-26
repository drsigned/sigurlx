package params

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Params is a
type Params struct {
	Param string   `json:"param,omitempty"`
	Risks []string `json:"risks,omitempty"`
}

// Results is a
type Results struct {
	List      []string `json:"list,omitempty"`
	Reflected []string `json:"reflected,omitempty"`
	Risky     []Params `json:"risky_params,omitempty"`
}

// Scan is a
func Scan(URL string, params []Params) (*Results, error) {
	results := &Results{}

	queryUnescaped, err := url.QueryUnescape(URL)
	if err != nil {
		return results, err
	}

	parsedURL, err := url.Parse(queryUnescaped)
	if err != nil {
		return results, err
	}

	query, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		return results, err
	}

	if len(query) > 0 {
		var payload = "iy3j4h234hjb23234"

		for parameter := range query {
			// parameter list
			results.List = append(results.List, parameter)

			// risky parameters
			for i := range params {
				if strings.ToLower(params[i].Param) == strings.ToLower(parameter) {
					results.Risky = append(results.Risky, params[i])
					break
				}
			}

			// reflected parameters
			query.Set(parameter, payload)

			parsedURL.RawQuery = query.Encode()

			req, err := http.NewRequest("GET", URL, nil)
			if err != nil {
				return results, err
			}

			client := &http.Client{}

			res, err := client.Do(req)
			if err != nil {
				return results, err
			}

			defer res.Body.Close()

			// always read the full body so we can re-use the tcp connection
			b, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return results, err
			}

			re := regexp.MustCompile(payload)
			match := re.FindStringSubmatch(string(b))

			if match != nil {
				results.Reflected = append(results.Reflected, parameter)
			}
		}
	}

	return results, nil
}
