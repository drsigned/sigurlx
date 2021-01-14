package sigurlx

import (
	"encoding/json"
	"os"
	"path"
	"strings"
)

type CommonVulnParam struct {
	Param string   `json:"param,omitempty"`
	Risks []string `json:"risks,omitempty"`
}

type ReflectedParam struct {
	Param      string   `json:"param,omitempty"`
	Characters []string `json:"characters,omitempty"`
}

type Result struct {
	URL              string            `json:"url,omitempty"`
	Category         string            `json:"category,omitempty"`
	StatusCode       int               `json:"status_code,omitempty"`
	ContentType      string            `json:"content_type,omitempty"`
	ContentLength    int               `json:"content_length,omitempty"`
	RedirectLocation string            `json:"redirect_location,omitempty"`
	CommonVulnParams []CommonVulnParam `json:"common_vuln_params,omitempty"`
	ReflectedParams  []ReflectedParam  `json:"reflected_params,omitempty"`
	DOM              []string          `json:"dom,omitempty"`
}

type Results []Result

func (results Results) SaveToJSON(PATH string) error {
	if PATH != "" {
		if _, err := os.Stat(PATH); os.IsNotExist(err) {
			directory, filename := path.Split(PATH)

			if _, err := os.Stat(directory); os.IsNotExist(err) {
				if directory != "" {
					if err = os.MkdirAll(directory, os.ModePerm); err != nil {
						return err
					}
				}
			}

			if strings.ToLower(path.Ext(filename)) != ".json" {
				PATH = PATH + ".json"
			}
		}

		JSON, err := json.MarshalIndent(results, "", "\t")
		if err != nil {
			return err
		}

		file, err := os.Create(PATH)
		if err != nil {
			return err
		}

		defer file.Close()

		_, err = file.WriteString(string(JSON))
		if err != nil {
			return err
		}
	}

	return nil
}
