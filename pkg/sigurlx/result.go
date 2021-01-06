package sigurlx

type CommonVulnParam struct {
	Param string   `json:"param,omitempty"`
	Risks []string `json:"risks,omitempty"`
}

type ReflectedParam struct {
	Param string `json:"param,omitempty"`
	URL   string `json:"url,omitempty"`
}

type Result struct {
	URL              string            `json:"url,omitempty"`
	Category         string            `json:"category,omitempty"`
	StatusCode       int               `json:"status_code,omitempty"`
	ContentType      string            `json:"content_type,omitempty"`
	ContentLength    int               `json:"content_length,omitempty"`
	RedirectLocation string            `json:"redirect_location,omitempty"`
	RedirectMode     string            `json:"redirect_mode,omitempty"`
	CommonVulnParams []CommonVulnParam `json:"common_vuln_params,omitempty"`
	ReflectedParams  []ReflectedParam  `json:"reflected_params,omitempty"`
	DOM              []string          `json:"dom,omitempty"`
}
