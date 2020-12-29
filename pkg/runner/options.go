package runner

// Options is a
type Options struct {
	// FEATURES
	All bool

	C       bool
	Request bool
	P       bool
	PV      bool
	PR      bool

	// REQUEST OPTIONS
	Proxy     string
	UserAgent string
	Timeout   int
}

// ParseOptions is a
func ParseOptions(options *Options) (*Options, error) {
	// TASK OPTIONS
	if !options.C && !options.P && !options.PR && !options.PV && !options.Request {
		options.All = true
	}

	// REQUEST OPTIONS
	if options.UserAgent == "" {
		options.UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36"
	}

	return options, nil
}
