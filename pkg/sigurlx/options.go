package sigurlx

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
		options.UserAgent = "Dr. Signed's sigurlx (https://github.com/drsigned/sigurlx)"
	}

	return options, nil
}
