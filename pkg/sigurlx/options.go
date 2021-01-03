package sigurlx

// Options is a
type Options struct {
	// FEATURES
	All bool

	C  bool
	DX bool
	PR bool
	PV bool
	R  bool

	// REQUEST OPTIONS
	HTTPProxy string
	UserAgent string
	Timeout   int
}

// ParseOptions is a
func ParseOptions(options *Options) (*Options, error) {
	// TASK OPTIONS
	if !options.C && !options.DX && !options.PR && !options.PV && !options.R {
		options.All = true
	}

	// REQUEST OPTIONS
	if options.UserAgent == "" {
		options.UserAgent = "Dr. Signed's sigurlx (https://github.com/drsigned/sigurlx)"
	}

	return options, nil
}
