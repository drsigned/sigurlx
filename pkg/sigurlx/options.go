package sigurlx

type Options struct {
	FollowRedirects     bool
	FollowHostRedirects bool
	HTTPProxy           string
	Timeout             int
	UserAgent           string
}

func (options *Options) Parse() {
	if options.UserAgent == "" {
		options.UserAgent = "Dr. Signed's sigurlx (https://github.com/drsigned/sigurlx)"
	}
}
