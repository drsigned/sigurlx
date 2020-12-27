package categorize

import "regexp"

// Categories is a
type Categories struct {
	JS      *regexp.Regexp
	DOC     *regexp.Regexp
	DATA    *regexp.Regexp
	STYLE   *regexp.Regexp
	MEDIA   *regexp.Regexp
	ARCHIVE *regexp.Regexp
}

// Run is a
func Run(URL string, categories Categories) (string, error) {
	category := ""

	if match := categories.DOC.MatchString(URL); match {
		category = "doc"
	}

	if category == "" {
		if match := categories.JS.MatchString(URL); match {
			category = "js"
		}
	}

	if category == "" {
		if match := categories.ARCHIVE.MatchString(URL); match {
			category = "archive"
		}
	}

	if category == "" {
		if match := categories.DATA.MatchString(URL); match {
			category = "data"
		}
	}

	if category == "" {
		if match := categories.STYLE.MatchString(URL); match {
			category = "style"
		}
	}

	if category == "" {
		if match := categories.MEDIA.MatchString(URL); match {
			category = "media"
		}
	}

	if category == "" {
		category = "endpoint"
	}

	return category, nil
}
