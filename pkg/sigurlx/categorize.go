package sigurlx

func (sigurlx *Sigurlx) initCategories() {
	sigurlx.JSRegex, _ = newRegex(`(?m).*?\.(js)(\?.*?|)$`)
	sigurlx.DOCRegex, _ = newRegex(`(?m).*?\.(pdf|xlsx|doc|docx|txt)(\?.*?|)$`)
	sigurlx.DATARegex, _ = newRegex(`(?m).*?\.(json|xml|csv)(\?.*?|)$`)
	sigurlx.STYLERegex, _ = newRegex(`(?m).*?\.(css)(\?.*?|)$`)
	sigurlx.MEDIARegex, _ = newRegex(`(?m).*?\.(jpg|jpeg|png|ico|svg|gif|webp|mp3|mp4|woff|woff2|ttf|eot|tif|tiff)(\?.*?|)$`)
	sigurlx.ARCHIVERegex, _ = newRegex(`(?m).*?\.(zip|tar|tar\.gz)(\?.*?|)$`)
}

func (sigurlx *Sigurlx) categorize(URL string) (category string, err error) {
	if match := sigurlx.JSRegex.MatchString(URL); match {
		category = "js"
	}

	if category == "" {
		if match := sigurlx.DOCRegex.MatchString(URL); match {
			category = "doc"
		}
	}

	if category == "" {
		if match := sigurlx.DATARegex.MatchString(URL); match {
			category = "data"
		}
	}

	if category == "" {
		if match := sigurlx.STYLERegex.MatchString(URL); match {
			category = "style"
		}
	}

	if category == "" {
		if match := sigurlx.MEDIARegex.MatchString(URL); match {
			category = "media"
		}
	}

	if category == "" {
		if match := sigurlx.ARCHIVERegex.MatchString(URL); match {
			category = "archive"
		}
	}

	if category == "" {
		category = "endpoint"
	}

	return category, nil
}
