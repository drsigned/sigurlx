package runner

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path"
)

// Options is a
type Options struct {
	// FEATURES
	All bool

	Categorize bool
	ScanParam  bool
	ParamsPath string
	Request    bool

	// REQUEST OPTIONS
	Proxy     string
	UserAgent string
	Timeout   int
}

// ParseOptions is a
func ParseOptions(options *Options) (*Options, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return options, err
	}

	// TASK OPTIONS
	if !options.Categorize && !options.ScanParam && !options.Request {
		options.All = true
	}

	// GENERAL OPTIONS
	options.ParamsPath = userHomeDir + "/.sigurlx/params.json"

	if _, err := os.Stat(options.ParamsPath); os.IsNotExist(err) {
		if err = pullParams(options.ParamsPath); err != nil {
			return options, err
		}
	}

	// REQUEST OPTIONS
	if options.UserAgent == "" {
		options.UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36"
	}

	return options, nil
}

func pullParams(ParamsPath string) error {
	directory, filename := path.Split(ParamsPath)

	if _, err := os.Stat(directory); os.IsNotExist(err) {
		if directory != "" {
			err = os.MkdirAll(directory, os.ModePerm)
			if err != nil {
				return err
			}
		}
	}

	paramsFile, err := os.Create(directory + filename)
	if err != nil {
		return err
	}

	defer paramsFile.Close()

	resp, err := http.Get("https://raw.githubusercontent.com/drsigned-os/sigurlx/main/static/params.json")
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New("unexpected code")
	}

	defer resp.Body.Close()

	_, err = io.Copy(paramsFile, resp.Body)
	if err != nil {
		return err
	}

	return nil
}
