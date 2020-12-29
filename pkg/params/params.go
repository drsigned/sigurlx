package params

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path"
)

func File() (file string) {
	userHomeDir, _ := os.UserHomeDir()
	return userHomeDir + "/.sigurlx/params.json"
}

func UpdateOrDownload(file string) (err error) {
	directory, filename := path.Split(file)

	if _, err := os.Stat(directory); os.IsNotExist(err) {
		if directory != "" {
			if err = os.MkdirAll(directory, os.ModePerm); err != nil {
				return err
			}
		}
	}

	paramsFile, err := os.Create(directory + filename)
	if err != nil {
		return err
	}
	defer paramsFile.Close()

	res, err := http.Get("https://raw.githubusercontent.com/drsigned/sigurlx/main/static/params.json")
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return errors.New("unexpected code")
	}

	defer res.Body.Close()

	if _, err = io.Copy(paramsFile, res.Body); err != nil {
		return err
	}

	return nil
}
