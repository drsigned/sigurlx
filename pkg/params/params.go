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

	resp, err := http.Get("https://raw.githubusercontent.com/drsigned/sigurlx/main/static/params.json")
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
