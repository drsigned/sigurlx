package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/drsigned/gos"
	"github.com/drsigned/sigurlx/pkg/sigurlx"
	"github.com/logrusorgru/aurora/v3"
)

type options struct {
	delay       int
	concurrency int
	output      string
	silent      bool
	noColor     bool
	URLs        string
	verbose     bool
}

var (
	co options
	au aurora.Aurora
	so sigurlx.Options
)

func banner() {
	fmt.Fprintln(os.Stderr, aurora.BrightBlue(`
     _                  _      
 ___(_) __ _ _   _ _ __| |_  __
/ __| |/ _`+"`"+` | | | | '__| \ \/ /
\__ \ | (_| | |_| | |  | |>  < 
|___/_|\__, |\__,_|_|  |_/_/\_\ v1.4.0
       |___/
`).Bold())
}

func init() {
	// general options
	flag.IntVar(&co.concurrency, "c", 50, "")
	flag.IntVar(&co.delay, "delay", 100, "")
	flag.BoolVar(&co.noColor, "nC", false, "")
	flag.BoolVar(&co.silent, "s", false, "")
	flag.StringVar(&co.URLs, "iL", "", "")
	flag.BoolVar(&co.verbose, "v", false, "")

	// task options
	flag.BoolVar(&so.Categorize, "cat", false, "")
	flag.BoolVar(&so.ScanParam, "param-scan", false, "")
	flag.BoolVar(&so.Request, "request", false, "")

	// Http options
	flag.IntVar(&so.Timeout, "timeout", 10, "")
	flag.BoolVar(&so.VerifyTLS, "tls", false, "")
	flag.StringVar(&so.UserAgent, "UA", "", "")
	flag.StringVar(&so.Proxy, "x", "", "")

	// OUTPUT
	flag.StringVar(&co.output, "oJ", "", "")

	flag.Usage = func() {
		banner()

		h := "USAGE:\n"
		h += "  sigurlx [OPTIONS]\n\n"

		h += "FEATURES:\n"
		h += "  -cat               categorize (endpoints, js, style, doc & media)\n"
		h += "  -param-scan        scan url parameters\n"
		h += "  -request           send HTTP request\n"

		h += "\nGENERAL OPTIONS:\n"
		h += "  -c                 concurrency level (default: 50)\n"
		h += "  -delay             delay between requests (ms) (default: 100)\n"
		h += "  -nC                no color mode\n"
		h += "  -s                 silent mode\n"
		h += "  -iL                list of urls (use `-` to read stdin)\n"
		h += "  -v                 verbose mode\n"

		h += "\nREQUEST OPTIONS (used with -request):\n"
		h += "  -timeout           HTTP request timeout (s) (default: 10)\n"
		h += "  -tls               enable tls verification (default: false)\n"
		h += "  -UA                HTTP user agent\n"
		h += "  -x                 HTTP Proxy URL\n"

		h += "\nOUTPUT OPTIONS:\n"
		h += "  -oJ                JSON output file\n\n"

		fmt.Fprintf(os.Stderr, h)
	}

	flag.Parse()

	au = aurora.NewAurora(!co.noColor)
}

func main() {
	if !co.silent {
		banner()
	}

	URLs := make(chan string, co.concurrency)

	go func() {
		defer close(URLs)

		var scanner *bufio.Scanner

		if co.URLs == "-" {
			if !gos.HasStdin() {
				log.Fatalln(errors.New("no stdin"))
			}

			scanner = bufio.NewScanner(os.Stdin)
		} else {
			openedFile, err := os.Open(co.URLs)
			if err != nil {
				log.Fatalln(err)
			}

			defer openedFile.Close()

			scanner = bufio.NewScanner(openedFile)
		}

		for scanner.Scan() {
			URLs <- scanner.Text()
		}

		if scanner.Err() != nil {
			log.Fatalln(scanner.Err())
		}
	}()

	options, err := sigurlx.ParseOptions(&so)
	if err != nil {
		log.Fatalln(err)
	}

	var output []sigurlx.Results

	mutex := &sync.Mutex{}
	wg := &sync.WaitGroup{}

	delay := time.Duration(co.delay) * time.Millisecond

	for i := 0; i < co.concurrency; i++ {
		wg.Add(1)
		time.Sleep(delay)

		go func() {
			defer wg.Done()

			runner, err := sigurlx.New(options)
			if err != nil {
				log.Fatalln(err)
			}

			for URL := range URLs {
				if URL == "" {
					continue
				}

				results, err := runner.Process(URL)
				if err != nil {
					if co.verbose {
						fmt.Fprintf(os.Stderr, err.Error()+"\n")
					}

					continue
				}

				fmt.Println(results.URL)

				mutex.Lock()
				output = append(output, results)
				mutex.Unlock()
			}
		}()
	}

	wg.Wait()

	if co.output != "" {
		if err := saveResults(co.output, output); err != nil {
			log.Fatalln(err)
		}
	}
}

func saveResults(outputPath string, output []sigurlx.Results) error {
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		directory, filename := path.Split(outputPath)

		if _, err := os.Stat(directory); os.IsNotExist(err) {
			if directory != "" {
				err = os.MkdirAll(directory, os.ModePerm)
				if err != nil {
					return err
				}
			}
		}

		if strings.ToLower(path.Ext(filename)) != ".json" {
			outputPath = outputPath + ".json"
		}
	}

	outputJSON, err := json.MarshalIndent(output, "", "\t")
	if err != nil {
		return err
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}

	defer outputFile.Close()

	_, err = outputFile.WriteString(string(outputJSON))
	if err != nil {
		return err
	}

	return nil
}
