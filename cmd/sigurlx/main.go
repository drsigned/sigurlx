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
	"github.com/drsigned/sigurlx/pkg/runner"
	"github.com/logrusorgru/aurora/v3"
)

type options struct {
	delay   int
	threads int
	output  string
	silent  bool
	noColor bool
	URLs    string
	verbose bool
}

var (
	co options
	au aurora.Aurora
	ro runner.Options
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
	// task options
	flag.BoolVar(&ro.Categorize, "C", false, "")
	flag.BoolVar(&ro.ScanParam, "P", false, "")
	flag.BoolVar(&ro.Request, "request", false, "")

	// general options
	flag.IntVar(&co.threads, "threads", 50, "")
	flag.IntVar(&co.delay, "delay", 100, "")
	flag.StringVar(&co.URLs, "iL", "", "")
	flag.BoolVar(&co.noColor, "nC", false, "")
	flag.BoolVar(&co.silent, "s", false, "")
	flag.BoolVar(&co.verbose, "v", false, "")

	// Http options
	flag.IntVar(&ro.Timeout, "timeout", 10, "")
	flag.StringVar(&ro.UserAgent, "UA", "", "")
	flag.StringVar(&ro.Proxy, "x", "", "")

	// OUTPUT
	flag.StringVar(&co.output, "oJ", "", "")

	flag.Usage = func() {
		banner()

		h := "USAGE:\n"
		h += "  sigurlx [OPTIONS]\n\n"

		h += "FEATURES:\n"
		h += "  -C                 categorize (endpoints, js, style, doc & media)\n"
		h += "  -P                 scan parameters\n"
		h += "  -request           send HTTP request\n"

		h += "\nGENERAL OPTIONS:\n"
		h += "  -threads           number concurrent threads (default: 50)\n"
		h += "  -delay             delay between requests (default: 100ms)\n"
		h += "  -iL                urls (use `iL -` to read stdin)\n"
		h += "  -nC                no color mode\n"
		h += "  -s                 silent mode\n"
		h += "  -v                 verbose mode\n"

		h += "\nREQUEST OPTIONS (used with -request):\n"
		h += "  -timeout           HTTP request timeout (s) (default: 10)\n"
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

	URLs := make(chan string, co.threads)

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
			if scanner.Text() != "" {
				URLs <- scanner.Text()
			}
		}

		if scanner.Err() != nil {
			log.Fatalln(scanner.Err())
		}
	}()

	options, err := runner.ParseOptions(&ro)
	if err != nil {
		log.Fatalln(err)
	}

	mutex := &sync.Mutex{}
	wg := &sync.WaitGroup{}

	var output []runner.Results

	for i := 0; i < co.threads; i++ {
		wg.Add(1)

		time.Sleep(time.Duration(co.delay) * time.Millisecond)

		go func() {
			defer wg.Done()

			sigurlx, err := runner.New(options)
			if err != nil {
				log.Fatalln(err)
			}

			for URL := range URLs {
				results, err := sigurlx.Process(URL)
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

	if err := saveToJSON(co.output, output); err != nil {
		log.Fatalln(err)
	}
}

func saveToJSON(outputPath string, output []runner.Results) error {
	if outputPath != "" {
		return nil
	}

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
