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
	"github.com/drsigned/sigurlx/pkg/params"
	"github.com/drsigned/sigurlx/pkg/runner"
	"github.com/logrusorgru/aurora/v3"
)

type options struct {
	delay        int
	threads      int
	output       string
	silent       bool
	noColor      bool
	URLs         string
	updateParams bool
	verbose      bool
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
	flag.IntVar(&co.delay, "delay", 100, "")
	flag.StringVar(&co.URLs, "iL", "", "")
	flag.BoolVar(&co.noColor, "nC", false, "")
	flag.BoolVar(&co.silent, "s", false, "")
	flag.IntVar(&co.threads, "threads", 50, "")
	flag.BoolVar(&co.updateParams, "update-params", false, "")
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
		h += "  -C                 categorize urls\n"
		h += "  -P                 scan parameters\n"
		h += "  -request           send HTTP request\n"

		h += "\nGENERAL OPTIONS:\n"
		h += "  -delay             delay between requests (default: 100ms)\n"
		h += "  -iL                urls (use `iL -` to read stdin)\n"
		h += "  -nC                no color mode\n"
		h += "  -s                 silent mode\n"
		h += "  -threads           number concurrent threads (default: 50)\n"
		h += "  -update-params     update params file\n"
		h += "  -v                 verbose mode\n"

		h += "\nREQUEST OPTIONS (used with -request):\n"
		h += "  -timeout           HTTP request timeout (default: 10s)\n"
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

	if co.updateParams {
		if err := params.UpdateOrDownload(params.File()); err != nil {
			log.Fatalln(err)
		}

		if !co.silent {
			fmt.Println("[", au.BrightBlue("INF"), "] params file updated successfully :)")
		}

		os.Exit(0)
	}

	options, err := runner.ParseOptions(&ro)
	if err != nil {
		log.Fatalln(err)
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

	// write output to file (json format)
	if co.output != "" {
		if _, err := os.Stat(co.output); os.IsNotExist(err) {
			directory, filename := path.Split(co.output)

			if _, err := os.Stat(directory); os.IsNotExist(err) {
				if directory != "" {
					if err = os.MkdirAll(directory, os.ModePerm); err != nil {
						log.Fatalln(err)
					}
				}
			}

			if strings.ToLower(path.Ext(filename)) != ".json" {
				co.output = co.output + ".json"
			}
		}
	}

	JSON, err := json.MarshalIndent(output, "", "\t")
	if err != nil {
		log.Fatalln(err)
	}

	file, err := os.Create(co.output)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()

	_, err = file.WriteString(string(JSON))
	if err != nil {
		log.Fatalln(err)
	}
}
