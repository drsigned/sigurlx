package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/drsigned/gos"
	"github.com/drsigned/sigurlx/pkg/params"
	"github.com/drsigned/sigurlx/pkg/sigurlx"
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
	ro sigurlx.Options
)

func banner() {
	fmt.Fprintln(os.Stderr, aurora.BrightBlue(`
     _                  _      
 ___(_) __ _ _   _ _ __| |_  __
/ __| |/ _`+"`"+` | | | | '__| \ \/ /
\__ \ | (_| | |_| | |  | |>  < 
|___/_|\__, |\__,_|_|  |_/_/\_\ v2.0.0
       |___/
`).Bold())
}

func init() {
	// general options
	flag.StringVar(&co.URLs, "iL", "", "")
	flag.IntVar(&co.threads, "threads", 50, "")
	flag.BoolVar(&co.updateParams, "update-params", false, "")
	flag.BoolVar(&co.verbose, "v", false, "")
	// http options
	flag.IntVar(&co.delay, "delay", 100, "")
	flag.BoolVar(&ro.FollowRedirects, "follow-redirects", false, "")
	flag.BoolVar(&ro.FollowHostRedirects, "follow-host-redirects", false, "")
	flag.StringVar(&ro.HTTPProxy, "http-proxy ", "", "")
	flag.IntVar(&ro.Timeout, "timeout", 10, "")
	flag.StringVar(&ro.UserAgent, "UA", "", "")
	// output options
	flag.BoolVar(&co.noColor, "nC", false, "")
	flag.StringVar(&co.output, "oJ", "", "")
	flag.BoolVar(&co.silent, "s", false, "")

	flag.Usage = func() {
		banner()

		h := "USAGE:\n"
		h += "  sigurlx [OPTIONS]\n"

		h += "\nGENERAL OPTIONS:\n"
		h += "  -iL                       input urls list (use `-iL -` to read from stdin)\n"
		h += "  -threads                  number concurrent threads (default: 50)\n"
		h += "  -update-params            update params file\n"
		h += "  -v                        verbose mode\n"

		h += "\nHTTP OPTIONS:\n"
		h += "  -delay                    delay between requests (default: 100ms)\n"
		h += "  -follow-redirects         follow redirects (default: false)\n"
		h += "  -follow-host-redirects    follow internal redirects i.e, same host redirects (default: false)\n"
		h += "  -http-proxy               HTTP Proxy URL\n"
		h += "  -timeout                  HTTP request timeout (default: 10s)\n"
		h += "  -UA                       HTTP user agent\n"

		h += "\nOUTPUT OPTIONS:\n"
		h += "  -nC                       no color mode\n"
		h += "  -oJ                       JSON output file\n"
		h += "  -s                        silent mode\n"

		fmt.Fprintf(os.Stderr, h)
	}

	flag.Parse()

	ro.Parse()

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

	// options, err := sigurlx.ParseOptions(&ro)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

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

	var output sigurlx.Results

	for i := 0; i < co.threads; i++ {
		wg.Add(1)

		time.Sleep(time.Duration(co.delay) * time.Millisecond)

		go func() {
			defer wg.Done()

			runner, err := sigurlx.New(&ro)
			if err != nil {
				log.Fatalln(err)
			}

			for URL := range URLs {
				results, err := runner.Process(URL)
				if err != nil {
					fmt.Println(au.BrightRed(" -"), results.URL, au.BrightGreen("...failed!"))

					if co.verbose {
						fmt.Fprintf(os.Stderr, err.Error()+"\n")
					}

					continue
				}

				mutex.Lock()
				fmt.Println(au.BrightGreen(" +"), results.URL, au.BrightGreen("...done!"))
				output = append(output, results)
				mutex.Unlock()
			}
		}()
	}

	wg.Wait()

	if err := output.SaveToJSON(co.output); err != nil {
		log.Fatalln(err)
	}
}
