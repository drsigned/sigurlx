package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
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
|___/_|\__, |\__,_|_|  |_/_/\_\ v1.9.0
       |___/
`).Bold())
}

func init() {
	// probe options
	flag.BoolVar(&ro.C, "c", false, "")
	flag.BoolVar(&ro.DX, "dX", false, "")
	flag.BoolVar(&ro.PR, "pR", false, "")
	flag.BoolVar(&ro.PV, "pV", false, "")
	flag.BoolVar(&ro.R, "r", false, "")
	// general options
	flag.IntVar(&co.delay, "delay", 100, "")
	flag.StringVar(&co.URLs, "iL", "", "")
	flag.BoolVar(&co.noColor, "nC", false, "")
	flag.BoolVar(&co.silent, "s", false, "")
	flag.IntVar(&co.threads, "threads", 50, "")
	flag.BoolVar(&co.updateParams, "update-params", false, "")
	flag.BoolVar(&co.verbose, "v", false, "")
	// http options
	flag.BoolVar(&ro.FollowRedirects, "follow-redirects", false, "")
	flag.BoolVar(&ro.FollowHostRedirects, "follow-host-redirects", false, "")
	flag.StringVar(&ro.HTTPProxy, "http-proxy ", "", "")
	flag.IntVar(&ro.Timeout, "timeout", 10, "")
	flag.StringVar(&ro.UserAgent, "UA", "", "")
	// output options
	flag.StringVar(&co.output, "oJ", "", "")

	flag.Usage = func() {
		banner()

		h := "USAGE:\n"
		h += "  sigurlx [OPTIONS]\n"

		h += "\nPROBE OPTIONS:\n"
		h += "  -c                        categorize urls\n"
		h += "  -dX                       probe for DOMXSS\n"
		h += "  -pR                       probe for reflected parameters\n"
		h += "  -pV                       probe for commonly vuln. parameters\n"
		h += "  -r                        probe request for status_code, content_type, e.t.c\n"

		h += "\nGENERAL OPTIONS:\n"
		h += "  -delay                    delay between requests (default: 100ms)\n"
		h += "  -iL                       urls (use `iL -` to read from stdin)\n"
		h += "  -nC                       no color mode\n"
		h += "  -s                        silent mode\n"
		h += "  -threads                  number concurrent threads (default: 50)\n"
		h += "  -update-params            update params file\n"
		h += "  -v                        verbose mode\n"

		h += "\nHTTP OPTIONS:\n"
		h += "  -follow-redirects         follow redirects (default: false)\n"
		h += "  -follow-host-redirects    follow internal redirects - same host redirects (default: false)\n"
		h += "  -http-proxy               HTTP Proxy URL\n"
		h += "  -timeout                  HTTP request timeout (default: 10s)\n"
		h += "  -UA                       HTTP user agent\n"

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

	options, err := sigurlx.ParseOptions(&ro)
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

	var output []sigurlx.Result

	for i := 0; i < co.threads; i++ {
		wg.Add(1)

		time.Sleep(time.Duration(co.delay) * time.Millisecond)

		go func() {
			defer wg.Done()

			runner, err := sigurlx.New(options)
			if err != nil {
				log.Fatalln(err)
			}

			for URL := range URLs {
				results, err := runner.Process(URL)
				if err != nil {
					if co.verbose {
						fmt.Fprintf(os.Stderr, err.Error()+"\n")
					}

					continue
				}

				fmt.Println(au.BrightBlue("+"), results.URL)
				if ro.C {
					fmt.Println(au.BrightCyan("    - category:"), results.Category)
				}
				if ro.R {
					fmt.Println(au.BrightCyan("    - status_code:"), coloredStatus(results.StatusCode, au))
					fmt.Println(au.BrightCyan("    - content_type:"), results.ContentType)
					fmt.Println(au.BrightCyan("    - content_lenght:"), results.ContentLength)
					if results.RedirectLocation != "" {
						fmt.Println(au.BrightCyan("    - redirect_location:"), results.RedirectLocation)
					}
				}
				if ro.PV {
					if len(results.CommonVulnParams) > 0 {
						fmt.Println(au.BrightCyan("    - common_vuln_params:"))
					}
					for i := range results.CommonVulnParams {
						fmt.Println(au.BrightCyan("        - param:"), results.CommonVulnParams[i].Param)
						fmt.Println(au.BrightCyan("        - issues:"), strings.Join(results.CommonVulnParams[i].Risks, ", "))
					}
				}
				if ro.PR {
					if len(results.ReflectedParams) > 0 {
						fmt.Println(au.BrightCyan("    - reflected_params:"))
					}
					for i := range results.ReflectedParams {
						fmt.Println(au.BrightCyan("        - param:"), results.ReflectedParams[i].Param)
						fmt.Println(au.BrightCyan("        - issues:"), results.ReflectedParams[i].URL)
					}
				}

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
}

func coloredStatus(code int, au aurora.Aurora) aurora.Value {
	var coloredStatusCode aurora.Value

	switch {
	case code >= http.StatusOK && code < http.StatusMultipleChoices:
		coloredStatusCode = au.BrightGreen(strconv.Itoa(code))
	case code >= http.StatusMultipleChoices && code < http.StatusBadRequest:
		coloredStatusCode = au.BrightYellow(strconv.Itoa(code))
	case code >= http.StatusBadRequest && code < http.StatusInternalServerError:
		coloredStatusCode = au.BrightRed(strconv.Itoa(code))
	case code > http.StatusInternalServerError:
		coloredStatusCode = au.Bold(aurora.Yellow(strconv.Itoa(code)))
	}

	return coloredStatusCode
}
