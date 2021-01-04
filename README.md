# sigurlx

[![release](https://img.shields.io/github/release/drsigned/sigurlx?style=flat&color=0040ff)](https://github.com/drsigned/sigurlx/releases) ![maintenance](https://img.shields.io/badge/maintained%3F-yes-0040ff.svg) [![open issues](https://img.shields.io/github/issues-raw/drsigned/sigurlx.svg?style=flat&color=0040ff)](https://github.com/drsigned/sigurlx/issues?q=is:issue+is:open) [![closed issues](https://img.shields.io/github/issues-closed-raw/drsigned/sigurlx.svg?style=flat&color=0040ff)](https://github.com/drsigned/sigurlx/issues?q=is:issue+is:closed) [![license](https://img.shields.io/badge/license-MIT-gray.svg?colorB=0040FF)](https://github.com/drsigned/sigurlx/blob/master/LICENSE) [![twitter](https://img.shields.io/badge/twitter-@drsigned-0040ff.svg)](https://twitter.com/drsigned)

sigurlx is a fast and multi-purpose HTTP toolkit allow to run multiple probers on URLs.

## Resources

* [Features](#features)
* [Usage](#usage)
* [Installation](#installation)
    * [From Binary](#from-binary)
    * [From source](#from-source)
    * [From github](#from-github)
* [Credits](#credits)
* [Contribution](#contribution)


## Features

* **categorize URLs**

	<details>
	<summary>URLs categories</summary>

	```
	> endpoint
	> js {js}
	> style {css}
	> data {json|xml|csv}
	> archive {zip|tar|tar.gz}
	> doc {pdf|xlsx|doc|docx|txt}
	> media {jpg|jpeg|png|ico|svg|gif|webp|mp3|mp4|woff|woff2|ttf|eot|tif|tiff}
	```

	</details>
* **probe for commonly vulnerable parameters** - Some HTTP parameter names are more commonly associated with one functionality than the others, **sigurlx finds such parameter names and the risks commonly associated with them**.
* **probe for reflected parameters**.
* **probe for DOMXSS**.
* **probe request for status_code, content_type, e.t.c**

## Usage

To display help message for sigurlx use the `-h` flag:

```
$ sigurlx -h

     _                  _      
 ___(_) __ _ _   _ _ __| |_  __
/ __| |/ _` | | | | '__| \ \/ /
\__ \ | (_| | |_| | |  | |>  < 
|___/_|\__, |\__,_|_|  |_/_/\_\ v1.7.1
       |___/

USAGE:
  sigurlx [OPTIONS]

PROBE OPTIONS:
  -c                 categorize urls
  -dX                probe for DOMXSS
  -pR                probe for reflected parameters
  -pV                probe for commonly vuln. parameters
  -r                 probe request for status_code, content_type, e.t.c

GENERAL OPTIONS:
  -delay             delay between requests (default: 100ms)
  -iL                urls (use `iL -` to read from stdin)
  -nC                no color mode
  -s                 silent mode
  -threads           number concurrent threads (default: 50)
  -update-params     update params file
  -v                 verbose mode

HTTP OPTIONS:
  -timeout           HTTP request timeout (default: 10s)
  -UA                HTTP user agent
  -x                 HTTP Proxy URL

OUTPUT OPTIONS:
  -oJ                JSON output file
```

## Installation

#### From Binary

You can download the pre-built binary for your platform from this repository's [releases](https://github.com/drsigned/sigurlx/releases/) page, extract, then move it to your `$PATH`and you're ready to go.

#### From Source

sigurlx requires **go1.14+** to install successfully. Run the following command to get the repo

```bash
$ GO111MODULE=on go get -u -v github.com/drsigned/sigurlx/cmd/sigurlx
```

#### From Github

```bash
$ git clone https://github.com/drsigned/sigurlx.git; cd sigurlx/cmd/sigurlx/; go build; mv sigurlx /usr/local/bin/; sigurlx -h
```

## Credits

The list of parameter names and the risks associated with them is mainly created from the public work of various people of the community - initial list was obtained from [Somdev Sangwan](https://github.com/s0md3v)'s [Parth](https://github.com/s0md3v/Parth).

## Contribution

[Issues](https://github.com/drsigned/sigurlx/issues) and [Pull Requests](https://github.com/drsigned/sigurlx/pulls) are welcome!