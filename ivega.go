package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/better0332/ivega/core"
	"github.com/better0332/ivega/db"
	"github.com/better0332/ivega/report"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
)

var (
	idFrom     = flag.Int("id-from", 0, "must be greater than 0")
	idTo       = flag.Int("id-to", 0, "must be greater than or equal id-from")
	host       = flag.String("host", "", "scan host(priority than domain)")
	domain     = flag.String("domain", "", "scan domain")
	all        = flag.Bool("all", false, "scan all")
	thread     = flag.Int("thread", 10, "scan thread less than or equal 20")
	auto       = flag.Bool("auto", false, "scan which never scaned except specify the scan id")
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

	queue chan bool

	wg sync.WaitGroup
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func parseReq(data *db.Data, r *report.XmlReport) {
	defer func() {
		<-queue
		wg.Done()
	}()

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data.Req)))
	if err != nil {
		log.Printf("id=%d ReadRequest error: %s\n", data.Id, err)

		var urlStr string
		if strings.Index(data.Path, data.Scheme+"://") == 0 {
			urlStr = data.Path
		} else {
			urlStr = data.Scheme + "://" + data.Host + data.Path
		}

		if req, err = http.NewRequest(data.Method, urlStr, nil); err != nil {
			log.Printf("id=%d NewRequest error: %s\n", data.Id, err)
			return
		}
	}

	req.URL.Scheme = data.Scheme
	req.URL.Host = data.Host
	req.RequestURI = ""
	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	req.Header.Del("Accept-Encoding")
	core.FixRequest(req)

	log.Printf("%d %s %s\n", data.Id, data.Method, req.URL)

	var body []byte
	if req.ContentLength != 0 {
		body, err = ioutil.ReadAll(req.Body)
		if err != nil {
			log.Printf("id=%d Read Request body error: %s\n", data.Id, err)
			return
		}
	}

	engine := core.CoreEngine{Id: data.Id, Req: req, Report: r, Body: body}
	engine.CheckVul()

	db.Update(data.Id)
}

func parse() {
	flag.Parse()
	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(2)
	}
	if *idFrom > *idTo {
		fmt.Fprintf(os.Stderr, "id-from can't be greater than id-to\n")
		os.Exit(2)
	}
	if *idFrom <= 0 && !*all && *host == "" && *domain == "" {
		fmt.Fprintf(os.Stderr, "id-from can't be less or equal than 0\n")
		os.Exit(2)
	}
	if *thread > 20 || *thread <= 0 {
		fmt.Fprintf(os.Stderr, "thread must be in (0, 20]\n")
		os.Exit(2)
	}
	if *all {
		*idFrom = 0
		*idTo = 0
		*host = ""
		*domain = ""
	}
	if *host != "" {
		*domain = ""
	}
}

func main() {
	parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	data := db.Query(*idFrom, *idTo, *host, *domain, *auto)

	r, err := report.XmlInit()
	if err != nil {
		log.Fatal(err)
	}

	queue = make(chan bool, *thread)
	for i := 0; i < len(data); i++ {
		wg.Add(1)
		queue <- true
		go parseReq(data[i], r)
	}

	wg.Wait()
	r.XmlEnd()
}
