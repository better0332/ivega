package report

import (
	"bufio"
	"encoding/xml"
	"log"
	"os"
	"sync"
	"time"
)

type XmlReport struct {
	w *bufio.Writer
	f *os.File
	e *xml.Encoder

	lock *sync.Mutex
}

func XmlInit() (r *XmlReport, e error) {
	f, e := os.Create("report.xml")
	if e != nil {
		log.Println(e)
		return
	}
	w := bufio.NewWriterSize(f, 32*1024)
	w.Write([]byte(xml.Header))
	w.Write([]byte("<report title=\"URL漏洞扫描报告\">\n"))
	w.Write([]byte("\t<StartTime>" + time.Now().Format("2006-01-02 15:04:05") + "</StartTime>\n"))

	enc := xml.NewEncoder(w)
	enc.Indent("\t\t", "\t")

	r = &XmlReport{w: w, f: f, e: enc, lock: &sync.Mutex{}}
	return
}

func (r *XmlReport) XmlEnd() {
	r.w.Write([]byte("\t<EndTime>" + time.Now().Format("2006-01-02 15:04:05") + "</EndTime>\n"))
	r.w.Write([]byte("</report>"))
	r.w.Flush()
	r.f.Close()
}

func (r *XmlReport) Marshal(v interface{}) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if err := r.e.Encode(v); err != nil {
		log.Printf("error: %v\n", err)
	}
}
