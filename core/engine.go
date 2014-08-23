package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/better0332/ivega/db"
	"github.com/better0332/ivega/decode"
	"github.com/better0332/ivega/report"
	"io"
	"io/ioutil"
	"log"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	checkUrl = iota
	checkPostForm
	checkMultipartForm
	checkMultipartFormFile
	checkPostXmlJson
	checkCookie
	checkHead

	sigNum = iota
	sigChr
	sigSch
)

type sigBlind struct {
	s [2]string
	t int
}

type sigTime struct {
	s string
	t int
}

var (
	tr = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true} /*DisableCompression: true*/}

	client = &http.Client{Transport: tr, CheckRedirect: redirectPolicy}

	stopRedirect = "stopped redirects"

	reDbErr = regexp.MustCompile(`You have an error in your SQL syntax|` +
		`Database error:.{1,8}Invalid SQL:|Microsoft OLE DB Provider for|` +
		`Microsoft JET Database Engine|ORA-01756|Incorrect syntax near`)

	reDomain1 = regexp.MustCompile(`[^\.]+\.(?:com|net|org|gov|edu)\.[a-z]{2}$`)
	reDomain2 = regexp.MustCompile(`[^\.]+\.(?:ac|bj|sh|tj|cq|he|sx|nm|ln|jl|hl|` +
		`js|zj|ah|fj|jx|sd|ha|hb|hn|gd|gx|hi|sc|gz|yn|xz|sn|gs|qh|nx|xj|tw|hk|mo)\.cn$`)
	reDomain3 = regexp.MustCompile(`[^\.]+\.[^\.]+$`)

	injectSig = []sigBlind{
		{[2]string{`'aNd'9`, `'aNd'0`}, sigChr},
		{[2]string{`%25'aNd's'''lIkE's''`, `%25'aNd's'''lIkE'w''`}, sigSch},
		{[2]string{`-000000`, `-999999`}, sigNum},
	}
	injectTimeSig = []sigTime{
		{` aNd slEep(15)`, sigNum},
		{`'aNd slEep(15)='0`, sigChr},
		{`%25'aNd slEep(15)lIkE'0`, sigSch},
		{`;waitfor delay '0:0:15'--`, sigNum},
		{`';waitfor delay '0:0:15'--`, sigChr},
		{`-slEep(15)`, sigNum},
		{`'-slEep(15)-'`, sigChr},
		{`'aNd slEep(15)-- ;`, sigChr},
		{`'aNd slEep(15))-- ;`, sigChr},
		// {`'oR slEep(15)-- ;`, sigChr},
		// {`'oR slEep(15))-- ;`, sigChr},
	}
	xssSig = []string{
		`<hikvision0317>`,
		`'"hikvision0906'"`,
	}
	errSig = []string{
		`'"`,
		`%B2'%B2"`,
		`%2527%2522`,
	}
)

// HTTP status codes, defined in RFC 2616.
const (
	StatusContinue           = 100
	StatusSwitchingProtocols = 101

	StatusOK                   = 200
	StatusCreated              = 201
	StatusAccepted             = 202
	StatusNonAuthoritativeInfo = 203
	StatusNoContent            = 204
	StatusResetContent         = 205
	StatusPartialContent       = 206

	StatusMultipleChoices   = 300
	StatusMovedPermanently  = 301
	StatusFound             = 302
	StatusSeeOther          = 303
	StatusNotModified       = 304
	StatusUseProxy          = 305
	StatusTemporaryRedirect = 307

	StatusBadRequest                   = 400
	StatusUnauthorized                 = 401
	StatusPaymentRequired              = 402
	StatusForbidden                    = 403
	StatusNotFound                     = 404
	StatusMethodNotAllowed             = 405
	StatusNotAcceptable                = 406
	StatusProxyAuthRequired            = 407
	StatusRequestTimeout               = 408
	StatusConflict                     = 409
	StatusGone                         = 410
	StatusLengthRequired               = 411
	StatusPreconditionFailed           = 412
	StatusRequestEntityTooLarge        = 413
	StatusRequestURITooLong            = 414
	StatusUnsupportedMediaType         = 415
	StatusRequestedRangeNotSatisfiable = 416
	StatusExpectationFailed            = 417
	StatusTeapot                       = 418

	StatusInternalServerError     = 500
	StatusNotImplemented          = 501
	StatusBadGateway              = 502
	StatusServiceUnavailable      = 503
	StatusGatewayTimeout          = 504
	StatusHTTPVersionNotSupported = 505

	// New HTTP status codes from RFC 6585. Not exported yet in Go 1.1.
	// See discussion at https://codereview.appspot.com/7678043/
	statusPreconditionRequired          = 428
	statusTooManyRequests               = 429
	statusRequestHeaderFieldsTooLarge   = 431
	statusNetworkAuthenticationRequired = 511
)

var statusText = map[int]string{
	StatusContinue:           "Continue",
	StatusSwitchingProtocols: "Switching Protocols",

	StatusOK:                   "OK",
	StatusCreated:              "Created",
	StatusAccepted:             "Accepted",
	StatusNonAuthoritativeInfo: "Non-Authoritative Information",
	StatusNoContent:            "No Content",
	StatusResetContent:         "Reset Content",
	StatusPartialContent:       "Partial Content",

	StatusMultipleChoices:   "Multiple Choices",
	StatusMovedPermanently:  "Moved Permanently",
	StatusFound:             "Found",
	StatusSeeOther:          "See Other",
	StatusNotModified:       "Not Modified",
	StatusUseProxy:          "Use Proxy",
	StatusTemporaryRedirect: "Temporary Redirect",

	StatusBadRequest:                   "Bad Request",
	StatusUnauthorized:                 "Unauthorized",
	StatusPaymentRequired:              "Payment Required",
	StatusForbidden:                    "Forbidden",
	StatusNotFound:                     "Not Found",
	StatusMethodNotAllowed:             "Method Not Allowed",
	StatusNotAcceptable:                "Not Acceptable",
	StatusProxyAuthRequired:            "Proxy Authentication Required",
	StatusRequestTimeout:               "Request Timeout",
	StatusConflict:                     "Conflict",
	StatusGone:                         "Gone",
	StatusLengthRequired:               "Length Required",
	StatusPreconditionFailed:           "Precondition Failed",
	StatusRequestEntityTooLarge:        "Request Entity Too Large",
	StatusRequestURITooLong:            "Request URI Too Long",
	StatusUnsupportedMediaType:         "Unsupported Media Type",
	StatusRequestedRangeNotSatisfiable: "Requested Range Not Satisfiable",
	StatusExpectationFailed:            "Expectation Failed",
	StatusTeapot:                       "I'm a teapot",

	StatusInternalServerError:     "Internal Server Error",
	StatusNotImplemented:          "Not Implemented",
	StatusBadGateway:              "Bad Gateway",
	StatusServiceUnavailable:      "Service Unavailable",
	StatusGatewayTimeout:          "Gateway Timeout",
	StatusHTTPVersionNotSupported: "HTTP Version Not Supported",

	statusPreconditionRequired:          "Precondition Required",
	statusTooManyRequests:               "Too Many Requests",
	statusRequestHeaderFieldsTooLarge:   "Request Header Fields Too Large",
	statusNetworkAuthenticationRequired: "Network Authentication Required",
}

func init() {
	if !unescapeSig() {
		panic("InitSig Error!!")
	}
}

func unescapeSig() bool {
	for i, _ := range injectSig {
		sig0, e := url.QueryUnescape(injectSig[i].s[0])
		if e != nil {
			return false
		}
		injectSig[i].s[0] = sig0
		sig1, e := url.QueryUnescape(injectSig[i].s[1])
		if e != nil {
			return false
		}
		injectSig[i].s[1] = sig1
	}

	for i, _ := range injectTimeSig {
		sig, e := url.QueryUnescape(injectTimeSig[i].s)
		if e != nil {
			return false
		}
		injectTimeSig[i].s = sig
	}

	for i, _ := range xssSig {
		sig, e := url.QueryUnescape(xssSig[i])
		if e != nil {
			return false
		}
		xssSig[i] = sig
	}

	for i, _ := range errSig {
		sig, e := url.QueryUnescape(errSig[i])
		if e != nil {
			return false
		}
		errSig[i] = sig
	}

	return true
}

func EscapeNonAscii(s string) string {
	hexCount := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E {
			hexCount++
		}
	}

	if hexCount == 0 {
		return s
	}

	t := make([]byte, len(s)+2*hexCount)
	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c < 0x20 || c > 0x7E:
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}

func redirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New(stopRedirect)
	}
	return nil
}

func FixRequest(req *http.Request) {
	// issue: https://code.google.com/p/go/issues/detail?id=6784 in shipin7.com
	if strings.Contains(req.URL.Path, "!") {
		req.URL.Opaque = "//" + req.URL.Host + req.URL.Path
	}
}

func DumpResponse(resp *http.Response, body bool) (dump []byte) {
	if body {
		FixResponse(resp)
		dump, _ = httputil.DumpResponse(resp, body)
	} else {
		var b bytes.Buffer

		text := resp.Status
		if text == "" {
			var ok bool
			text, ok = statusText[resp.StatusCode]
			if !ok {
				text = "status code " + strconv.Itoa(resp.StatusCode)
			}
		}
		protoMajor, protoMinor := strconv.Itoa(resp.ProtoMajor), strconv.Itoa(resp.ProtoMinor)
		statusCode := strconv.Itoa(resp.StatusCode) + " "
		text = strings.TrimPrefix(text, statusCode)
		io.WriteString(&b, "HTTP/"+protoMajor+"."+protoMinor+" "+statusCode+text+"\r\n")

		resp.Header.Write(&b)

		// End-of-header
		io.WriteString(&b, "\r\n")

		dump = b.Bytes()
	}
	return
}

func doRequest(req *http.Request) (resp *http.Response, err error) {
	if resp, err = client.Do(req); err != nil &&
		strings.Index(err.Error(), stopRedirect) == -1 {
		log.Println(err)
		return resp, err
	}
	return resp, nil
}

func GetRealContentLength(resp *http.Response) (l int64, err error) {
	l = resp.ContentLength
	if l == -1 {
		l, err = io.Copy(ioutil.Discard, resp.Body)
	}

	return
}

func isChar(s string) (isChr bool) {
	for i := 0; i < len(s); i++ {
		if !((s[i] <= '9' && s[i] >= '0') || s[i] == '-' || s[i] == '.') {
			return true
		}
	}
	return false
}

func getDomain(host string) string {
	host = strings.Split(host, ":")[0]

	if net.ParseIP(host) != nil {
		return host
	}

	var domain string
	if domain = reDomain1.FindString(host); domain != "" {
		return domain
	}
	if domain = reDomain2.FindString(host); domain != "" {
		return domain
	}
	if domain = reDomain3.FindString(host); domain != "" {
		return domain
	}

	return ""
}

func isDbError(resp *http.Response) (bool, string) {
	// check last 1024 byte
	if resp.StatusCode == 200 &&
		strings.Index(strings.ToLower(resp.Header.Get("Content-Type")), "text") == 0 {

		var body []byte

		if resp.ContentLength >= 1024 {
			io.CopyN(ioutil.Discard, resp.Body, resp.ContentLength-1024)
			body, _ = ioutil.ReadAll(resp.Body)
		} else {
			buf1 := make([]byte, 1024)
			buf2 := make([]byte, 1024)
			for {
				_, e := io.ReadFull(resp.Body, buf1)
				if e == io.ErrUnexpectedEOF || e == io.EOF {
					break
				}
				_, e = io.ReadFull(resp.Body, buf2)
				if e == io.ErrUnexpectedEOF || e == io.EOF {
					break
				}
			}

			if l1, l2 := len(buf1), len(buf2); l2 < 1024 {
				body = append(buf1[l2:], buf2[:l2]...)
			} else {
				body = append(buf2[l1:], buf1[:l1]...)
			}
			return reDbErr.Match(body), string(body)
		}
	}
	return false, ""
}

type xmlItem struct {
	XMLName  xml.Name `xml:"HttpRequest"`
	Url      string   `xml:"url,attr"`
	VulType  int
	Sig      string
	Request  string
	Response string
}

type CoreEngine struct {
	Id         int
	Req        *http.Request
	Report     *report.XmlReport
	Body       []byte
	urlValues  url.Values
	cookies    url.Values
	headValues url.Values

	upfiles url.Values
	fh      map[string]*multipart.FileHeader
}

func FixResponse(resp *http.Response) {
	// https://code.google.com/p/go/issues/detail?id=5381
	// fix add Content-Length: 0 when resp.Write()
	if resp != nil && resp.StatusCode == 200 &&
		resp.ContentLength == 0 && len(resp.TransferEncoding) == 0 {
		resp.TransferEncoding = append(resp.TransferEncoding, "identity")
	}
}

func (ce *CoreEngine) ExportRlt(vultype int, sig interface{}, req, resp string) {
	var es string
	switch s := sig.(type) {
	case string:
		es = EscapeNonAscii(s)
	case [2]string:
		es = EscapeNonAscii(s[0]) + "\n" + EscapeNonAscii(s[1])
	}

	ce.Report.Marshal(&xmlItem{
		Url:      ce.Req.URL.String(),
		VulType:  vultype,
		Sig:      es,
		Request:  req,
		Response: resp,
	})

	db.Insert(ce.Id, vultype, es, req, resp)
}

func (ce *CoreEngine) setRequest(key, val string, checkType int) (body interface{}) {
	switch checkType {
	case checkHead:
		ce.headValues.Set(key, val)
		for k, v := range ce.headValues {
			ce.Req.Header[k] = v
		}
		if ce.Body != nil {
			ce.Req.Body = ioutil.NopCloser(bytes.NewReader(ce.Body))
			body = ce.Body
		}
	case checkUrl:
		ce.urlValues.Set(key, val)
		ce.Req.URL.RawQuery = ce.urlValues.Encode()
		if ce.Body != nil {
			ce.Req.Body = ioutil.NopCloser(bytes.NewReader(ce.Body))
			body = ce.Body
		}
	case checkCookie:
		ce.cookies.Set(key, val)
		ce.Req.Header.Del("Cookie")
		for k, v := range ce.cookies {
			cookie := &http.Cookie{Name: strings.Replace(url.QueryEscape(k), "+", "%2B", -1),
				Value: url.QueryEscape(v[0])}
			ce.Req.AddCookie(cookie)
		}
		if ce.Body != nil {
			ce.Req.Body = ioutil.NopCloser(bytes.NewReader(ce.Body))
			body = ce.Body
		}
	case checkPostForm:
		ce.Req.PostForm.Set(key, val)
		s := ce.Req.PostForm.Encode()
		ce.Req.Body = ioutil.NopCloser(strings.NewReader(s))
		ce.Req.ContentLength = int64(len(s))

		if ce.Req.Header.Get("Content-Length") != "" {
			ce.Req.Header.Set("Content-Length", strconv.Itoa(len(s)))
		}
		body = s
	case checkMultipartForm:
		ce.Req.MultipartForm.Value[key] = []string{val}
		b := bytes.NewBuffer(make([]byte, 0, len(ce.Body)+64))
		w := multipart.NewWriter(b)
		for k, v := range ce.Req.MultipartForm.Value {
			field, _ := w.CreateFormField(k)
			io.WriteString(field, v[0])
		}
		for key, fh := range ce.Req.MultipartForm.File {
			field, _ := w.CreateFormFile(key, fh[0].Filename)
			f, _ := fh[0].Open()
			io.Copy(field, f)
			f.Close()
		}
		w.Close()

		buf := b.Bytes()
		ce.Req.Body = ioutil.NopCloser(bytes.NewReader(buf))
		ce.Req.ContentLength = int64(len(buf))

		if ce.Req.Header.Get("Content-Length") != "" {
			ce.Req.Header.Set("Content-Length", strconv.Itoa(len(buf)))
		}
		body = buf
	case checkMultipartFormFile:
		ce.upfiles.Set(key, val)
		b := bytes.NewBuffer(make([]byte, 0, len(ce.Body)+64))
		w := multipart.NewWriter(b)
		for k, v := range ce.Req.MultipartForm.Value {
			field, _ := w.CreateFormField(k)
			io.WriteString(field, v[0])
		}
		for key, filename := range ce.upfiles {
			field, _ := w.CreateFormFile(key, filename[0])
			f, _ := ce.fh[key].Open()
			io.Copy(field, f)
			f.Close()
		}
		w.Close()

		buf := b.Bytes()
		ce.Req.Body = ioutil.NopCloser(bytes.NewReader(buf))
		ce.Req.ContentLength = int64(len(buf))

		if ce.Req.Header.Get("Content-Length") != "" {
			ce.Req.Header.Set("Content-Length", strconv.Itoa(len(buf)))
		}
		body = buf
	case checkPostXmlJson:
		s := val
		ce.Req.Body = ioutil.NopCloser(strings.NewReader(s))
		ce.Req.ContentLength = int64(len(s))

		if ce.Req.Header.Get("Content-Length") != "" {
			ce.Req.Header.Set("Content-Length", strconv.Itoa(len(s)))
		}
		body = s
	default:
		log.Fatal("no such checkType")
	}

	return
}

func (ce *CoreEngine) sendRequest() (resp *http.Response, err error) {
	resp, err = doRequest(ce.Req)
	return
}

func (ce *CoreEngine) resetReqHead(values url.Values, checkType int) {
	switch checkType {
	case checkUrl:
		ce.Req.URL.RawQuery = values.Encode()
	case checkCookie:
		ce.Req.Header.Del("Cookie")
		for k, v := range values {
			cookie := &http.Cookie{Name: k, Value: v[0]}
			ce.Req.AddCookie(cookie)
		}
	case checkHead:
		for k, v := range values {
			ce.Req.Header[k] = v
		}
	}
}

var reqWriteExcludeHeaderDump = map[string]bool{
	"Host":              true, // not in Header map anyway
	"Transfer-Encoding": true,
	"Trailer":           true,
}

func DumpRequestHead(req *http.Request) []byte {
	var b bytes.Buffer

	fmt.Fprintf(&b, "%s %s HTTP/%d.%d\r\n", req.Method, req.URL.RequestURI(),
		req.ProtoMajor, req.ProtoMinor)

	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", host)
	}

	if req.Header.WriteSubset(&b, reqWriteExcludeHeaderDump) != nil {
		return nil
	}

	if req.Close {
		fmt.Fprintf(&b, "Connection: close\r\n")
	}

	io.WriteString(&b, "\r\n")

	return b.Bytes()
}

func (ce *CoreEngine) scanSql(k string, d *decode.Decode, i int, checkType int) {
	_, s, err := d.Get(i)
	if err != nil {
		log.Println(err)
		return
	}
	isChr := isChar(s)
	if len(k) >= 2 && k[:2] == "__" && checkType != checkUrl {
		return
	}

	// --------------------------------SQL injection base blind-------------------------------
	for _, sig := range injectSig {
		if isChr && sig.t == sigNum || !isChr && sig.t == sigSch {
			continue
		}

		v, err := d.Set(i, s)
		if err != nil {
			log.Println(err)
			return
		}
		body0 := ce.setRequest(k, v, checkType)
		resp0, err := ce.sendRequest() // original request
		if err != nil {
			return
		}
		conTyp := strings.ToLower(resp0.Header.Get("Content-Type"))
		//Content-Type: Text/*
		if strings.Index(conTyp, "text") != 0 {
			continue
		}
		len0, err := GetRealContentLength(resp0)
		if err != nil {
			log.Println("GetRealContentLength err: ", err)
			continue
		}
		resp0.Body.Close()
		reqc0 := DumpRequestHead(ce.Req)

		if v, err = d.Set(i, s+sig.s[0]); err != nil {
			log.Println(err)
			return
		}
		body1 := ce.setRequest(k, v, checkType)
		resp1, err := ce.sendRequest() // true request
		if err != nil {
			continue
		}
		conTyp = strings.ToLower(resp1.Header.Get("Content-Type"))
		//Content-Type: Text/*
		if strings.Index(conTyp, "text") != 0 {
			continue
		}
		len1, err := GetRealContentLength(resp1)
		if err != nil {
			log.Println("GetRealContentLength err: ", err)
			continue
		}
		resp1.Body.Close()
		reqc1 := DumpRequestHead(ce.Req)

		if v, err = d.Set(i, s+sig.s[1]); err != nil {
			log.Println(err)
			break
		}
		body2 := ce.setRequest(k, v, checkType)
		resp2, err := ce.sendRequest() // false request
		if err != nil {
			continue
		}
		conTyp = strings.ToLower(resp2.Header.Get("Content-Type"))
		//Content-Type: Text/*
		if strings.Index(conTyp, "text") != 0 {
			continue
		}
		len2, err := GetRealContentLength(resp2)
		if err != nil {
			log.Println("GetRealContentLength err: ", err)
			continue
		}
		resp2.Body.Close()
		reqc2 := DumpRequestHead(ce.Req)

		diff := int(math.Abs(float64(len1-len2)) - math.Abs(float64(len0-len1)))
		if diff > 20 {
			respc0 := DumpResponse(resp0, false)
			respc1 := DumpResponse(resp1, false)
			respc2 := DumpResponse(resp2, false)

			reqc := "原始请求： \n" + string(reqc0)
			switch body := body0.(type) {
			case string:
				reqc += body
			case []byte:
				reqc += string(body)
			}
			reqc += "真条件请求： \n" + string(reqc1)
			switch body := body1.(type) {
			case string:
				reqc += body
			case []byte:
				reqc += string(body)
			}
			reqc += "假条件请求： \n" + string(reqc2)
			switch body := body2.(type) {
			case string:
				reqc += body
			case []byte:
				reqc += string(body)
			}

			respc := fmt.Sprintf("|%d-%d|-|%d-%d|=%d\n", len1, len2, len0, len1, diff)
			respc += "原始响应： \n" + string(respc0) + "真条件响应： \n" +
				string(respc1) + "假条件响应： \n" + string(respc2)

			ce.ExportRlt(10000, sig.s, reqc, respc)
			return
		}
	} // for injectSig

	// --------------------------------SQL injection base time-------------------------------
	for _, sig := range injectTimeSig {
		if isChr && sig.t == sigNum || !isChr && sig.t == sigSch {
			continue
		}

		v, err := d.Set(i, s+sig.s)
		if err != nil {
			log.Println(err)
			break
		}

		nextSig := false
		var t0, t1 time.Time
		var body interface{}
		var resp *http.Response

		for j := 0; j < 2; j++ { // try two
			body = ce.setRequest(k, v, checkType)
			t0 = time.Now()
			resp, err = ce.sendRequest()
			t1 = time.Now()
			if err != nil {
				nextSig = true
				break
			}
			resp.Body.Close()

			if t1.Sub(t0).Seconds() < 15-1 { // No high precision clock
				nextSig = true
				break
			}
		}
		if nextSig {
			continue
		}

		reqc := string(DumpRequestHead(ce.Req))
		switch b := body.(type) {
		case string:
			reqc += b
		case []byte:
			reqc += string(b)
		}
		respc := DumpResponse(resp, false)
		s1 := "发送请求时间： " + t0.Format("2006-01-02 15:04:05") + "\n\n" + reqc
		s2 := "接收请求时间： " + t1.Format("2006-01-02 15:04:05") + "\n\n" + string(respc)
		ce.ExportRlt(10001, sig.s, s1, s2)
		return
	} // for injectTimeSig
}

func (ce *CoreEngine) scanXss(k string, d *decode.Decode, i int, checkType int) {
	_, s, err := d.Get(i)
	if err != nil {
		log.Println(err)
		return
	}

	for _, sig := range xssSig {
		v, err := d.Set(i, s+sig)
		if err != nil {
			log.Println(err)
			return
		}
		body := ce.setRequest(k, v, checkType)
		resp, err := ce.sendRequest()
		if err != nil {
			continue
		}

		conTyp := strings.ToLower(resp.Header.Get("Content-Type"))

		if strings.Index(conTyp, "text/json") == 0 {
			respByte, _ := ioutil.ReadAll(resp.Body)
			respString := string(respByte)
			json := decode.NewDecode(respString)
			for i := 0; i < json.Count(); i++ {
				_, s, err = json.Get(i)
				if err != nil {
					log.Println(err)
					continue
				}

				if strings.Contains(strings.ToLower(s), sig) {
					reqc := string(DumpRequestHead(ce.Req))
					switch b := body.(type) {
					case string:
						reqc += b
					case []byte:
						reqc += string(b)
					}
					ce.ExportRlt(20001, sig, reqc, respString)
					resp.Body.Close()
					break
				}
			}
		}
		if strings.Index(conTyp, "text/xml") == 0 {
			respByte, _ := ioutil.ReadAll(resp.Body)
			respString := string(respByte)
			xml := decode.NewDecode(respString)
			for i := 0; i < xml.Count(); i++ {
				_, s, err := xml.Get(i)
				if err != nil {
					log.Println(err)
					continue
				}
				if strings.Contains(strings.ToLower(s), sig) {
					reqc := string(DumpRequestHead(ce.Req))
					switch b := body.(type) {
					case string:
						reqc += b
					case []byte:
						reqc += string(b)
					}
					ce.ExportRlt(20002, sig, reqc, respString)
					resp.Body.Close()
					break
				}
			}
		}
		if strings.Index(conTyp, "text/html") == 0 {
			var line []byte
			xss := false
			bsig := []byte(sig)
			q := NewQueue(5, false)
			b := bufio.NewReader(resp.Body)
			for {
				line, _ = b.ReadBytes('\n')
				if len(line) == 0 {
					break
				}
				q.Push(line)
				if bytes.Contains(bytes.ToLower(line), bsig) {
					xss = true
					break
				}
			}
			if xss {
				if last1, _ := b.ReadBytes('\n'); len(last1) != 0 {
					q.Push(last1)
				}
				if last2, _ := b.ReadBytes('\n'); len(last2) != 0 {
					q.Push(last2)
				}
				result := make([]byte, 0, q.Len()*len(line))
				for i := 0; i < q.Len(); i++ {
					result = append(result, q.Poll().([]byte)...)
				}

				reqc := string(DumpRequestHead(ce.Req))
				switch b := body.(type) {
				case string:
					reqc += b
				case []byte:
					reqc += string(b)
				}
				ce.ExportRlt(20000, sig, reqc, string(result))
				resp.Body.Close()
				break
			}
		}
		resp.Body.Close()
	} // for xssSig
}

func (ce *CoreEngine) scanErr(k string, d *decode.Decode, i int, checkType int) {
	_, s, err := d.Get(i)
	if err != nil {
		log.Println(err)
		return
	}

	for _, sig := range errSig {
		v, err := d.Set(i, s+sig)
		if err != nil {
			log.Println(err)
			return
		}
		body := ce.setRequest(k, v, checkType)
		resp, err := ce.sendRequest()
		if err != nil {
			continue
		}
		if resp.StatusCode >= 500 {
			reqc := string(DumpRequestHead(ce.Req))
			switch b := body.(type) {
			case string:
				reqc += b
			case []byte:
				reqc += string(b)
			}
			respc := DumpResponse(resp, true)
			resp.Body.Close()

			ce.ExportRlt(30000, sig, reqc, string(respc))
			break
		}
		if bErr, cErr := isDbError(resp); bErr {
			reqc := string(DumpRequestHead(ce.Req))
			switch b := body.(type) {
			case string:
				reqc += b
			case []byte:
				reqc += string(b)
			}
			ce.ExportRlt(30001, sig, reqc, cErr)
			break
		}
		resp.Body.Close()
	} // for errSig
}

func (ce *CoreEngine) setHeadValues(keys ...string) {
	ce.headValues = make(url.Values, len(keys))
	for _, k := range keys {
		if k == "Content-Length" {
			continue
		}
		if v, ok := ce.Req.Header[k]; ok {
			ce.headValues[k] = v
		} else if k == "X-Forwarded-For" {
			ce.headValues.Set(k, "122.225.36.88")
		}
	}
}

func (ce *CoreEngine) setCookieValues() {
	cookies := ce.Req.Cookies()
	ce.cookies = make(url.Values, len(cookies))
	for _, v := range cookies {
		ce.cookies[v.Name] = []string{v.Value}
	}
}

func (ce *CoreEngine) setMultipartFormFile() {
	ce.upfiles = make(url.Values, len(ce.Req.MultipartForm.File))
	ce.fh = make(map[string]*multipart.FileHeader, len(ce.Req.MultipartForm.File))

	for key, fh := range ce.Req.MultipartForm.File {
		ce.upfiles[key] = []string{fh[0].Filename}
		ce.fh[key] = fh[0]
	}
}

func (ce *CoreEngine) checkHead() {
	ce.setHeadValues("Referer", "X-Forwarded-For") // init ce.headValues

	for k, v := range ce.headValues {
		d := decode.NewDecode(v[0])
		for i := 0; i < d.Count(); i++ {
			ce.scanSql(k, d, i, checkHead)
			// ce.scanXss(k, d, i, checkHead)
			ce.scanErr(k, d, i, checkHead)
		}
		ce.headValues[k] = v // repair values
	}
	ce.resetReqHead(ce.headValues, checkHead)
}

func (ce *CoreEngine) checkUrl() {
	ce.urlValues, _ = url.ParseQuery(ce.Req.URL.RawQuery) // init ce.urlValues

	for k, v := range ce.urlValues {
		d := decode.NewDecode(v[0])
		for i := 0; i < d.Count(); i++ {
			ce.scanSql(k, d, i, checkUrl)
			ce.scanXss(k, d, i, checkUrl)
			ce.scanErr(k, d, i, checkUrl)
		}
		ce.urlValues[k] = v // repair values
	}
	ce.resetReqHead(ce.urlValues, checkUrl)
}

func (ce *CoreEngine) checkCookie() {
	ce.setCookieValues() // init ce.cookies

	for k, v := range ce.cookies {
		d := decode.NewDecode(v[0])
		for i := 0; i < d.Count(); i++ {
			ce.scanSql(k, d, i, checkCookie)
			// ce.scanXss(k, d, i, checkCookie)
			ce.scanErr(k, d, i, checkCookie)
		}
		ce.cookies[k] = v // repair values
	}
	ce.resetReqHead(ce.cookies, checkCookie)
}

func (ce *CoreEngine) checkPostForm() {
	if len(ce.Req.PostForm) == 0 {
		return
	}

	contentLen := ce.Req.ContentLength

	for k, v := range ce.Req.PostForm {
		d := decode.NewDecode(v[0])
		for i := 0; i < d.Count(); i++ {
			ce.scanSql(k, d, i, checkPostForm)
			ce.scanXss(k, d, i, checkPostForm)
			ce.scanErr(k, d, i, checkPostForm)
		}
		ce.Req.PostForm[k] = v // repair values
	}

	ce.Req.ContentLength = contentLen
	if ce.Req.Header.Get("Content-Length") != "" {
		ce.Req.Header.Set("Content-Length", strconv.Itoa(int(contentLen)))
	}
}

func (ce *CoreEngine) checkMultipartForm() {
	if ce.Req.MultipartForm == nil || len(ce.Req.MultipartForm.Value) == 0 {
		return
	}

	contentLen := ce.Req.ContentLength

	for k, v := range ce.Req.MultipartForm.Value {
		d := decode.NewDecode(v[0])
		for i := 0; i < d.Count(); i++ {
			ce.scanSql(k, d, i, checkMultipartForm)
			ce.scanXss(k, d, i, checkMultipartForm)
			ce.scanErr(k, d, i, checkMultipartForm)
		}
		ce.Req.MultipartForm.Value[k] = v // repair values
	}

	ce.Req.ContentLength = contentLen
	if ce.Req.Header.Get("Content-Length") != "" {
		ce.Req.Header.Set("Content-Length", strconv.Itoa(int(contentLen)))
	}
}

func (ce *CoreEngine) checkMultipartFormFile() {
	if ce.Req.MultipartForm == nil || len(ce.Req.MultipartForm.File) == 0 {
		return
	}
	ce.setMultipartFormFile() // init ce.upfiles and ce.fh

	contentLen := ce.Req.ContentLength

	for k, v := range ce.upfiles {
		d := decode.NewDecode(v[0])
		for i := 0; i < d.Count(); i++ {
			ce.scanSql(k, d, i, checkMultipartFormFile)
			ce.scanXss(k, d, i, checkMultipartFormFile)
			ce.scanErr(k, d, i, checkMultipartFormFile)
		}
		ce.upfiles[k] = v // repair values
	}

	ce.Req.ContentLength = contentLen
	if ce.Req.Header.Get("Content-Length") != "" {
		ce.Req.Header.Set("Content-Length", strconv.Itoa(int(contentLen)))
	}
}

func (ce *CoreEngine) checkPostXmlJson() {
	conTyp := strings.ToLower(ce.Req.Header.Get("Content-Type"))
	if strings.Index(conTyp, "text") == 0 ||
		strings.Index(conTyp, "json") >= 0 ||
		strings.Index(conTyp, "xml") >= 0 {

		contentLen := ce.Req.ContentLength

		d := decode.NewDecode(string(ce.Body))
		for i := 0; i < d.Count(); i++ {
			ce.scanSql("", d, i, checkPostXmlJson)
			ce.scanXss("", d, i, checkPostXmlJson)
			ce.scanErr("", d, i, checkPostXmlJson)
		}

		ce.Req.ContentLength = contentLen
		if ce.Req.Header.Get("Content-Length") != "" {
			ce.Req.Header.Set("Content-Length", strconv.Itoa(int(contentLen)))
		}
	}
}

func (ce *CoreEngine) CheckVul() {
	ce.checkHead()
	ce.checkUrl()
	ce.checkCookie()

	if ce.Body != nil {
		ce.Req.Body = ioutil.NopCloser(bytes.NewReader(ce.Body))
		ce.Req.ParseMultipartForm(500 * 1024) // init ce.Req.PostForm and ce.Req.MultipartForm

		ce.checkPostForm()
		ce.checkMultipartForm()
		ce.checkMultipartFormFile()
		ce.checkPostXmlJson()
	}
}
