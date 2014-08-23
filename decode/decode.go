package decode

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	BARE = iota
	BASE64
	BASE64_URL
	URL_ENCODE
	JSONMAP
	JSONARRAY
	XMLOBJ

	notBare = "the leaf type is not BARE!"
)

var (
	RangeErr = errors.New("out of the Decode range!")
)

type jsonMap struct {
	org interface{}
	m   map[string]interface{}
	k   string
}

type jsonArray struct {
	org interface{}
	a   []interface{}
	i   int
}

type xmlObj struct {
	xt    []xmlToken
	index int
}

type xmlToken struct {
	isData bool
	token  xml.Token
}

type node struct {
	typ int
	pre *node

	key string

	// string(BARE), nil(BASE64), nil(BASE64_URL), nil(URL_ENCODE)
	// jsonMap(JSONMAP), jsonArray(JSONARRAY), xmlObj(XMLOBJ)
	obj interface{}
}

type Decode struct {
	leaf []*node
}

func (d *Decode) Count() int {
	return len(d.leaf)
}

func (d *Decode) Get(i int) (string, string, error) {
	if i >= len(d.leaf) || i < 0 {
		return "", "", RangeErr
	}

	node := d.leaf[i]
	if node.typ != BARE {
		panic(notBare)
	}

	return node.key, node.obj.(string), nil
}

func set(n *node, s string) (string, error) {
	if n == nil {
		return s, nil
	}

	switch n.typ {
	case BARE:
		return set(n.pre, s)
	case BASE64:
		return set(n.pre, base64.StdEncoding.EncodeToString([]byte(s)))
	case BASE64_URL:
		return set(n.pre, base64.URLEncoding.EncodeToString([]byte(s)))
	case URL_ENCODE:
		return set(n.pre, url.QueryEscape(s))
	case JSONMAP:
		obj, _ := n.obj.(*jsonMap)
		save := obj.m[obj.k]
		obj.m[obj.k] = s
		j, err := json.Marshal(obj.org)
		obj.m[obj.k] = save
		if err != nil {
			return "", err
		}
		return set(n.pre, string(j))
	case JSONARRAY:
		obj, _ := n.obj.(*jsonArray)
		save := obj.a[obj.i]
		obj.a[obj.i] = s
		j, err := json.Marshal(obj.org)
		obj.a[obj.i] = save
		if err != nil {
			return "", err
		}
		return set(n.pre, string(j))
	case XMLOBJ:
		obj, _ := n.obj.(*xmlObj)
		save := obj.xt[obj.index].token
		obj.xt[obj.index].token = xml.CharData(s)
		x := obj.marshal()
		obj.xt[obj.index].token = save
		return set(n.pre, string(x))
	default:
		panic("Decode type invalid!")
	}
}

func (x *xmlObj) marshal() []byte {
	b := new(bytes.Buffer)
	for i := 0; i < len(x.xt); i++ {
		switch token := x.xt[i].token.(type) {
		case xml.StartElement:
			if token.Name.Space == "" {
				b.WriteString("<" + token.Name.Local)
			} else {
				b.WriteString("<" + token.Name.Space + ":" + token.Name.Local)
			}
			for _, attr := range token.Attr {
				b.WriteByte(' ')
				if attr.Name.Space == "" {
					b.WriteString(attr.Name.Local + "=\"" + attr.Value + "\"")
				} else {
					b.WriteString(attr.Name.Space + ":" + attr.Name.Local + "=\"" + attr.Value + "\"")
				}
			}
			b.WriteByte('>')
		case xml.EndElement:
			if token.Name.Space == "" {
				b.WriteString("</" + token.Name.Local)
			} else {
				b.WriteString("</" + token.Name.Space + ":" + token.Name.Local)
			}
			b.WriteByte('>')
		case xml.CharData:
			if x.xt[i].isData {
				xml.EscapeText(b, token)
			} else {
				b.Write(token)
			}
		case xml.ProcInst:
			b.WriteString("<?" + token.Target + " ")
			b.Write(token.Inst)
			b.WriteString("?>")
		case xml.Directive:
			b.WriteString("<!")
			b.Write(token)
			b.WriteString(">")
		case xml.Comment:
			b.WriteString("<!--")
			b.Write(token)
			b.WriteString("-->")
		}
	}

	return b.Bytes()
}

func (d *Decode) Set(i int, s string) (string, error) {
	if i >= len(d.leaf) || i < 0 {
		return "", RangeErr
	}

	node := d.leaf[i]
	if node.typ != BARE {
		panic(notBare)
	}

	return set(node, s)
}

func NewDecode(s string) (d *Decode) {
	d = new(Decode)
	d.decode(s, nil)
	return
}

func (d *Decode) decode(v interface{}, pre *node) {
	var s string
	n := new(node)
	if pre != nil {
		n.pre = pre
		n.key = pre.key
	}

	switch vv := v.(type) {
	case string:
		s = vv
	case float64, bool:
		n.typ = BARE
		n.obj = fmt.Sprint(vv)
		d.leaf = append(d.leaf, n)
		return
	case nil:
		n.typ = BARE
		n.obj = ""
		d.leaf = append(d.leaf, n)
		return
	default:
		panic("invalid type in decode!")
	}

	var org interface{}
	if json.Unmarshal([]byte(s), &org) == nil {
		switch v := org.(type) {
		case map[string]interface{}, []interface{}:
			d.parseInterface(&org, &v, n) // recursive self and decode
			return
		}
	}

	n.typ = BARE
	n.obj = s
	d.leaf = append(d.leaf, n)

	if s != "" {
		if d.parseXML(s, pre) { // recursive decode
			return
		}

		var key string
		if pre != nil {
			key = pre.key
		}

		if strings.IndexRune(s, '%') >= 0 {
			if data, err := url.QueryUnescape(s); err == nil {
				d.decode(data, &node{URL_ENCODE, pre, key, nil})
				return
			}
		}

		if data, err := base64.StdEncoding.DecodeString(s); err == nil {
			d.decode(string(data), &node{BASE64, pre, key, nil})
			return
		}

		if data, err := base64.URLEncoding.DecodeString(s); err == nil {
			d.decode(string(data), &node{BASE64_URL, pre, key, nil})
			return
		}
	}
}

func (d *Decode) parseXML(s string, pre *node) bool {
	tokenArray := make([]xmlToken, 0, 64)

	decoder := xml.NewDecoder(strings.NewReader(s))
	for t, err := decoder.RawToken(); err == nil; t, err = decoder.RawToken() {
		tokenArray = append(tokenArray, xmlToken{token: xml.CopyToken(t)})
	}

	var isXML bool
	for i := 0; i < len(tokenArray); i++ {
		if token, ok := tokenArray[i].token.(xml.CharData); ok {
			if i > 0 && i+1 < len(tokenArray) {
				if start, ok := tokenArray[i-1].token.(xml.StartElement); ok {
					if _, ok := tokenArray[i+1].token.(xml.EndElement); ok {
						isXML = true
						tokenArray[i].isData = true
						d.decode(string(token), &node{XMLOBJ, pre,
							start.Name.Local, &xmlObj{tokenArray, i}})
					}
				}
			}
		}
	}

	return isXML
}

func (d *Decode) parseInterface(org, i interface{}, pre *node) {
	ii, ok := i.(*interface{})
	if !ok {
		panic("the parameter must be *interface{} type!")
	}

	switch v := (*ii).(type) {
	case map[string]interface{}:
		for k, vv := range v {
			switch vv.(type) {
			case map[string]interface{}, []interface{}:
				pre.key = k
				d.parseInterface(org, &vv, pre)
			default:
				d.decode(vv, &node{JSONMAP, pre, k, &jsonMap{org, v, k}})
			}
		}
	case []interface{}:
		for i, vv := range v {
			switch vv.(type) {
			case map[string]interface{}, []interface{}:
				d.parseInterface(org, &vv, pre)
			default:
				var key string
				if pre != nil {
					key = pre.key
				}
				d.decode(vv, &node{JSONARRAY, pre, key, &jsonArray{org, v, i}})
			}
		}
	default:
		panic("parse invalid type!")
	}
}
