package decode

import (
	// "encoding/base64"
	"fmt"
	// "net/url"
	"testing"
)

var (
	data = `ICB7ICJuYW1lIjoiV2VkbmVzZGF%35%49%69wiQWdlIjpmYWxzZSwiUGFyZW50cyIgOiBbIkdvbWV6IiwiZDJGdVoyaHMiLCBudWxsICwgImV5SmhZbU1pT25SeWRXVXNJQ0psWm1jaU9qQjlJQT09IgogXSwgImpfc29OIjp7IndobCI6NSwgImpqd3ciOi0xLjAzLCAiSmp3dyI6bnVsbCwgIm15dGVzdCIgOiAgIllsaHNNRnBZVGpCaFZ6VnVUVlJKZWs1QkpUTkVKVE5rIn19IAo%67`
	sig  = `'and 1=0`

	//input = `
	//<test1>
	//<test2>{"a1":"jjww1", "age":false, "Parents" : ["&lt;in1&gt;god&lt;/in1&gt;", "2jjww", null]}</test2>
	//<test3>123</test3>
	//</test1>
	//<email>abc@163.com</email>`
	input = `
<test1>
	<test2>{&#34;Parents&#34;:[&#34;\u003cin1\u003egod\u003c/in1\u003e&#34;,&#34;2jjww&#34;,null],&#34;a1&#34;:&#34;jjww1&#34;,&#34;age&#34;:false}</test2>
	<test3>123</test3>
</test1>
<email>abc@163.com</email>
`
)

func validate(s, org string) error {
	dd := NewDecode(s)
	for ii := 0; ii < dd.Count(); ii++ {
		_, vv, err := dd.Get(ii)
		if err != nil {
			return fmt.Errorf("dd.Get(%d) error: %v", ii, err)
		}
		if vv == org {
			return nil
		}
	}

	return fmt.Errorf("decode %s can't found %s!\n", s, org)
}

func TestNewDecode(t *testing.T) {
	d := NewDecode(data)
	c := d.Count()
	if c != 18 {
		t.Fatalf("d.Count error: Got %d, expected 9", c)
	}

	var pre string
	for i := 0; i < c; i++ {
		_, v0, err := d.Get(i)
		if err != nil {
			t.Errorf("d.Get(%d) error: %v", i, err)
			continue
		}
		/*fmt.Printf("%s => %s\n", k, v0)
		continue*/

		v1 := v0 + sig
		v2, err := d.Set(i, v1)
		if err != nil {
			t.Errorf("d.Set(%d) error: %v", i, err)
			continue
		}
		/*vv2, _ := url.QueryUnescape(v2)
		b, _ := base64.StdEncoding.DecodeString(vv2)
		fmt.Printf("%s<--->%s\n\n", v1, string(b))*/
		if err := validate(v2, v1); err != nil {
			t.Errorf("index %d: %v", i, err)
		}

		if pre != "" {
			if err := validate(v2, pre); err == nil {
				t.Errorf("index %d: %s should find %s", i, v2, pre)
			}
		}

		pre = v1
	}
}

func TestNewDecode1(t *testing.T) {
	d := NewDecode(input)
	c := d.Count()
	if c != 9 {
		t.Fatalf("d.Count error: Got %d, expected 9", c)
	}

	var pre string
	for i := 0; i < c; i++ {
		k, v0, err := d.Get(i)
		if err != nil {
			t.Errorf("d.Get(%d) error: %v", i, err)
			continue
		}
		//fmt.Printf("%s => %s\n", k, v0)
		//continue

		if i == 2 && (k != "in1" || v0 != "god") {
			t.Fatalf("%s, %s, nil = d.Get(%d) but expected in1, god", k, v0, i)
		}

		v1 := v0 + sig
		v2, err := d.Set(i, v1)
		if err != nil {
			t.Errorf("d.Set(%d) error: %v", i, err)
			continue
		}
		if err := validate(v2, v1); err != nil {
			t.Errorf("index %d: %v", i, err)
		}

		if pre != "" {
			if err := validate(v2, pre); err == nil {
				t.Errorf("index %d: %s should find %s", i, v2, pre)
			}
		}

		pre = v1
	}
}

func BenchmarkNewDecode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewDecode(data)
	}
}

func BenchmarkSet(b *testing.B) {
	d := NewDecode(data)
	index := 8
	_, v, err := d.Get(index)
	if err != nil {
		b.Fatalf("d.Get(%d) error: %v", index, err)
	}

	// b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Set(index, v)
	}
}

func BenchmarkSet0(b *testing.B) {
	d := NewDecode(data)
	index := 0
	_, v, err := d.Get(index)
	if err != nil {
		b.Fatalf("d.Get(%d) error: %v", index, err)
	}

	// b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Set(index, v)
	}
}

func BenchmarkSet1(b *testing.B) {
	d := NewDecode(data)
	index := 1
	_, v, err := d.Get(index)
	if err != nil {
		b.Fatalf("d.Get(%d) error: %v", index, err)
	}

	// b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Set(index, v)
	}
}
