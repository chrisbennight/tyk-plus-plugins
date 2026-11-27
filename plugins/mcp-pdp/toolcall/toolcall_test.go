package toolcall

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	c, err := Parse([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"refund","arguments":{"environment":"test"},"_meta":{"k":1}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(c.ID) != "7" || c.Method != "tools/call" || c.Name != "refund" || string(c.Arguments) != `{"environment":"test"}` || string(c.Meta) != `{"k":1}` {
		t.Fatalf("parsed %+v", c)
	}
	// Members the gateway does not read, and arguments with any names, are
	// left to the arguments check.
	if _, err := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"Name":1,"name":2},"task":{}},"extra":1}`)); err != nil {
		t.Fatal(err)
	}
}

func TestParseRefusesCaseVariants(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}},"Params":{"name":"t","arguments":{"x":1}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}},"paramſ":{"name":"t"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{},"Arguments":{"x":1}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","NAME":"u"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","_META":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"tools/list","params":{"name":"t"}}`,
		`{"jsonrpc":"2.0","id":1,"ID":2,"method":"tools/call","params":{"name":"t"}}`,
		`{"jsonrpc":"2.0","JSONRPC":"1.0","id":1,"method":"tools/call","params":{"name":"t"}}`,
	} {
		c, err := Parse([]byte(body))
		if !errors.Is(err, ErrAmbiguous) {
			t.Errorf("%s: got %v", body, err)
		}
		if string(c.ID) != "1" {
			t.Errorf("%s: the refusal needs the request ID, got %q", body, c.ID)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"a":1,"a":2}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t"},"params":{"name":"u"}}`,
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"t\",\"arguments\":{\"a\":\"\xff\"}}}",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[]}`,
		`not json`,
	} {
		if _, err := Parse([]byte(body)); err == nil || errors.Is(err, ErrAmbiguous) {
			t.Errorf("%s: got %v", body, err)
		}
	}
}
