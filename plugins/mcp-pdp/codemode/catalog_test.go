package codemode

import (
	"encoding/json"
	"strings"
	"testing"
)

func entries() []Entry {
	return []Entry{
		{Proxy: "a", Name: "lookup", Definition: json.RawMessage(`{"name":"lookup","description":"Find a record.\nMore detail.","inputSchema":{"type":"object"}}`)},
		{Proxy: "a", Name: "plain"},
		{Proxy: "b", Name: "lookup", Definition: json.RawMessage(`{"name":"lookup","description":"Find a record elsewhere."}`)},
	}
}

func TestSearch(t *testing.T) {
	found, err := Search(entries(), "RECORD find", "", 0, "", "v1")
	if err != nil {
		t.Fatal(err)
	}
	tools := found["tools"].([]map[string]any)
	if len(tools) != 2 || tools[0]["proxy"] != "a" || tools[1]["proxy"] != "b" || tools[0]["description"] != "Find a record." ||
		tools[0]["call"] != `connectors["a"]["lookup"]` || tools[0]["inputSchema"] != nil || found["nextCursor"] != nil {
		t.Fatalf("summary search: %+v", found)
	}
	found, _ = Search(entries(), "lookup", "full", 0, "", "v1")
	tools = found["tools"].([]map[string]any)
	if string(tools[0]["inputSchema"].(json.RawMessage)) != `{"type":"object"}` || !strings.Contains(tools[0]["description"].(string), "More detail.") {
		t.Fatalf("full search: %+v", tools[0])
	}
}

func TestSearchPages(t *testing.T) {
	var seen []string
	cursor := ""
	for range 5 {
		found, err := Search(entries(), "", "", 1, cursor, "v1")
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range found["tools"].([]map[string]any) {
			seen = append(seen, tool["proxy"].(string)+"/"+tool["name"].(string))
		}
		next, more := found["nextCursor"].(string)
		if !more {
			break
		}
		cursor = next
	}
	if strings.Join(seen, ",") != "a/lookup,a/plain,b/lookup" {
		t.Fatalf("pages %v", seen)
	}
	// A cursor from another query or another policy set is refused.
	found, _ := Search(entries(), "", "", 1, "", "v1")
	next := found["nextCursor"].(string)
	if _, err := Search(entries(), "", "", 1, next, "v2"); err != ErrCursor {
		t.Errorf("a cursor from another set was accepted: %v", err)
	}
	if _, err := Search(entries(), "lookup", "", 1, next, "v1"); err != ErrCursor {
		t.Errorf("a cursor from another query was accepted: %v", err)
	}
	if _, err := Search(entries(), "", "", 1, "not-a-cursor", "v1"); err != ErrCursor {
		t.Errorf("a malformed cursor was accepted: %v", err)
	}
}

func TestDescribe(t *testing.T) {
	d := Describe(entries()[0])
	if d["call"] != `connectors["a"]["lookup"]` || string(d["inputSchema"].(json.RawMessage)) != `{"type":"object"}` {
		t.Fatalf("describe %+v", d)
	}
	if d := Describe(entries()[1]); d["note"] == nil || d["inputSchema"] != nil {
		t.Fatalf("a tool without an approved definition: %+v", d)
	}
}

func TestEditList(t *testing.T) {
	var reported []string
	report := func(name string) { reported = append(reported, name) }
	message := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"lookup"},{"name":"codemode.execute","description":"upstream"}],"nextCursor":"n"}}`)
	out := EditList(message, []json.RawMessage{Definition(SearchTool)}, report)
	var reply struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
			NextCursor string `json:"nextCursor"`
		} `json:"result"`
	}
	if json.Unmarshal(out, &reply) != nil {
		t.Fatalf("unreadable %s", out)
	}
	tools := reply.Result.Tools
	if len(tools) != 2 || tools[0].Name != "lookup" || tools[1].Name != SearchTool || tools[1].Description == "upstream" || reply.Result.NextCursor != "n" {
		t.Fatalf("edited %s", out)
	}
	if len(reported) != 1 || reported[0] != "codemode.execute" {
		t.Fatalf("reported %v", reported)
	}
	// Notifications, errors and lists needing no change pass unchanged.
	for _, m := range []string{
		`{"jsonrpc":"2.0","method":"notifications/progress"}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"lookup"}]}}`,
	} {
		if got := EditList([]byte(m), nil, report); string(got) != m {
			t.Errorf("changed %s to %s", m, got)
		}
	}
}

func TestDefinitionsAreValid(t *testing.T) {
	for _, name := range Tools {
		var d struct {
			Name        string         `json:"name"`
			InputSchema map[string]any `json:"inputSchema"`
		}
		if json.Unmarshal(Definition(name), &d) != nil || d.Name != name || d.InputSchema["type"] != "object" {
			t.Errorf("definition of %s: %s", name, Definition(name))
		}
	}
}
