package driftreview

import (
	"strings"
	"testing"

	"github.com/go-json-experiment/json/jsontext"
)

func TestSchemasThatAreBooleansAreCompared(t *testing.T) {
	diff := DefinitionDiff(jsontext.Value(`{"inputSchema":{"type":"object","properties":{"x":false}}}`),
		jsontext.Value(`{"inputSchema":{"type":"object","properties":{"x":true}}}`))
	if !strings.Contains(diff, "Schema of parameter x changed: false → true") {
		t.Fatalf("diff:\n%s", diff)
	}
}

func TestNamesStayOnOneLine(t *testing.T) {
	if got := ShownName("tool\nfake row"); got != "tool⟨U+000A⟩fake row" {
		t.Fatalf("shownName = %q", got)
	}
}

func TestVisibleLeavesOtherScriptsAlone(t *testing.T) {
	for text, want := range map[string]string{
		"привет мир":  "привет мир",
		"pаypal":      "pа⟨U+0430⟩ypal",
		"a\tb":        "a⟨U+0009⟩b",
		"⟨U+0041⟩":    "⟨U+27E8⟩U+0041⟨U+27E9⟩",
		"line\nline":  "line\nline",
		"x\u00a0y":    "x⟨U+00A0⟩y",
		"a\u034fb":    "a⟨U+034F⟩b",
		"e\u0301cole": "e\u0301cole",
		"café":        "café",
		"αбв":         "α⟨U+03B1⟩б⟨U+0431⟩в⟨U+0432⟩",
	} {
		if got, _, _ := Visible(text); got != want {
			t.Errorf("Visible(%q) = %q, want %q", text, got, want)
		}
	}
}
