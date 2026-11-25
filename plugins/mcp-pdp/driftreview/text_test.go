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

func TestIndentationIsBounded(t *testing.T) {
	// Each level indents every line below it, so deep nesting would indent
	// to many times its size.
	deep := strings.Repeat("[", 5000) + strings.Repeat("]", 5000)
	if got := Indented(jsontext.Value(deep)); len(got) > 2*len(deep) {
		t.Fatalf("indented %d bytes into %d", len(deep), len(got))
	}
	if got := Indented(jsontext.Value(`{"a":[1]}`)); got != "{\n  \"a\": [\n    1\n  ]\n}\n" {
		t.Fatalf("Indented = %q", got)
	}
}

func TestNamesMarkEveryLookAlikeLetter(t *testing.T) {
	// Spelled wholly in Cyrillic, the name reads as "change".
	if got := ShownName("сhаngе"); got != "с⟨U+0441⟩hа⟨U+0430⟩ngе⟨U+0435⟩" {
		t.Fatalf("ShownName = %q", got)
	}
	if got := ShownName("lookup_v2"); got != "lookup_v2" {
		t.Fatalf("ShownName = %q", got)
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
