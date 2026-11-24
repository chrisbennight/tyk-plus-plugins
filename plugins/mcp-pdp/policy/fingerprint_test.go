package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func fingerprint(t *testing.T, definition string) string {
	t.Helper()
	fp, err := DefinitionFingerprint([]byte(definition))
	if err != nil {
		t.Fatalf("%s: %v", definition, err)
	}
	return fp
}

func TestFingerprintIgnoresLayoutAndMeta(t *testing.T) {
	base := fingerprint(t, `{"name":"lookup","description":"Find a record","inputSchema":{"type":"object","properties":{"id":{"type":"string"}}},"annotations":{"readOnlyHint":true}}`)
	for _, same := range []string{
		`{ "annotations": {"readOnlyHint": true}, "inputSchema": {"properties": {"id": {"type": "string"}}, "type": "object"},
		   "description": "Find a record", "name": "lookup" }`,
		`{"name":"lookup","description":"Find a record","inputSchema":{"type":"object","properties":{"id":{"type":"string"}}},"annotations":{"readOnlyHint":true},"_meta":{"trace":"x"}}`,
		// An escaped character is the same text once canonicalized.
		`{"name":"lookup","description":"Find a \u0072ecord","inputSchema":{"type":"object","properties":{"id":{"type":"string"}}},"annotations":{"readOnlyHint":true}}`,
	} {
		if got := fingerprint(t, same); got != base {
			t.Errorf("fingerprint changed for an equivalent definition: %s", same)
		}
	}
}

func TestFingerprintChangesWithContent(t *testing.T) {
	base := fingerprint(t, `{"name":"lookup","description":"Find a record","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}`)
	for _, changed := range []string{
		`{"name":"lookup","description":"Find a record.","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}`,
		`{"name":"lookup","description":"Find a record","inputSchema":{"type":"object","required":["id"]},"annotations":{"readOnlyHint":true}}`,
		`{"name":"lookup","description":"Find a record","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":false}}`,
		`{"name":"lookup","description":"Find a record","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true},"title":"Lookup"}`,
		// An invisible character is a change a reviewer must see.
		"{\"name\":\"lookup\",\"description\":\"Find a​record\",\"inputSchema\":{\"type\":\"object\"},\"annotations\":{\"readOnlyHint\":true}}",
	} {
		if got := fingerprint(t, changed); got == base {
			t.Errorf("fingerprint did not change: %s", changed)
		}
	}
}

func TestFingerprintRejectsAmbiguousDefinitions(t *testing.T) {
	for _, bad := range []string{
		`{"name":"lookup","name":"other"}`,
		`{"name":"lookup","inputSchema":{"type":"object","type":"string"}}`,
		`["lookup"]`,
		`null`,
		`{"name":`,
	} {
		if _, err := DefinitionFingerprint([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestFingerprintIsTheHashOfTheCanonicalForm(t *testing.T) {
	got, err := DefinitionFingerprint([]byte(`{"name": "t", "b": [1.0, {"y": "\u0041", "x": null}], "a": true, "_meta": {"z": 1}}`))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(`{"a":true,"b":[1.0,{"x":null,"y":"A"}],"name":"t"}`))
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
