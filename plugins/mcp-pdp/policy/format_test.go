package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const formatTools = `{"governed": {"upstream": "https://u.example/mcp", "tools": {
  "lookup": {"facts": {"readOnly": true}, "definition": {"name": "lookup", "description": "Find", "annotations": {"readOnlyHint": true}}}}}}`

const formatRules = `permit (principal, action, resource) when { resource.reviewed.flags.contains({name: "readOnly", value: true}) };`

// writeLegacySet stores a format-1 set as earlier builds published it.
func writeLegacySet(t *testing.T, root string) string {
	t.Helper()
	contents := map[string][]byte{"rules.cedar": []byte(formatRules), "tools.json": []byte(formatTools), "checks.json": []byte("[]")}
	hashes := hashFiles(legacyFiles, contents)
	set := Fingerprint(legacyFormat, hashes)
	s, err := openStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.unlock()
	if err := s.writeSet(set, Manifest{Format: legacyFormat, Files: hashes}, contents); err != nil {
		t.Fatal(err)
	}
	return set
}

func decide(s *Snapshot) string {
	reason, _ := s.Decide(Caller{Issuer: "i", Subject: "s"}, "governed", "https://u.example/mcp", "lookup", nil)
	return reason
}

func TestFormatOneSetsStillLoad(t *testing.T) {
	root := t.TempDir()
	legacy := writeLegacySet(t, root)
	snapshot, manifest, err := LoadSet(root, legacy)
	if err != nil || manifest.Format != legacyFormat {
		t.Fatalf("format-1 set did not load: %v %+v", err, manifest)
	}
	if _, approved := snapshot.Instructions("governed"); approved {
		t.Fatal("a format-1 set approved instructions")
	}
	if err := Activate(root, legacy, epoch); err != nil {
		t.Fatalf("activating a format-1 set: %v", err)
	}
	source := writeSource(t, formatRules, formatTools, "[]")
	current, err := Promote(root, source, "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	converted, _, err := LoadSet(root, current)
	if err != nil {
		t.Fatal(err)
	}
	if decide(snapshot) != "permitted" || decide(converted) != "permitted" {
		t.Fatalf("decisions differ: format 1 %s, format 2 %s", decide(snapshot), decide(converted))
	}
}

func TestPromoteConvertsAFormatOneSource(t *testing.T) {
	root, source := t.TempDir(), t.TempDir()
	for name, text := range map[string]string{"rules.cedar": formatRules, "tools.json": formatTools, "checks.json": "[]"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set, err := Promote(root, source, "converted", epoch)
	if err != nil {
		t.Fatal(err)
	}
	manifest, contents, err := ReadSet(root, set)
	if err != nil || manifest.Format != FormatVersion {
		t.Fatalf("converted set: %v %+v", err, manifest)
	}
	if string(contents["approved_tools.json"]) != formatTools || strings.TrimSpace(string(contents["approved_instructions.json"])) != "{}" {
		t.Fatalf("converted files: %q %q", contents["approved_tools.json"], contents["approved_instructions.json"])
	}
	if _, err := os.Stat(filepath.Join(root, setsDir, set, "tools.json")); !os.IsNotExist(err) {
		t.Fatal("the converted set kept tools.json")
	}
	// A source with both layouts is ambiguous.
	if err := os.WriteFile(filepath.Join(source, "approved_tools.json"), []byte(formatTools), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(root, source, "", epoch); err == nil {
		t.Fatal("accepted a source with both tools.json and approved_tools.json")
	}
}

func TestApprovedInstructions(t *testing.T) {
	compile := func(instructions string) (*Snapshot, error) {
		return Compile(Inputs{Rules: []byte(formatRules), Tools: []byte(formatTools), Instructions: []byte(instructions), Checks: []byte("[]")}, "v")
	}
	s, err := compile(`{"governed": "Use lookup for records.", "quiet": ""}`)
	if err != nil {
		t.Fatal(err)
	}
	if text, ok := s.Instructions("governed"); !ok || text != "Use lookup for records." {
		t.Fatalf("governed: %q %v", text, ok)
	}
	if text, ok := s.Instructions("quiet"); !ok || text != "" {
		t.Fatalf("an empty approved value: %q %v", text, ok)
	}
	if _, ok := s.Instructions("other"); ok {
		t.Fatal("instructions approved for an unlisted proxy")
	}
	for _, bad := range []string{`{"governed": null}`, `null`, `[]`, `{"governed": 7}`, `{"": "x"}`, `{"governed": "a", "governed": "b"}`} {
		if _, err := compile(bad); err == nil {
			t.Errorf("accepted approved instructions %s", bad)
		}
	}
}

func TestDefinitionsAreValidated(t *testing.T) {
	compile := func(definition string) error {
		tools, _ := json.Marshal(map[string]any{"governed": map[string]any{"upstream": "https://u.example/mcp",
			"tools": map[string]any{"lookup": map[string]any{"definition": json.RawMessage(definition)}}}})
		_, err := Compile(Inputs{Rules: []byte(formatRules), Tools: tools, Instructions: []byte("{}"), Checks: []byte("[]")}, "v")
		return err
	}
	if err := compile(`{"name": "lookup", "description": "Find"}`); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"name": "other"}`, `{"name": "lookup", "description": "a", "description": "b"}`} {
		if err := compile(bad); err == nil {
			t.Errorf("accepted definition %s", bad)
		}
	}
}

func TestFormatOneToleratesDefinitionsFormatTwoRefuses(t *testing.T) {
	// A number beyond the range of a 64-bit float cannot be canonicalized.
	tools := `{"governed": {"upstream": "https://u.example/mcp", "tools": {"lookup": {"facts": {"readOnly": true},
	  "definition": {"name": "lookup", "inputSchema": {"type": "object", "properties": {"n": {"type": "number", "maximum": 1e400}}}}}}}}`
	if _, err := Compile(Inputs{Rules: []byte(formatRules), Tools: []byte(tools), Checks: []byte("[]"), Format: legacyFormat}, "v"); err != nil {
		t.Fatalf("a format-1 set that loaded before now fails: %v", err)
	}
	if _, err := Compile(Inputs{Rules: []byte(formatRules), Tools: []byte(tools), Instructions: []byte("{}"), Checks: []byte("[]")}, "v"); err == nil {
		t.Fatal("a format-2 set approved a definition without a fingerprint")
	}
}

func TestWholeNumberAnnotationsAgreeWithFingerprints(t *testing.T) {
	// Upstream annotations can only narrow access, so the rule that reads one
	// is a forbid.
	rules := []byte(`permit (principal, action, resource);
forbid (principal, action, resource) when { resource.upstreamAnnotations.numbers.contains({name: "cost", value: 1}) };`)
	decideWith := func(cost string) string {
		definition := `{"name": "lookup", "annotations": {"cost": ` + cost + `}}`
		tools := `{"governed": {"upstream": "https://u.example/mcp", "tools": {"lookup": {"definition": ` + definition + `}}}}`
		s, err := Compile(Inputs{Rules: rules, Tools: []byte(tools), Instructions: []byte("{}"), Checks: []byte("[]")}, "v")
		if err != nil {
			t.Fatal(err)
		}
		return decide(s)
	}
	var fingerprints []string
	for _, cost := range []string{"1", "1.0", "1e0"} {
		if got := decideWith(cost); got != "policy_denied" {
			t.Errorf("cost %s was not read as the integer 1: %s", cost, got)
		}
		fingerprints = append(fingerprints, fingerprint(t, `{"name": "lookup", "annotations": {"cost": `+cost+`}}`))
	}
	if fingerprints[0] != fingerprints[1] || fingerprints[0] != fingerprints[2] {
		t.Fatalf("spellings of one number fingerprinted differently: %v", fingerprints)
	}
	if got := decideWith("1.5"); got != "permitted" {
		t.Fatalf("a fractional annotation became an integer: %s", got)
	}
}

// compileCost builds a one-tool set whose definition annotates a cost, in the
// given format, and decides a call to it.
func compileCost(t *testing.T, rules, cost string, format int) string {
	t.Helper()
	definition := `{"name": "lookup", "annotations": {"cost": ` + cost + `}}`
	tools := `{"governed": {"upstream": "https://u.example/mcp", "tools": {"lookup": {"definition": ` + definition + `}}}}`
	in := Inputs{Rules: []byte(rules), Tools: []byte(tools), Checks: []byte("[]"), Format: format}
	if format != legacyFormat {
		in.Instructions = []byte("{}")
	}
	s, err := Compile(in, "v")
	if err != nil {
		t.Fatal(err)
	}
	return decide(s)
}

func TestFormatOneAnnotationDecisionsAreUnchanged(t *testing.T) {
	rules := `permit (principal, action, resource);
forbid (principal, action, resource) when { resource.upstreamAnnotations.numbers.contains({name: "cost", value: 1}) };`
	// Earlier builds read only integer spellings as numbers; format-1 sets keep that.
	if got := compileCost(t, rules, "1", legacyFormat); got != "policy_denied" {
		t.Fatalf("format 1, cost 1: %s", got)
	}
	if got := compileCost(t, rules, "1.0", legacyFormat); got != "permitted" {
		t.Fatalf("format 1, cost 1.0 changed meaning: %s", got)
	}
}

func TestNullIsNeverANumber(t *testing.T) {
	// A forbid for cost 0 applies to 0 and not to null. (An annotation can only
	// narrow access, so the check is a forbid rather than an exception.)
	rules := `permit (principal, action, resource);
forbid (principal, action, resource) when { resource.upstreamAnnotations.numbers.contains({name: "cost", value: 0}) };`
	for _, format := range []int{legacyFormat, FormatVersion} {
		if got := compileCost(t, rules, "0", format); got != "policy_denied" {
			t.Fatalf("format %d: cost 0: %s", format, got)
		}
		if got := compileCost(t, rules, "null", format); got != "permitted" {
			t.Fatalf("format %d: null was read as 0: %s", format, got)
		}
	}
}

func TestLargeIntegersAgreeWithFingerprints(t *testing.T) {
	// Both spellings canonicalize to the same binary64 number.
	rules := `permit (principal, action, resource);
forbid (principal, action, resource) when { resource.upstreamAnnotations.numbers.contains({name: "cost", value: 9007199254740992}) };`
	a, b := "9007199254740993", "9007199254740993.0"
	if fingerprint(t, `{"name":"lookup","annotations":{"cost":`+a+`}}`) != fingerprint(t, `{"name":"lookup","annotations":{"cost":`+b+`}}`) {
		t.Fatal("the two spellings fingerprinted differently")
	}
	if compileCost(t, rules, a, FormatVersion) != compileCost(t, rules, b, FormatVersion) {
		t.Fatal("two spellings with one fingerprint produced different decisions")
	}
}

func TestMetaDoesNotBlockAFingerprint(t *testing.T) {
	if _, err := DefinitionFingerprint([]byte(`{"name": "lookup", "_meta": {"big": 1e400}}`)); err != nil {
		t.Fatalf("ignored metadata blocked the fingerprint: %v", err)
	}
}
