package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestMetaDoesNotBlockAFingerprint(t *testing.T) {
	if _, err := DefinitionFingerprint([]byte(`{"name": "lookup", "_meta": {"big": 1e400}}`)); err != nil {
		t.Fatalf("ignored metadata blocked the fingerprint: %v", err)
	}
}

func TestNumbersAreFingerprintedExactly(t *testing.T) {
	// No two different numbers share a fingerprint, even beyond the precision
	// of a 64-bit float, and numbers outside its range still fingerprint.
	pairs := [][2]string{{"1", "1.0"}, {"1", "1e0"}, {"9007199254740993", "9007199254740992"}, {"1e400", "2e400"}}
	for _, pair := range pairs {
		a := fingerprint(t, `{"name":"lookup","inputSchema":{"maximum":`+pair[0]+`}}`)
		b := fingerprint(t, `{"name":"lookup","inputSchema":{"maximum":`+pair[1]+`}}`)
		if a == b {
			t.Errorf("%s and %s share a fingerprint", pair[0], pair[1])
		}
	}
}

func TestAnnotationsReadTheSameInBothFormats(t *testing.T) {
	rules := `permit (principal, action, resource);
forbid (principal, action, resource) when { resource.upstreamAnnotations.numbers.contains({name: "cost", value: 1}) };`
	for _, format := range []int{legacyFormat, FormatVersion} {
		// Only an integer spelling is an integer fact, as in earlier builds.
		if got := compileCost(t, rules, "1", format); got != "policy_denied" {
			t.Errorf("format %d, cost 1: %s", format, got)
		}
		if got := compileCost(t, rules, "1.0", format); got != "permitted" {
			t.Errorf("format %d, cost 1.0: %s", format, got)
		}
		// Integers beyond the precision of a 64-bit float are read exactly.
		large := `permit (principal, action, resource);
forbid (principal, action, resource) when { resource.upstreamAnnotations.numbers.contains({name: "cost", value: 9007199254740993}) };`
		if got := compileCost(t, large, "9007199254740993", format); got != "policy_denied" {
			t.Errorf("format %d, a large integer was not read exactly: %s", format, got)
		}
		if got := compileCost(t, large, "9007199254740992", format); got != "permitted" {
			t.Errorf("format %d, a neighbouring integer matched: %s", format, got)
		}
		// Out-of-range numbers do not stop a set from loading.
		if got := compileCost(t, rules, "1e400", format); got != "permitted" {
			t.Errorf("format %d, cost 1e400: %s", format, got)
		}
	}
}

func TestBrokenLinksInASourceAreNotSkipped(t *testing.T) {
	for _, name := range []string{"approved_tools.json", "approved_instructions.json"} {
		root, source := t.TempDir(), t.TempDir()
		for file, text := range map[string]string{"rules.cedar": formatRules, "tools.json": formatTools, "checks.json": "[]"} {
			if err := os.WriteFile(filepath.Join(source, file), []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(filepath.Join(source, "missing"), filepath.Join(source, name)); err != nil {
			t.Fatal(err)
		}
		if _, err := Promote(root, source, "", epoch); err == nil {
			t.Errorf("a broken %s link was ignored", name)
		}
	}
}

func TestDeeplyNestedDefinitionsFingerprintQuickly(t *testing.T) {
	const depth = 5000
	schema := strings.Repeat(`{"items":`, depth) + `{"type":"string","description":"` + strings.Repeat("x", 1000) + `"}` + strings.Repeat("}", depth)
	start := time.Now()
	if _, err := DefinitionFingerprint([]byte(`{"name":"lookup","inputSchema":` + schema + `}`)); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a %d-level definition took %s", depth, elapsed)
	}
	// A large value deep inside is written once, not once per enclosing
	// level. Its time is compared with the same value at the top level, so
	// the test measures the cost of depth, not the speed of a busy machine:
	// writing it once per level would take thousands of times longer.
	value := `{"description":"` + strings.Repeat("x", 4<<20) + `"}`
	fingerprint := func(schema string) time.Duration {
		t.Helper()
		start := time.Now()
		if _, err := DefinitionFingerprint([]byte(`{"name":"lookup","inputSchema":` + schema + `}`)); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	flat := fingerprint(value)
	deep := fingerprint(strings.Repeat(`{"items":`, depth) + value + strings.Repeat("}", depth))
	if deep > 20*flat+time.Second {
		t.Fatalf("a %d-level definition with a large value took %s, against %s at the top level", depth, deep, flat)
	}
}

func TestDriftSettingsAreValidated(t *testing.T) {
	compile := func(drift string) error {
		tools := `{"governed": {"upstream": "https://u.example/mcp", "drift": ` + drift + `, "tools": {}}}`
		_, err := Compile(Inputs{Rules: []byte(""), Tools: []byte(tools), Instructions: []byte("{}"), Checks: []byte("[]")}, "v")
		return err
	}
	fp := strings.Repeat("a", 64)
	for _, good := range []string{`{}`, `{"changedTools": "serve-approved", "changedInstructions": "strip"}`,
		`{"rejectedTools": {"lookup": ["` + fp + `"]}, "rejectedInstructions": ["` + fp + `"]}`} {
		if err := compile(good); err != nil {
			t.Errorf("%s: %v", good, err)
		}
	}
	for _, bad := range []string{`{"changedTools": "show"}`, `{"changedInstructions": "keep"}`, `{"rejectedTools": {"lookup": ["abc"]}}`,
		`{"rejectedInstructions": ["abc"]}`, `{"rejectedTools": {"": ["` + fp + `"]}}`, `{"unknown": true}`} {
		if err := compile(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestActivationChecksApplyDriftReview(t *testing.T) {
	compile := func(drift, expect string) error {
		tools := `{"governed": {"upstream": "https://u.example/mcp"` + drift + `, "tools": {"lookup": {}}}}`
		checks := `[{"caller": {"issuer": "i", "subject": "s"}, "proxy": "governed", "upstream": "https://u.example/mcp", "tool": "lookup", "expect": "` + expect + `"}]`
		_, err := Compile(Inputs{Rules: []byte(`permit (principal, action, resource);`), Tools: []byte(tools), Instructions: []byte("{}"), Checks: []byte(checks)}, "v")
		return err
	}
	if err := compile("", "permitted"); err != nil {
		t.Fatal(err)
	}
	// Under drift review lookup has no approved definition, so it is refused.
	if err := compile(`, "drift": {}`, "permitted"); err == nil || !strings.Contains(err.Error(), "unapproved_tool") {
		t.Fatalf("accepted a permit for an unapproved tool: %v", err)
	}
	// A check that expects the denial passes.
	if err := compile(`, "drift": {}`, "policy_denied"); err != nil {
		t.Fatal(err)
	}
	// A denial check naming a tool that is not listed, or the wrong upstream,
	// does not pass on drift review's account.
	for _, check := range []string{
		`[{"caller": {"issuer": "i", "subject": "s"}, "proxy": "governed", "upstream": "https://u.example/mcp", "tool": "lookpu", "expect": "policy_denied"}]`,
		`[{"caller": {"issuer": "i", "subject": "s"}, "proxy": "governed", "upstream": "https://other.example/mcp", "tool": "lookup", "expect": "policy_denied"}]`,
	} {
		tools := `{"governed": {"upstream": "https://u.example/mcp", "drift": {}, "tools": {"lookup": {}}}}`
		if _, err := Compile(Inputs{Rules: []byte(`permit (principal, action, resource);`), Tools: []byte(tools), Instructions: []byte("{}"), Checks: []byte(check)}, "v"); err == nil {
			t.Errorf("accepted %s", check)
		}
	}
}
