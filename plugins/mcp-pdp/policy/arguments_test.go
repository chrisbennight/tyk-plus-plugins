package policy

import (
	"strings"
	"testing"
)

// The example refund rule: a permit for the test environment and a forbid
// for production, each read from the same declared argument.
const argumentRules = `
@id("refund-test") permit (principal, action, resource) when { context.strings.contains({name: "environment", value: "test"}) };
@id("no-production") forbid (principal, action, resource) when { context.strings.contains({name: "environment", value: "production"}) };
`

const argumentTools = `{"p": {"upstream": "https://u.example/mcp", "tools": {"refund": {"arguments": {"environment": "string", "amount": "long"}}}}}`

func TestArgumentNamesMustBeUnambiguous(t *testing.T) {
	s, err := Compile(Inputs{Rules: []byte(argumentRules), Tools: []byte(argumentTools), Instructions: []byte("{}"), Checks: []byte("[]")}, "v")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args, want string
	}{
		{`{"environment": "test", "amount": 5}`, "permitted"},
		{`{"environment": "production"}`, "policy_denied"},
		{`{"environment": "staging"}`, "policy_denied"},
		// Names that merely share letters or a prefix are distinct.
		{`{"environment": "test", "env": "production", "environments": "production"}`, "permitted"},
		// Undeclared names are not read, but must not collide either.
		{`{"environment": "test", "note": "a", "Notes": "b"}`, "permitted"},
		{`{"environment": "test", "note": "a", "NOTE": "b"}`, "ambiguous_call"},
		// A case-insensitive parser could read production from these.
		{`{"environment": "test", "Environment": "production"}`, "ambiguous_call"},
		{`{"Environment": "production", "environment": "test"}`, "ambiguous_call"},
		{`{"environment": "test", "ENVIRONMENT": "production"}`, "ambiguous_call"},
		{`{"Environment": "production"}`, "ambiguous_call"},
		{`{"environment": "test", "amount": 5, "AMOUNT": 500}`, "ambiguous_call"},
		// Go's encoding/json folds the Kelvin sign to k and the long s to s.
		{`{"environment": "test", "environmentſ": "x", "environmentS": "y"}`, "ambiguous_call"},
		{`{"environment": "test", "amount": 5, "amountK": 1, "amountk": 2}`, "ambiguous_call"},
		// Values are compared exactly, and a name differing in a letter is
		// another name.
		{`{"environment": "teſt", "environmenK": 1}`, "policy_denied"},
		// A control character in a name is refused; some parsers drop it.
		{`{"environment": "test", "environment\u0000": "production"}`, "ambiguous_call"},
		{`{"environment": "test", "other\u001f": 1}`, "ambiguous_call"},
		{`{"environment": "test", "other\u007f": 1}`, "ambiguous_call"},
		// Exact duplicates, invalid UTF-8 and non-objects remain invalid.
		{`{"environment": "test", "environment": "production"}`, "invalid_argument"},
		{"{\"environment\": \"test\", \"x\": \"\xff\"}", "invalid_argument"},
		{`["environment", "test"]`, "invalid_argument"},
		{`"test"`, "invalid_argument"},
		{`{"environment": 1}`, "invalid_argument"},
	} {
		got, _ := s.Decide(Caller{Issuer: "i", Subject: "s"}, "p", "https://u.example/mcp", "refund", []byte(c.args))
		if got != c.want {
			t.Errorf("%s: got %s, want %s", c.args, got, c.want)
		}
	}
	// A call with no arguments, or null, supplies no facts.
	for _, args := range []string{"", "null", "{}"} {
		if got, _ := s.Decide(Caller{Issuer: "i", Subject: "s"}, "p", "https://u.example/mcp", "refund", []byte(args)); got != "policy_denied" {
			t.Errorf("%q: got %s", args, got)
		}
	}
}

// An activation check is decided as a live call, so one with ambiguous
// arguments rejects the set whatever it expects.
func TestActivationChecksRefuseAmbiguousArguments(t *testing.T) {
	for _, expect := range []string{"permitted", "policy_denied"} {
		checks := `[{"caller": {"issuer": "i", "subject": "s"}, "proxy": "p", "upstream": "https://u.example/mcp", "tool": "refund",
  "arguments": {"environment": "test", "Environment": "production"}, "expect": "` + expect + `"}]`
		_, err := Compile(Inputs{Rules: []byte(argumentRules), Tools: []byte(argumentTools), Instructions: []byte("{}"), Checks: []byte(checks)}, "v")
		if err == nil || !strings.Contains(err.Error(), "got ambiguous_call") {
			t.Errorf("expecting %s: got %v", expect, err)
		}
	}
}

func TestFoldNameMatchesEqualFold(t *testing.T) {
	names := []string{"k", "K", "K", "s", "S", "ſ", "environment", "ENVIRONMENT", "Environment", "env", "ǅ", "ǆ", "Ǆ", "σ", "ς", "Σ", "ß", "ẞ", "i", "İ", "ı"}
	for _, a := range names {
		for _, b := range names {
			if (foldName(a) == foldName(b)) != strings.EqualFold(a, b) {
				t.Errorf("%q and %q: folded %q and %q, EqualFold %v", a, b, foldName(a), foldName(b), strings.EqualFold(a, b))
			}
		}
	}
}

// A name matching two declared arguments under case folding is ambiguous
// even when it spells one of them exactly.
func TestCaseEquivalentDeclarations(t *testing.T) {
	tools := `{"p": {"upstream": "https://u.example/mcp", "tools": {"t": {"arguments": {"id": "string", "Id": "string", "other": "string"}}}}}`
	rules := `permit (principal, action, resource) when { !context.strings.contains({name: "Id", value: "secret"}) };`
	s, err := Compile(Inputs{Rules: []byte(rules), Tools: []byte(tools), Instructions: []byte("{}"), Checks: []byte("[]")}, "v")
	if err != nil {
		t.Fatal(err)
	}
	for args, want := range map[string]string{
		`{"other": "x"}`:   "permitted",
		`{"id": "secret"}`: "ambiguous_call",
		`{"Id": "secret"}`: "ambiguous_call",
		`{"ID": "secret"}`: "ambiguous_call",
	} {
		if got, _ := s.Decide(Caller{Issuer: "i", Subject: "s"}, "p", "https://u.example/mcp", "t", []byte(args)); got != want {
			t.Errorf("%s: got %s, want %s", args, got, want)
		}
	}
}

// Drift review turns a check of an unapproved tool into the denial it
// expects, but never one whose arguments are ambiguous.
func TestDriftReviewKeepsAmbiguousChecksFailing(t *testing.T) {
	tools := `{"governed": {"upstream": "https://u.example/mcp", "drift": {}, "tools": {"lookup": {}}}}`
	checks := `[{"caller": {"issuer": "i", "subject": "s"}, "proxy": "governed", "upstream": "https://u.example/mcp", "tool": "lookup",
  "arguments": {"note": "a", "NOTE": "b"}, "expect": "policy_denied"}]`
	_, err := Compile(Inputs{Rules: []byte(`permit (principal, action, resource);`), Tools: []byte(tools), Instructions: []byte("{}"), Checks: []byte(checks)}, "v")
	if err == nil || !strings.Contains(err.Error(), "got ambiguous_call") {
		t.Fatalf("got %v", err)
	}
}
