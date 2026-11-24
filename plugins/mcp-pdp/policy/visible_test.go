package policy

import (
	"fmt"
	"sync"
	"testing"
)

const visibilityTools = `{"p": {"upstream": "https://u.example/mcp", "tools": {
  "lookup": {"facts": {"readOnly": true, "risk": "low"}, "arguments": {"count": "long"}},
  "change": {"facts": {"readOnly": false, "risk": "high"}, "arguments": {"count": "long"}},
  "hinted": {"definition": {"name": "hinted", "annotations": {"readOnlyHint": true}}},
  "report": {"facts": {"risk": "low"}, "arguments": {"count": "long"}},
  "plain": {"facts": {"risk": "low"}},
  "ordered": {"facts": {"risk": "low"}, "arguments": {"count": "long"}},
  "split": {"facts": {"risk": "low"}, "arguments": {"count": "long"}},
  "excepted": {"facts": {"risk": "low"}, "arguments": {"count": "long"}},
  "branched": {"facts": {"risk": "low"}, "arguments": {"count": "long"}},
  "forbidden": {"facts": {"risk": "low"}, "arguments": {"count": "long"}}}}}`

const visibilityRules = `
@id("support-read") permit (principal, action, resource) when { principal.roles.contains("support") && resource.reviewed.flags.contains({name: "readOnly", value: true}) };
@id("guest-count") permit (principal, action, resource) when { principal.roles.contains("guest") && resource.name == "change" && context.numbers.contains({name: "count", value: 3}) };
@id("anyone-count") permit (principal, action, resource) when { resource.name == "lookup" && context.numbers.contains({name: "count", value: 7}) };
@id("high-risk") forbid (principal, action, resource) when { resource.reviewed.strings.contains({name: "risk", value: "high"}) && !principal.roles.contains("operator") && !principal.roles.contains("guest") && !principal.roles.contains("auditor") };
@id("count-forbid") forbid (principal, action, resource) when { context.numbers.contains({name: "count", value: 9}) };
@id("hint-only") permit (principal, action, resource) when { principal.roles.contains("hinter") && resource.upstreamAnnotations has readOnlyHint && resource.upstreamAnnotations.readOnlyHint };
@id("unless-arg") permit (principal, action, resource) when { principal.roles.contains("auditor") && resource.name == "change" } unless { context.numbers.contains({name: "count", value: 1}) };
@id("guest-report") permit (principal, action, resource) when { principal.roles.contains("guest") && resource.name == "report" && context.numbers.contains({name: "count", value: 3}) };
@id("plain-count") permit (principal, action, resource) when { resource.name == "plain" && context.numbers.contains({name: "count", value: 3}) };
@id("context-first") permit (principal, action, resource) when { context.numbers.contains({name: "count", value: 3}) && principal.roles.contains("guest") && resource.name == "ordered" };
@id("two-clauses") permit (principal, action, resource) when { principal.roles.contains("guest") && resource.name == "split" } when { context.numbers.contains({name: "count", value: 3}) };
@id("unless-role") permit (principal, action, resource) when { resource.name == "excepted" } unless { context.numbers.contains({name: "count", value: 1}) || !principal.roles.contains("guest") };
@id("if-role") permit (principal, action, resource) when { resource.name == "branched" && (if principal.roles.contains("operator") then context.numbers.contains({name: "count", value: 3}) else false) };
@id("open-forbidden") permit (principal, action, resource) when { resource.name == "forbidden" };
@id("forbid-unless-arg") forbid (principal, action, resource) when { resource.name == "forbidden" } unless { context.numbers.contains({name: "count", value: 5}) };
@id("blocked") forbid (principal, action, resource) when { principal.roles.contains("blocked") };
@id("blocked-read") permit (principal, action, resource) when { principal.roles.contains("blocked") && resource.name == "lookup" };
`

func visibilitySnapshot(t *testing.T) *Snapshot {
	t.Helper()
	s, err := Compile(Inputs{Rules: []byte(visibilityRules), Tools: []byte(visibilityTools), Instructions: []byte("{}"), Checks: []byte("[]")}, "v")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var visibilityCases = []struct {
	role, tool string
	want       bool
	why        string
}{
	{"support", "lookup", true, "plain grant"},
	{"support", "change", false, "no permit and a high-risk forbid"},
	{"guest", "change", true, "permit needs count=3, which some call could supply"},
	{"nobody", "change", false, "guest-only permit with an argument condition must not leak to others"},
	{"nobody", "lookup", true, "anyone may call lookup with count=7"},
	{"operator", "change", false, "operator has no permit at all"},
	{"hinter", "hinted", false, "an upstream hint alone cannot grant"},
	{"auditor", "change", true, "permit with an argument exception"},
	{"blocked", "lookup", false, "a forbid with no argument condition overrides the permit"},
	{"guest", "report", true, "a guest-only permit with an argument condition"},
	{"nobody", "report", false, "only the role condition hides it: a guest-only permit must not leak"},
	{"support", "plain", false, "a tool without declared arguments is called with no argument facts"},
	{"guest", "ordered", true, "the argument condition comes first"},
	{"nobody", "ordered", false, "an argument condition written first must not leak a guest-only permit"},
	{"guest", "split", true, "role and argument conditions in separate clauses"},
	{"nobody", "split", false, "a separate argument clause must not leak a guest-only permit"},
	{"guest", "excepted", true, "a role restriction inside an unless clause that also tests arguments"},
	{"nobody", "excepted", false, "an unless clause mixing arguments and roles must not leak"},
	{"operator", "branched", true, "a role test in the condition of an if, with an argument test in its branch"},
	{"nobody", "branched", false, "a role test in the condition of an if must not leak"},
	{"nobody", "forbidden", true, "a forbid that some arguments avoid does not hide the tool"},
}

func TestVisibilityPrecision(t *testing.T) {
	s := visibilitySnapshot(t)
	for _, c := range visibilityCases {
		who := Caller{Issuer: "i", Subject: c.role, Roles: []string{c.role}}
		if got := s.Visible(who, "p", c.tool); got != c.want {
			t.Errorf("%s calling %s: visible=%v, want %v (%s)", c.role, c.tool, got, c.want, c.why)
		}
		if got := s.VisibleTools(who, "p", DefaultVisibilityBatchThreshold)[c.tool]; got != c.want {
			t.Errorf("%s calling %s: listed=%v, want %v (%s)", c.role, c.tool, got, c.want, c.why)
		}
	}
}

func TestBatchVisibilityNeverHidesUsableTools(t *testing.T) {
	s := visibilitySnapshot(t)
	for _, c := range visibilityCases {
		who := Caller{Issuer: "i", Subject: c.role, Roles: []string{c.role}}
		// A threshold of zero checks every proxy in one batch.
		if c.want && !s.VisibleTools(who, "p", 0)[c.tool] {
			t.Errorf("%s calling %s: the batch check hid a usable tool (%s)", c.role, c.tool, c.why)
		}
	}
	// The batch check may show extra tools, but a permit limited to one role
	// never reveals a tool to other callers, and tools without declared
	// arguments are decided exactly.
	nobody := s.VisibleTools(Caller{Issuer: "i", Subject: "nobody", Roles: []string{"nobody"}}, "p", 0)
	for _, tool := range []string{"report", "ordered", "split", "excepted", "branched"} {
		if nobody[tool] {
			t.Errorf("the batch check revealed the role-limited tool %s to another caller", tool)
		}
	}
	if s.VisibleTools(Caller{Issuer: "i", Subject: "support", Roles: []string{"support"}}, "p", 0)["plain"] {
		t.Error("the batch check showed a tool without arguments that no call can use")
	}
}

func TestVisibilityIsCachedPerCallerFacts(t *testing.T) {
	s := visibilitySnapshot(t)
	// The same subject with different roles must not share a result.
	support := s.VisibleTools(Caller{Issuer: "i", Subject: "x", Roles: []string{"support"}}, "p", DefaultVisibilityBatchThreshold)
	guest := s.VisibleTools(Caller{Issuer: "i", Subject: "x", Roles: []string{"guest"}}, "p", DefaultVisibilityBatchThreshold)
	if support["change"] || !guest["change"] {
		t.Fatalf("support %v, guest %v", support, guest)
	}
	// Role order does not matter.
	if visibilityKey(Caller{Roles: []string{"a", "b"}}, "p") != visibilityKey(Caller{Roles: []string{"b", "a"}}, "p") {
		t.Fatal("role order changed the cache key")
	}
	// An unknown proxy shows nothing.
	if len(s.VisibleTools(Caller{Issuer: "i", Subject: "x"}, "other", DefaultVisibilityBatchThreshold)) != 0 {
		t.Fatal("tools shown on an unknown proxy")
	}
}

func TestVisibilityIsSafeToCheckConcurrently(t *testing.T) {
	s := visibilitySnapshot(t)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 50 {
				role := visibilityCases[(i+j)%len(visibilityCases)]
				who := Caller{Issuer: "i", Subject: fmt.Sprint(j % 5), Roles: []string{role.role}}
				if got := s.VisibleTools(who, "p", DefaultVisibilityBatchThreshold)[role.tool]; got != role.want {
					t.Errorf("%s calling %s: listed=%v", role.role, role.tool, got)
				}
			}
		}()
	}
	wg.Wait()
}
