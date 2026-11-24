package policy

import (
	"fmt"
	"sync"
	"testing"
)

const visibilityTools = `{"p": {"upstream": "https://u.example/mcp", "tools": {
  "lookup": {"facts": {"readOnly": true, "risk": "low"}, "arguments": {"count": "long"}},
  "change": {"facts": {"readOnly": false, "risk": "high"}, "arguments": {"count": "long"}},
  "hinted": {"definition": {"name": "hinted", "annotations": {"readOnlyHint": true}}}}}}`

const visibilityRules = `
@id("support-read") permit (principal, action, resource) when { principal.roles.contains("support") && resource.reviewed.flags.contains({name: "readOnly", value: true}) };
@id("guest-count") permit (principal, action, resource) when { principal.roles.contains("guest") && resource.name == "change" && context.numbers.contains({name: "count", value: 3}) };
@id("anyone-count") permit (principal, action, resource) when { resource.name == "lookup" && context.numbers.contains({name: "count", value: 7}) };
@id("high-risk") forbid (principal, action, resource) when { resource.reviewed.strings.contains({name: "risk", value: "high"}) && !principal.roles.contains("operator") && !principal.roles.contains("guest") && !principal.roles.contains("auditor") };
@id("count-forbid") forbid (principal, action, resource) when { context.numbers.contains({name: "count", value: 9}) };
@id("hint-only") permit (principal, action, resource) when { principal.roles.contains("hinter") && resource.upstreamAnnotations has readOnlyHint && resource.upstreamAnnotations.readOnlyHint };
@id("unless-arg") permit (principal, action, resource) when { principal.roles.contains("auditor") && resource.name == "change" } unless { context.numbers.contains({name: "count", value: 1}) };
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
