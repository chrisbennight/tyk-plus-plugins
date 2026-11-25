package policy

import (
	"strings"
	"testing"
)

func TestDecideBuiltIn(t *testing.T) {
	rules := `
@id("code-mode") permit (principal, action, resource) when { principal.roles.contains("coder") && resource.name == "codemode.execute" };
@id("read-only") permit (principal, action, resource) when { resource.reviewed.flags.contains({name: "readOnly", value: true}) };
@id("blocked") forbid (principal, action, resource) when { principal.roles.contains("blocked") };
`
	tools := `{"p": {"upstream": "https://u.example/mcp", "tools": {"lookup": {"facts": {"readOnly": true}}}}}`
	s, err := Compile(Inputs{Rules: []byte(rules), Tools: []byte(tools), Instructions: []byte("{}"), Checks: []byte("[]")}, "v")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		roles []string
		proxy string
		want  string
	}{
		{[]string{"coder"}, "p", "permitted"},
		// A proxy the set does not review still decides by the rules alone.
		{[]string{"coder"}, "other", "permitted"},
		{[]string{"reader"}, "p", "policy_denied"},
		{[]string{"coder", "blocked"}, "p", "policy_denied"},
	} {
		got, _ := s.DecideBuiltIn(Caller{Issuer: "i", Subject: "s", Roles: c.roles}, c.proxy, "https://u.example/mcp", "codemode.execute")
		if got != c.want {
			t.Errorf("roles %v on %s: got %s, want %s", c.roles, c.proxy, got, c.want)
		}
	}
	// A permit for reviewed read-only tools does not reach a built-in tool,
	// which has no reviewed facts.
	if got, _ := s.DecideBuiltIn(Caller{Issuer: "i", Subject: "s"}, "p", "https://u.example/mcp", "codemode.execute"); got != "policy_denied" {
		t.Errorf("a reviewed-fact permit granted a built-in tool: %s", got)
	}
}

func TestApprovedTools(t *testing.T) {
	tools := `{"p": {"upstream": "https://u.example/mcp", "tools": {
  "zeta": {"facts": {"readOnly": true}},
  "alpha": {"definition": {"name": "alpha", "description": "A"}}}}}`
	s, err := Compile(Inputs{Rules: []byte(""), Tools: []byte(tools), Instructions: []byte("{}"), Checks: []byte("[]")}, "v")
	if err != nil {
		t.Fatal(err)
	}
	upstream, list := s.ApprovedTools("p")
	if upstream != "https://u.example/mcp" || len(list) != 2 || list[0].Name != "alpha" || list[1].Name != "zeta" ||
		!strings.Contains(string(list[0].Definition), `"description"`) || list[1].Definition != nil {
		t.Fatalf("approved tools %q %+v", upstream, list)
	}
	if _, none := s.ApprovedTools("other"); none != nil {
		t.Fatalf("an unknown proxy has tools: %+v", none)
	}
}
