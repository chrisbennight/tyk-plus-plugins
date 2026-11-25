package policy

import "testing"

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
