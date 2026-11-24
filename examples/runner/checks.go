package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// activationCheck is one entry of the policy set's checks.json.
type activationCheck struct {
	Caller    identity       `json:"caller"`
	Proxy     string         `json:"proxy"`
	Upstream  string         `json:"upstream"`
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Expect    string         `json:"expect"`
}

// checks derives the policy set's activation checks from expected.json. The
// runner refuses to run while the committed checks differ from these, so the
// checks the gateway enforces at publication always match the expected outcomes.
// Calls the policy never evaluates are left out: tools that were never
// approved, and arguments of the wrong type, which the gateway refuses first.
func (e *examples) checks() ([]byte, error) {
	out := []activationCheck{}
	for _, c := range e.expected.Calls {
		if !e.approved(c.Server, c.Tool, c.Arguments) {
			// The gateway refuses these before the policy sees them, so a row
			// expecting them to be permitted contradicts the approved tools.
			if c.Expect == "permitted" {
				return nil, fmt.Errorf("expected.json expects %s to call %s.%s, but that tool or its arguments are not approved", c.Caller, c.Server, c.Tool)
			}
			continue
		}
		id, err := e.identity(c.Caller)
		if err != nil {
			return nil, err
		}
		expect := "permitted"
		if c.Expect == "refused" {
			expect = "policy_denied"
		}
		out = append(out, activationCheck{Caller: id, Proxy: c.Server, Upstream: e.tools[c.Server].Upstream, Tool: c.Tool, Arguments: c.Arguments, Expect: expect})
	}
	// A request carrying a key and a token is decided as the key's caller, so
	// those rows are checked under the key's identity.
	for _, k := range e.expected.KeyAndToken {
		if !e.approved(k.Server, k.Tool, k.Arguments) {
			continue
		}
		id, err := e.identity(k.Key)
		if err != nil {
			return nil, err
		}
		expect := "permitted"
		if k.Expect == "refused" {
			expect = "policy_denied"
		}
		out = append(out, activationCheck{Caller: id, Proxy: k.Server, Upstream: e.tools[k.Server].Upstream, Tool: k.Tool, Arguments: k.Arguments, Expect: expect})
	}
	var buf bytes.Buffer
	buf.WriteString("[\n")
	for i, c := range out {
		line, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		buf.WriteString("  ")
		buf.Write(line)
		if i < len(out)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("]\n")
	return buf.Bytes(), nil
}

// argumentsMatch reports whether every argument the policy reads has the type
// the approved tool declares for it.
func argumentsMatch(declared map[string]string, args map[string]any) bool {
	for name, kind := range declared {
		v, present := args[name]
		if !present {
			continue
		}
		switch kind {
		case "string":
			if _, ok := v.(string); !ok {
				return false
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				return false
			}
		case "long":
			n, ok := v.(json.Number)
			if !ok {
				return false
			}
			if _, err := n.Int64(); err != nil {
				return false
			}
		}
	}
	return true
}

// checksCurrent reports an error when policy/checks.json differs from the
// checks expected.json generates.
func (e *examples) checksCurrent() error {
	want, err := e.checks()
	if err != nil {
		return err
	}
	if !bytes.Equal(e.committedChecks, want) {
		return fmt.Errorf("policy/checks.json does not match expected.json; regenerate it as examples/README.md describes")
	}
	return nil
}
