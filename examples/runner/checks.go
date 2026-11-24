package main

import (
	"bytes"
	"encoding/json"
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

// checks derives the policy set's activation checks from expected.json, so the
// policy cannot be published while it disagrees with the expected outcomes.
// Calls the policy never evaluates are left out: tools that were never
// approved, and arguments of the wrong type, which the gateway refuses first.
func (e *examples) checks() ([]byte, error) {
	out := []activationCheck{}
	for _, c := range e.expected.Calls {
		inv, ok := e.tools[c.Server]
		if !ok {
			continue
		}
		t, ok := inv.Tools[c.Tool]
		if !ok || !argumentsMatch(t.Arguments, c.Arguments) {
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
		out = append(out, activationCheck{Caller: id, Proxy: c.Server, Upstream: inv.Upstream, Tool: c.Tool, Arguments: c.Arguments, Expect: expect})
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
