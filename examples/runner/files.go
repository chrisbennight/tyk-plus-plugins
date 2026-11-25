package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// expectations is expected.json: what an equivalent gateway must do for each
// example caller. It names callers, servers and tools only, so it can describe
// another gateway under an equivalent policy.
type expectations struct {
	// OlderProtocolOnly lists servers that speak only the older protocol
	// version; every other server must be reached with the version the
	// client asks for.
	OlderProtocolOnly []string `json:"olderProtocolOnly"`
	Calls             []call   `json:"calls"`
	// Listed gives, for each caller and server, the tools the caller's
	// tools/list shows: every approved tool it could call with some
	// arguments, and no other.
	Listed         map[string]map[string][]string `json:"listed"`
	RefusedCallers []string                       `json:"refusedCallers"`
	// Drift walks a server through changes to what it declares.
	Drift *driftWalk `json:"drift"`
	// KeyAndToken lists requests carrying both a key and a token. The key
	// identifies the caller, so each expectation follows the key's access.
	KeyAndToken []struct {
		Key       string         `json:"key"`
		Token     string         `json:"token"`
		Server    string         `json:"server"`
		Tool      string         `json:"tool"`
		Arguments map[string]any `json:"arguments"`
		Expect    string         `json:"expect"`
		Why       string         `json:"why"`
	} `json:"keyAndToken"`
}

// driftWalk is what a caller should see while a server changes what it
// declares. Every step switches the server to a version through its control
// path, outside MCP, and states what the caller then sees.
type driftWalk struct {
	Server string `json:"server"`
	Caller string `json:"caller"`
	// Instructions are the approved instructions, which the caller must be
	// given at every step, whatever the server sends.
	Instructions string `json:"instructions"`
	// Arguments are the arguments each tool is called with.
	Arguments map[string]map[string]any `json:"arguments"`
	Steps     []driftStep               `json:"steps"`
}

type driftStep struct {
	Version int    `json:"version"`
	Why     string `json:"why"`
	// Listed is every tool the caller is shown. Permitted tools must work,
	// and refused ones must be refused without reaching the server.
	Listed    []string `json:"listed"`
	Permitted []string `json:"permitted"`
	Refused   []string `json:"refused"`
}

type call struct {
	Caller    string         `json:"caller"`
	Server    string         `json:"server"`
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
	Expect    string         `json:"expect"`
	Why       string         `json:"why"`
}

// deck is the issuer's list of example people, callers/people.json.
type deck struct {
	Issuer          string                    `json:"issuer"`
	Audience        string                    `json:"audience"`
	LifetimeSeconds int64                     `json:"lifetimeSeconds"`
	People          map[string]map[string]any `json:"people"`
}

// identity is a caller as the policy sees it.
type identity struct {
	Issuer  string   `json:"issuer"`
	Subject string   `json:"subject"`
	Roles   []string `json:"roles,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Scopes  []string `json:"scopes,omitempty"`
}

// approvedTools is the part of policy/approved_tools.json the runner reads.
type approvedTools map[string]struct {
	Upstream string `json:"upstream"`
	Tools    map[string]struct {
		Arguments map[string]string `json:"arguments"`
		// Definition is the approved definition. On a proxy under drift
		// review, a tool without one is never listed or called.
		Definition json.RawMessage `json:"definition"`
	} `json:"tools"`
}

type examples struct {
	expected expectations
	deck     deck
	keys     map[string]identity
	tools    approvedTools
	// committedChecks is policy/checks.json as committed.
	committedChecks []byte
}

func load(dir string) (*examples, error) {
	var e examples
	for _, f := range []struct {
		path string
		into any
	}{
		{"expected.json", &e.expected},
		{"callers/people.json", &e.deck},
		{"callers/keys.json", &e.keys},
		{"policy/approved_tools.json", &e.tools},
	} {
		data, err := os.ReadFile(filepath.Join(dir, f.path))
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(f.into); err != nil {
			return nil, fmt.Errorf("%s: %w", f.path, err)
		}
	}
	var err error
	if e.committedChecks, err = os.ReadFile(filepath.Join(dir, "policy/checks.json")); err != nil {
		return nil, err
	}
	// Caller names become shell variable names in "runner env", so they must
	// stay within the issuer's own rule for names.
	for name := range e.deck.People {
		if !callerName.MatchString(name) {
			return nil, fmt.Errorf("callers/people.json: %q is not a valid caller name", name)
		}
	}
	for name := range e.keys {
		if !callerName.MatchString(name) {
			return nil, fmt.Errorf("callers/keys.json: %q is not a valid caller name", name)
		}
	}
	for i, k := range e.expected.KeyAndToken {
		if k.Expect != "permitted" && k.Expect != "refused" {
			return nil, fmt.Errorf("expected.json keyAndToken %d: expect must be permitted or refused", i)
		}
		if k.Expect == "permitted" && !e.approved(k.Server, k.Tool, k.Arguments) {
			return nil, fmt.Errorf("expected.json keyAndToken %d expects %s.%s to be permitted, but that tool or its arguments are not approved", i, k.Server, k.Tool)
		}
	}
	for i, c := range e.expected.Calls {
		if c.Expect != "permitted" && c.Expect != "refused" {
			return nil, fmt.Errorf("expected.json call %d: expect must be permitted or refused", i)
		}
		if _, err := e.identity(c.Caller); err != nil {
			return nil, fmt.Errorf("expected.json call %d: %w", i, err)
		}
	}
	if err := e.checkListed(); err != nil {
		return nil, err
	}
	if err := e.checkDrift(); err != nil {
		return nil, err
	}
	return &e, nil
}

// checkDrift reports an error when the drift walk names an unknown caller or
// proxy, expects an unapproved tool to be listed or to work, or calls a tool
// it gives no arguments for.
func (e *examples) checkDrift() error {
	d := e.expected.Drift
	if d == nil {
		return nil
	}
	if _, err := e.identity(d.Caller); err != nil {
		return fmt.Errorf("expected.json drift: %w", err)
	}
	inv, ok := e.tools[d.Server]
	if !ok {
		return fmt.Errorf("expected.json drift: there is no proxy named %q", d.Server)
	}
	for i, step := range d.Steps {
		for _, tool := range append(slices.Clone(step.Listed), step.Permitted...) {
			if t, approved := inv.Tools[tool]; !approved || len(t.Definition) == 0 {
				return fmt.Errorf("expected.json drift step %d: %s.%s is expected to be listed or to work, but it has no approved definition", i, d.Server, tool)
			}
		}
		for _, tool := range append(slices.Clone(step.Permitted), step.Refused...) {
			if _, ok := d.Arguments[tool]; !ok {
				return fmt.Errorf("expected.json drift step %d: no arguments for %s", i, tool)
			}
		}
	}
	return nil
}

// checkListed reports an error when expected.json's listed tools leave out a
// caller that calls uses or a proxy for a caller they name, so no check is
// dropped by deleting a row; or when they name an unknown caller or proxy, or
// a tool without an approved definition, which is never listed.
func (e *examples) checkListed() error {
	for _, c := range e.expected.Calls {
		if _, ok := e.expected.Listed[c.Caller]; !ok {
			return fmt.Errorf("expected.json listed: %s makes calls but its tool list is not given", c.Caller)
		}
	}
	for caller, servers := range e.expected.Listed {
		if _, err := e.identity(caller); err != nil {
			return fmt.Errorf("expected.json listed: %w", err)
		}
		for server := range e.tools {
			if _, ok := servers[server]; !ok {
				return fmt.Errorf("expected.json listed: %s's tool list on %s is not given", caller, server)
			}
		}
		for server, tools := range servers {
			inv, ok := e.tools[server]
			if !ok {
				return fmt.Errorf("expected.json listed: there is no proxy named %q", server)
			}
			for _, tool := range tools {
				if t, approved := inv.Tools[tool]; !approved || len(t.Definition) == 0 {
					return fmt.Errorf("expected.json listed: %s should see %s.%s, but that tool has no approved definition", caller, server, tool)
				}
			}
		}
	}
	return nil
}

// callerName is the issuer's rule for a person's name, applied to every caller.
var callerName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// approved reports whether the policy evaluates a call to tool on server with
// these arguments: the tool is approved and its arguments have their declared types.
func (e *examples) approved(server, tool string, args map[string]any) bool {
	inv, ok := e.tools[server]
	t, approved := inv.Tools[tool]
	return ok && approved && argumentsMatch(t.Arguments, args)
}

// identity returns how the policy sees a named caller: a person from the deck
// presenting a token, or a service presenting a key.
func (e *examples) identity(name string) (identity, error) {
	if id, ok := e.keys[name]; ok {
		return id, nil
	}
	claims, ok := e.deck.People[name]
	if !ok {
		return identity{}, fmt.Errorf("no caller named %q in callers/people.json or callers/keys.json", name)
	}
	id := identity{Issuer: e.deck.Issuer, Subject: name}
	if sub, ok := claims["sub"].(string); ok {
		id.Subject = sub
	}
	id.Roles, id.Groups, id.Scopes = list(claims["roles"]), list(claims["groups"]), list(claims["scope"])
	return id, nil
}

// list reads a claim that is a list of strings or one space-separated string,
// the two shapes the gateway accepts.
func list(claim any) []string {
	switch v := claim.(type) {
	case string:
		return strings.Fields(v)
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (e *examples) isKey(name string) bool {
	_, ok := e.keys[name]
	return ok
}
