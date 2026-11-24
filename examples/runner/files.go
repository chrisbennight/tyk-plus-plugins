package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	RefusedCallers    []string `json:"refusedCallers"`
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
	for i, c := range e.expected.Calls {
		if c.Expect != "permitted" && c.Expect != "refused" {
			return nil, fmt.Errorf("expected.json call %d: expect must be permitted or refused", i)
		}
		if _, err := e.identity(c.Caller); err != nil {
			return nil, fmt.Errorf("expected.json call %d: %w", i, err)
		}
	}
	return &e, nil
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
