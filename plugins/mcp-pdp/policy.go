package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
	jsonv2 "github.com/go-json-experiment/json"
)

//go:embed schema.cedarschema
var inputSchema []byte

// The native upstream definition may include MCP fields outside the Cedar schema.
type toolDefinition struct {
	Name        string                     `json:"name"`
	Annotations map[string]json.RawMessage `json:"annotations"`
	facts       cedar.RecordMap
}

func (d *toolDefinition) UnmarshalJSON(data []byte) error {
	type wire toolDefinition
	if err := jsonv2.Unmarshal(data, (*wire)(d)); err != nil {
		return err
	}
	values := scalarFacts{}
	for name, raw := range d.Annotations {
		switch raw[0] {
		case '"':
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return err
			}
			values.add("string", name, cedar.String(value))
		case 't', 'f':
			values.add("boolean", name, cedar.Boolean(raw[0] == 't'))
		default:
			var value int64
			if raw[0] != 'n' && json.Unmarshal(raw, &value) == nil {
				values.add("long", name, cedar.Long(value))
			}
		}
	}
	d.facts = values.fields()
	if raw, ok := d.Annotations["readOnlyHint"]; ok {
		var hint *bool
		if err := json.Unmarshal(raw, &hint); err != nil {
			return err
		}
		if hint != nil {
			d.facts["readOnlyHint"] = cedar.Boolean(*hint)
		}
	}
	return nil
}

// Operators choose the names of reviewed facts and tags. The plug-in gives
// no name a meaning; only the operator's rules do.
type tool struct {
	Facts      map[string]json.RawMessage `json:"facts"`
	Tags       []string                   `json:"tags"`
	Definition *toolDefinition            `json:"definition"`
	Arguments  map[string]string          `json:"arguments"`
	reviewed   cedar.Record
}

func (t *tool) prepare(name string) error {
	if t.Definition != nil && t.Definition.Name != name {
		return fmt.Errorf("upstream definition name differs from reviewed tool %q", name)
	}
	for _, kind := range t.Arguments {
		switch kind {
		case "string", "long", "boolean":
		default:
			return fmt.Errorf("unsupported argument type %q", kind)
		}
	}
	values := scalarFacts{}
	for fact, raw := range t.Facts {
		switch raw[0] {
		case '"':
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return err
			}
			values.add("string", fact, cedar.String(value))
		case 't', 'f':
			values.add("boolean", fact, cedar.Boolean(raw[0] == 't'))
		default:
			var value *int64
			if json.Unmarshal(raw, &value) != nil || value == nil {
				return fmt.Errorf("fact %q on tool %q must be a string, boolean, or signed 64-bit integer", fact, name)
			}
			values.add("long", fact, cedar.Long(*value))
		}
	}
	fields := values.fields()
	if slices.Contains(t.Tags, "") {
		return fmt.Errorf("tool %q has an empty tag", name)
	}
	fields["tags"] = stringsSet(t.Tags)
	t.reviewed = cedar.NewRecord(fields)
	return nil
}

type inventory struct {
	Upstream string           `json:"upstream"`
	Tools    map[string]*tool `json:"tools"`
}

type snapshot struct {
	version  string
	policies *cedar.PolicySet
	tools    map[string]inventory
}

func compile(rules, inventoryData, checks []byte, version string) (*snapshot, error) {
	var schemaDoc schema.Schema
	if err := schemaDoc.UnmarshalCedar(inputSchema); err != nil {
		return nil, err
	}
	resolved, err := schemaDoc.Resolve()
	if err != nil {
		return nil, err
	}
	validator := validate.New(resolved)
	list, err := cedar.NewPolicyListFromBytes("rules.cedar", rules)
	if err != nil {
		return nil, err
	}
	s := &snapshot{version: version, policies: cedar.NewPolicySet()}
	for i, p := range list {
		id := cedar.PolicyID(p.Annotations()["id"])
		if id == "" {
			id = cedar.PolicyID(fmt.Sprintf("policy%d", i))
		}
		if err := validator.Policy(string(id), (*ast.Policy)(p.AST())); err != nil {
			return nil, err
		}
		if !s.policies.Add(id, p) {
			return nil, fmt.Errorf("duplicate policy ID %s", id)
		}
	}
	if err := jsonv2.Unmarshal(inventoryData, &s.tools, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if s.tools == nil {
		return nil, fmt.Errorf("tool inventory must be an object")
	}
	for proxy, inv := range s.tools {
		if proxy == "" || inv.Upstream == "" || inv.Tools == nil {
			return nil, fmt.Errorf("invalid inventory for proxy %q", proxy)
		}
		for name, t := range inv.Tools {
			if name == "" || t == nil {
				return nil, fmt.Errorf("tool %q for proxy %q must be a named object", name, proxy)
			}
			if err := t.prepare(name); err != nil {
				return nil, err
			}
		}
	}
	// Activation checks are optional. An operator adds them to test a candidate's
	// decisions before it can replace the last good configuration.
	var cases []struct {
		Caller           caller          `json:"caller"`
		Proxy            string          `json:"proxy"`
		Upstream         string          `json:"upstream"`
		Tool             string          `json:"tool"`
		Arguments        json.RawMessage `json:"arguments"`
		HypotheticalTool *tool           `json:"hypotheticalTool"`
		Expect           string          `json:"expect"`
	}
	if err := jsonv2.Unmarshal(checks, &cases, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if cases == nil {
		return nil, fmt.Errorf("activation checks must be an array")
	}
	for i, c := range cases {
		if c.Caller.Issuer == "" || c.Caller.Subject == "" || c.Proxy == "" || c.Tool == "" || c.Upstream == "" {
			return nil, fmt.Errorf("incomplete activation check %d", i)
		}
		switch c.Expect {
		case "permitted", "policy_denied":
		default:
			return nil, fmt.Errorf("invalid expected outcome in activation check %d", i)
		}
		candidate := s
		if h := c.HypotheticalTool; h != nil {
			if err := h.prepare(c.Tool); err != nil {
				return nil, fmt.Errorf("activation check %d: %w", i, err)
			}
			// A hypothetical reviewed tool exercises the policies without publishing a tool.
			candidate = &snapshot{policies: s.policies, tools: map[string]inventory{
				c.Proxy: {Upstream: c.Upstream, Tools: map[string]*tool{c.Tool: h}},
			}}
		}
		reason, _ := candidate.decide(c.Caller, c.Proxy, c.Upstream, c.Tool, c.Arguments)
		if reason != c.Expect {
			return nil, fmt.Errorf("activation check %d expected %s, got %s", i, c.Expect, reason)
		}
	}
	return s, nil
}

// active holds the configuration tool calls are decided against. Calls read it
// without locking or touching the filesystem; only the refresh loop replaces it.
var active atomic.Pointer[snapshot]

// The default interval keeps a promoted change visible within seconds while
// reading the configuration rarely.
const defaultRefreshInterval = 5 * time.Second

// current returns the active configuration without blocking.
func current() *snapshot {
	return active.Load()
}

// The gateway loads the plug-in before it serves traffic, so the first
// configuration is loaded and the refresh loop started before any tool call.
func init() {
	interval := defaultRefreshInterval
	if value := os.Getenv("CEDAR_REFRESH_INTERVAL"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 {
			slog.Error("Invalid CEDAR_REFRESH_INTERVAL; using the default", "value", value, "default", interval.String())
		} else {
			interval = parsed
		}
	}
	var r reloader
	r.load()
	go func() {
		for range time.Tick(interval) {
			r.load()
		}
	}()
}

// reloader is owned by the refresh loop, so its state needs no lock.
type reloader struct {
	version string
}

// load validates a changed configuration and activates it only if it passes.
// A rejected or unreadable configuration leaves the last good one active. A
// panic during validation is contained here so the gateway keeps serving.
func (r *reloader) load() {
	defer func() {
		if failure := recover(); failure != nil {
			slog.Error("Cedar configuration refresh failed", "panic", fmt.Sprint(failure))
		}
	}()
	dir := "/opt/tyk-gateway/cedar"
	rules, e1 := os.ReadFile(filepath.Join(dir, "rules.cedar"))
	tools, e2 := os.ReadFile(filepath.Join(dir, "tools.json"))
	checks, e3 := os.ReadFile(filepath.Join(dir, "checks.json"))
	if e1 != nil || e2 != nil || e3 != nil {
		if r.version != "unreadable" {
			slog.Warn("Cedar configuration unreadable", "rules", e1, "tools", e2, "checks", e3)
			r.version = "unreadable"
		}
		return
	}
	version := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%x%x%x", sha256.Sum256(rules), sha256.Sum256(tools), sha256.Sum256(checks)))))
	if version == r.version {
		return
	}
	r.version = version
	next, err := compile(rules, tools, checks, version)
	if err != nil {
		slog.Warn("Cedar configuration rejected", "candidate", version, "error", err.Error())
		return
	}
	active.Store(next)
	slog.Info("Cedar configuration activated", "version", version)
}
