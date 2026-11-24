package policy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

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
	// raw is the definition as published, kept to fingerprint it.
	raw []byte
	// fingerprint identifies the exact definition the operator approved.
	fingerprint string
}

func (d *toolDefinition) UnmarshalJSON(data []byte) error {
	type wire toolDefinition
	if err := jsonv2.Unmarshal(data, (*wire)(d)); err != nil {
		return err
	}
	d.raw = append([]byte(nil), data...)
	facts, err := annotationFacts(d.Annotations)
	if err != nil {
		return err
	}
	d.facts = facts
	return nil
}

// annotationFacts turns upstream annotations into the facts rules read, from
// each value as written: only an integer spelling is an integer fact, and
// JSON null is never a fact. A definition's fingerprint keeps numbers as
// written too, so a different spelling is a reviewed change.
func annotationFacts(annotations map[string]json.RawMessage) (cedar.RecordMap, error) {
	values := scalarFacts{}
	readOnly := json.RawMessage(nil)
	for name, raw := range annotations {
		if name == "readOnlyHint" {
			readOnly = raw
		}
		switch raw[0] {
		case '"':
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return nil, err
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
	facts := values.fields()
	if readOnly != nil {
		var hint *bool
		if err := json.Unmarshal(readOnly, &hint); err != nil {
			return nil, err
		}
		if hint != nil {
			facts["readOnlyHint"] = cedar.Boolean(*hint)
		}
	}
	return facts, nil
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
	Drift    *driftSettings   `json:"drift"`
}

// Snapshot is a validated configuration ready to decide tool calls. Version
// identifies the policy set it was built from, and Label is that set's
// human-readable label.
type Snapshot struct {
	Version  string
	Label    string
	policies *cedar.PolicySet
	tools    map[string]inventory
	// instructions holds each proxy's approved instructions. It is nil for a
	// format-1 set, which approves none.
	instructions map[string]string
}

// Instructions returns a proxy's approved instructions and whether the set
// approves any for it. An empty string is an approved value.
func (s *Snapshot) Instructions(proxy string) (string, bool) {
	text, ok := s.instructions[proxy]
	return text, ok
}

// Compile validates a set's policy files and builds the snapshot gateways
// decide with. Version identifies the set.
func Compile(in Inputs, version string) (*Snapshot, error) {
	rules, inventoryData, checks := in.Rules, in.Tools, in.Checks
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
	s := &Snapshot{Version: version, policies: cedar.NewPolicySet()}
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
		if inv.Drift != nil {
			if err := inv.Drift.validate(proxy); err != nil {
				return nil, err
			}
		}
		for name, t := range inv.Tools {
			if name == "" || t == nil {
				return nil, fmt.Errorf("tool %q for proxy %q must be a named object", name, proxy)
			}
			if err := t.prepare(name); err != nil {
				return nil, err
			}
			// Every approved definition has a fingerprint, so drift review can
			// compare it exactly. Any definition that loads has one.
			if t.Definition != nil {
				if t.Definition.fingerprint, err = DefinitionFingerprint(t.Definition.raw); err != nil {
					return nil, fmt.Errorf("tool %q for proxy %q: %w", name, proxy, err)
				}
			}
		}
	}
	if in.Instructions != nil {
		var approved map[string]*string
		if err := jsonv2.Unmarshal(in.Instructions, &approved); err != nil {
			return nil, fmt.Errorf("approved instructions: %w", err)
		}
		if approved == nil {
			return nil, fmt.Errorf("approved instructions must be an object")
		}
		s.instructions = make(map[string]string, len(approved))
		for proxy, text := range approved {
			if proxy == "" || text == nil {
				return nil, fmt.Errorf("approved instructions for proxy %q must be a string", proxy)
			}
			s.instructions[proxy] = *text
		}
	}
	// Activation checks are optional. An operator adds them to test a candidate's
	// decisions before it can replace the last good configuration.
	var cases []struct {
		Caller           Caller          `json:"caller"`
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
			candidate = &Snapshot{policies: s.policies, tools: map[string]inventory{
				c.Proxy: {Upstream: c.Upstream, Tools: map[string]*tool{c.Tool: h}},
			}}
		}
		reason, _ := candidate.Decide(c.Caller, c.Proxy, c.Upstream, c.Tool, c.Arguments)
		// Under drift review a listed tool without an approved definition is
		// refused before rules are evaluated, so a check of it cannot expect a
		// permit; a check expecting a denial still passes. A tool that is not
		// listed, or a check naming another upstream, keeps the decision above,
		// so a misspelled or removed tool cannot pass a check unnoticed.
		inv, listed := candidate.tools[c.Proxy]
		_, listed = inv.Tools[c.Tool]
		listed = listed && inv.Upstream == c.Upstream
		if view, enforcing := candidate.Drift(c.Proxy); enforcing && c.HypotheticalTool == nil && listed {
			if _, _, approved := view.Approved(c.Tool); !approved {
				reason = "unapproved_tool"
				if c.Expect == "policy_denied" {
					reason = c.Expect
				}
			}
		}
		if reason != c.Expect {
			return nil, fmt.Errorf("activation check %d expected %s, got %s", i, c.Expect, reason)
		}
	}
	return s, nil
}

// ToolRef identifies one reviewed tool and the argument types its rules may read.
type ToolRef struct {
	Proxy, Upstream, Name string
	Arguments             map[string]string
}

// Tools lists the reviewed tools in a stable order.
func (s *Snapshot) Tools() []ToolRef {
	var refs []ToolRef
	for proxy, inv := range s.tools {
		for name, t := range inv.Tools {
			refs = append(refs, ToolRef{Proxy: proxy, Upstream: inv.Upstream, Name: name, Arguments: maps.Clone(t.Arguments)})
		}
	}
	slices.SortFunc(refs, func(a, b ToolRef) int {
		if a.Proxy != b.Proxy {
			return strings.Compare(a.Proxy, b.Proxy)
		}
		return strings.Compare(a.Name, b.Name)
	})
	return refs
}
