package policy

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/cedar-policy/cedar-go"
)

type Caller struct {
	Issuer  string   `json:"issuer"`
	Subject string   `json:"subject"`
	Roles   []string `json:"roles"`
	Groups  []string `json:"groups"`
	Scopes  []string `json:"scopes"`
}

func stringsSet(items []string) cedar.Set {
	values := make([]cedar.Value, 0, len(items))
	for _, item := range items {
		values = append(values, cedar.String(item))
	}
	return cedar.NewSet(values...)
}

type scalarFacts map[string][]cedar.Value

func (f scalarFacts) add(kind, name string, value cedar.Value) {
	f[kind] = append(f[kind], cedar.NewRecord(cedar.RecordMap{"name": cedar.String(name), "value": value}))
}

func (f scalarFacts) fields() cedar.RecordMap {
	return cedar.RecordMap{"strings": cedar.NewSet(f["string"]...), "numbers": cedar.NewSet(f["long"]...), "flags": cedar.NewSet(f["boolean"]...)}
}

func argumentFacts(selected map[string]string, raw json.RawMessage) (cedar.Record, error) {
	var args map[string]json.RawMessage
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return cedar.Record{}, err
		}
	}
	sets := scalarFacts{}
	for name, kind := range selected {
		data, exists := args[name]
		if !exists {
			continue
		}
		var v cedar.Value
		switch kind {
		case "string":
			var s *string
			if json.Unmarshal(data, &s) != nil || s == nil {
				return cedar.Record{}, fmt.Errorf("expected string")
			}
			v = cedar.String(*s)
		case "boolean":
			var b *bool
			if json.Unmarshal(data, &b) != nil || b == nil {
				return cedar.Record{}, fmt.Errorf("expected boolean")
			}
			v = cedar.Boolean(*b)
		case "long":
			var n *int64
			if json.Unmarshal(data, &n) != nil || n == nil {
				return cedar.Record{}, fmt.Errorf("expected integer")
			}
			v = cedar.Long(*n)
		}
		sets.add(kind, name, v)
	}
	return cedar.NewRecord(sets.fields()), nil
}

func (s *Snapshot) Decide(who Caller, proxy, upstream, name string, args json.RawMessage) (string, []string) {
	inv, exists := s.tools[proxy]
	if exists && upstream != inv.Upstream {
		return "unreviewed_upstream", nil
	}
	t, ok := inv.Tools[name]
	if !ok {
		return "unknown_tool", nil
	}
	facts, err := argumentFacts(t.Arguments, args)
	if err != nil {
		return "invalid_argument", nil
	}
	// Tuple encoding keeps issuer/subject and proxy/tool identifiers unambiguous.
	principalID, _ := json.Marshal([2]string{who.Issuer, who.Subject})
	toolID, _ := json.Marshal([2]string{proxy, name})
	principal := cedar.NewEntityUID("Caller", cedar.String(principalID))
	resource := cedar.NewEntityUID("Tool", cedar.String(toolID))
	annotations := scalarFacts(nil).fields()
	if t.Definition != nil {
		annotations = t.Definition.facts
	}
	callerFacts := cedar.RecordMap{
		"issuer": cedar.String(who.Issuer), "subject": cedar.String(who.Subject),
		"roles": stringsSet(who.Roles), "groups": stringsSet(who.Groups), "scopes": stringsSet(who.Scopes),
	}
	toolFacts := cedar.RecordMap{
		"proxy": cedar.String(proxy), "upstream": cedar.String(upstream), "name": cedar.String(name),
		"reviewed": t.reviewed, "upstreamAnnotations": cedar.NewRecord(annotations),
	}
	entities := cedar.EntityMap{
		principal: {UID: principal, Attributes: cedar.NewRecord(callerFacts)},
		resource:  {UID: resource, Attributes: cedar.NewRecord(toolFacts)},
	}
	req := cedar.Request{Principal: principal, Action: cedar.NewEntityUID("Action", "tools/call"), Resource: resource, Context: facts}
	outcome, ids := s.evaluate(entities, req)
	if outcome == "permitted" && t.Definition != nil && len(t.Definition.Annotations) > 0 {
		// An upstream hint may narrow access. Permission must be justified
		// by trusted facts even if the upstream supplies no annotations.
		attrs := entities[resource].Attributes.Map()
		attrs["upstreamAnnotations"] = cedar.NewRecord(scalarFacts(nil).fields())
		entities[resource] = cedar.Entity{UID: resource, Attributes: cedar.NewRecord(attrs)}
		baseline, baselineIDs := s.evaluate(entities, req)
		if baseline != "permitted" {
			return baseline, baselineIDs
		}
		ids = append(ids, baselineIDs...)
		slices.Sort(ids)
		return baseline, slices.Compact(ids)
	}
	return outcome, ids
}

func (s *Snapshot) evaluate(entities cedar.EntityMap, req cedar.Request) (string, []string) {
	return evaluateWith(s.policies, entities, req)
}

// evaluateWith decides a request with a policy set. A forbid that fails to
// evaluate denies the request.
func evaluateWith(policies *cedar.PolicySet, entities cedar.EntityMap, req cedar.Request) (string, []string) {
	decision, diag := cedar.Authorize(policies, entities, req)
	return outcomeOf(policies, decision, diag), reasons(policies, diag)
}

// outcomeOf names a decision, treating a forbid that failed to evaluate as a
// denial.
func outcomeOf(policies *cedar.PolicySet, decision cedar.Decision, diag cedar.Diagnostic) string {
	outcome := "policy_denied"
	if decision == cedar.Allow {
		outcome = "permitted"
	}
	for _, failure := range diag.Errors {
		if policies.Get(failure.PolicyID).Effect() == cedar.Forbid {
			outcome = "forbid_error"
		}
	}
	return outcome
}

// reasons lists the policies that decided a request: those that applied,
// or every forbid that failed to evaluate.
func reasons(policies *cedar.PolicySet, diag cedar.Diagnostic) []string {
	var ids []string
	for _, reason := range diag.Reasons {
		ids = append(ids, string(reason.PolicyID))
	}
	var failed []string
	for _, failure := range diag.Errors {
		if policies.Get(failure.PolicyID).Effect() == cedar.Forbid {
			failed = append(failed, string(failure.PolicyID))
		}
	}
	if len(failed) > 0 {
		// The permits that applied did not decide a request a forbid denied.
		var forbids []string
		for _, id := range ids {
			if policies.Get(cedar.PolicyID(id)).Effect() == cedar.Forbid {
				forbids = append(forbids, id)
			}
		}
		ids = append(forbids, failed...)
	}
	slices.Sort(ids)
	return ids
}
