package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/cedar-policy/cedar-go"
	jsonv2 "github.com/go-json-experiment/json"
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

// errAmbiguous reports call arguments that an upstream matching names
// regardless of letter case could read differently from the plug-in.
var errAmbiguous = errors.New("argument names that differ only by letter case or hold control characters")

// argumentFacts reads the declared arguments of a call for rules. The
// arguments are read with exact names, and rejected when they hold duplicate
// names or invalid UTF-8, or when ambiguousNames finds a name another parser
// could read differently.
func argumentFacts(selected map[string]string, raw json.RawMessage) (cedar.Record, error) {
	var args map[string]json.RawMessage
	if len(raw) > 0 {
		if err := jsonv2.Unmarshal(raw, &args); err != nil {
			return cedar.Record{}, err
		}
	}
	if ambiguousNames(args, selected) {
		return cedar.Record{}, errAmbiguous
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

// ambiguousNames reports whether the top-level argument names of a call
// could be read differently by an upstream that matches names regardless of
// letter case: two names equal under Unicode case folding, a name equal under
// folding to a declared argument but not spelled exactly as declared, or a
// name holding a control character, which some parsers drop.
func ambiguousNames(args map[string]json.RawMessage, declared map[string]string) bool {
	declaredFolds := make(map[string]bool, len(declared))
	for name := range declared {
		declaredFolds[foldName(name)] = true
	}
	seen := make(map[string]bool, len(args))
	for name := range args {
		if strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return true
		}
		folded := foldName(name)
		if seen[folded] {
			return true
		}
		seen[folded] = true
		if _, exact := declared[name]; !exact && declaredFolds[folded] {
			return true
		}
	}
	return false
}

// foldName maps every rune to the smallest rune that strings.EqualFold treats
// as equal to it, so two names are equal under case folding exactly when
// their folded forms are equal.
func foldName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		b.WriteRune(least)
	}
	return b.String()
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
	if errors.Is(err, errAmbiguous) {
		return "ambiguous_call", nil
	}
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
