package policy

import (
	"context"
	"encoding/json"
	"hash/maphash"
	"reflect"
	"slices"
	"sync/atomic"

	"github.com/cedar-policy/cedar-go"
	cedarast "github.com/cedar-policy/cedar-go/ast"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/batch"
)

// Visibility decides which of a proxy's tools to show a caller. A tool is
// left out only when Cedar shows that no call arguments could let the caller
// call it; when that is unclear, the tool is shown. See visibilityPolicy for
// how conditions on arguments are treated.
//
// Large proxies are checked with cedar-go's experimental batch package, so
// cedar-go is pinned to an exact version and the accuracy tests run in CI.

// DefaultVisibilityBatchThreshold is the number of tools on a proxy above
// which VisibleTools checks the whole proxy in one batch instead of one tool
// at a time.
const DefaultVisibilityBatchThreshold = 500

// visibilitySlots bounds the per-caller results a snapshot keeps. A result
// whose slot is taken by another caller is computed again, so the bound
// trades work for memory and cannot affect which tools are shown.
const visibilitySlots = 4096

// visibilityCache holds per-caller results for one snapshot, so results last
// until the policy set changes. Slots are replaced atomically and never
// locked, so the request path does not wait on other callers.
type visibilityCache struct {
	seed  maphash.Seed
	slots [visibilitySlots]atomic.Pointer[visibilityEntry]
}

func newVisibilityCache() *visibilityCache { return &visibilityCache{seed: maphash.MakeSeed()} }

type visibilityEntry struct {
	key     string
	visible map[string]bool
}

// VisibleTools returns the tools on a proxy the caller could call with some
// arguments. Proxies with up to batchThreshold tools are checked one tool at
// a time, which is exact. Larger proxies are checked in one batch, which can
// show a tool the caller cannot use but never hides one it can. Results are
// cached per caller for the life of the snapshot.
func (s *Snapshot) VisibleTools(who Caller, proxy string, batchThreshold int) map[string]bool {
	key := visibilityKey(who, proxy)
	slot := &s.visibility.slots[maphash.String(s.visibility.seed, key)%visibilitySlots]
	if entry := slot.Load(); entry != nil && entry.key == key {
		return entry.visible
	}
	inv := s.tools[proxy]
	// Only the visible names are kept, so a caller who may see few tools
	// costs little to cache however large the proxy.
	visible := map[string]bool{}
	if len(inv.Tools) > batchThreshold {
		for name := range s.visibleInBatch(who, proxy) {
			visible[name] = true
		}
	} else {
		for name := range inv.Tools {
			if s.Visible(who, proxy, name) {
				visible[name] = true
			}
		}
	}
	slot.Store(&visibilityEntry{key: key, visible: visible})
	return visible
}

// visibilityKey identifies a caller and proxy by every fact rules can read
// about the caller, so two callers share a result only when no rule can tell
// them apart.
func visibilityKey(who Caller, proxy string) string {
	sorted := func(values []string) []string {
		out := slices.Clone(values)
		slices.Sort(out)
		return slices.Compact(out)
	}
	key, _ := json.Marshal([]any{proxy, who.Issuer, who.Subject, sorted(who.Roles), sorted(who.Groups), sorted(who.Scopes)})
	return string(key)
}

// Visible reports whether some call arguments could let this caller call the
// tool, checking one tool.
func (s *Snapshot) Visible(who Caller, proxy, name string) bool {
	inv, ok := s.tools[proxy]
	if !ok {
		return false
	}
	t, ok := inv.Tools[name]
	if !ok {
		return false
	}
	if len(t.Arguments) == 0 {
		// A tool whose arguments rules cannot read is always called with the
		// same empty argument facts, so the call decision itself is exact.
		outcome, _ := s.Decide(who, proxy, inv.Upstream, name, nil)
		return outcome == "permitted"
	}
	principal, entities := callerEntity(who)
	toolID, _ := json.Marshal([2]string{proxy, name})
	resource := cedar.NewEntityUID("Tool", cedar.String(toolID))
	allowed := func(stripAnnotations bool) bool {
		entities[resource] = toolEntity(resource, proxy, inv.Upstream, name, t, stripAnnotations)
		outcome, _ := evaluateWith(s.visibilityPolicies, entities, cedar.Request{
			Principal: principal, Action: cedar.NewEntityUID("Action", "tools/call"), Resource: resource, Context: noArguments(),
		})
		return outcome == "permitted"
	}
	// As for calls, upstream annotations may only narrow access: the call
	// must also be permitted without them.
	if !allowed(false) {
		return false
	}
	return t.Definition == nil || len(t.Definition.Annotations) == 0 || allowed(true)
}

// noArguments is the argument facts of a call that supplies none.
func noArguments() cedar.Record {
	facts, _ := argumentFacts(nil, nil)
	return facts
}

// visibleInBatch returns the tools on a proxy that some call arguments could
// let this caller call, evaluating the whole proxy in one batch per kind of
// tool. It can include tools Visible would leave out. Every tool's entity is
// present during the batch, where a call decision sees only its own; a rule
// could tell them apart only by naming another tool's entity, which rules
// about tools have no reason to do, since they match the requested tool
// through resource.
func (s *Snapshot) visibleInBatch(who Caller, proxy string) map[string]bool {
	inv := s.tools[proxy]
	principal, _ := callerEntity(who)
	// Tools without declared arguments are decided with the rules as
	// written, as their calls would be; others with the rules rewritten for
	// unknown arguments.
	pass := func(policies *cedar.PolicySet, names []string, stripAnnotations bool) map[string]bool {
		allowed := make(map[string]bool, len(names))
		if len(names) == 0 {
			return allowed
		}
		_, entities := callerEntity(who)
		uids := make([]cedar.Value, 0, len(names))
		byUID := make(map[cedar.EntityUID]string, len(names))
		for _, name := range names {
			toolID, _ := json.Marshal([2]string{proxy, name})
			uid := cedar.NewEntityUID("Tool", cedar.String(toolID))
			entities[uid] = toolEntity(uid, proxy, inv.Upstream, name, inv.Tools[name], stripAnnotations)
			uids = append(uids, uid)
			byUID[uid] = name
		}
		err := batch.Authorize(context.Background(), policies, entities, batch.Request{
			Principal: principal, Action: cedar.NewEntityUID("Action", "tools/call"),
			Resource: batch.Variable("tool"), Context: noArguments(),
			Variables: batch.Variables{"tool": uids},
		}, func(r batch.Result) error {
			if outcomeOf(policies, r.Decision, r.Diagnostic) == "permitted" {
				allowed[byUID[r.Request.Resource]] = true
			}
			return nil
		})
		if err != nil {
			// The batch could not be evaluated, so every tool is shown.
			for _, name := range names {
				allowed[name] = true
			}
		}
		return allowed
	}
	var exact, unknown []string
	for name, t := range inv.Tools {
		if len(t.Arguments) == 0 {
			exact = append(exact, name)
		} else {
			unknown = append(unknown, name)
		}
	}
	visible := pass(s.policies, exact, false)
	for name := range pass(s.visibilityPolicies, unknown, false) {
		visible[name] = true
	}
	var recheckExact, recheckUnknown []string
	for name := range visible {
		if t := inv.Tools[name]; t.Definition != nil && len(t.Definition.Annotations) > 0 {
			if len(t.Arguments) == 0 {
				recheckExact = append(recheckExact, name)
			} else {
				recheckUnknown = append(recheckUnknown, name)
			}
		}
	}
	without := pass(s.policies, recheckExact, true)
	for name := range pass(s.visibilityPolicies, recheckUnknown, true) {
		without[name] = true
	}
	for _, name := range append(recheckExact, recheckUnknown...) {
		if !without[name] {
			delete(visible, name)
		}
	}
	return visible
}

// callerEntity returns the caller's entity UID and an entity map holding it,
// built as Decide builds it.
func callerEntity(who Caller) (cedar.EntityUID, cedar.EntityMap) {
	principalID, _ := json.Marshal([2]string{who.Issuer, who.Subject})
	principal := cedar.NewEntityUID("Caller", cedar.String(principalID))
	callerFacts := cedar.RecordMap{
		"issuer": cedar.String(who.Issuer), "subject": cedar.String(who.Subject),
		"roles": stringsSet(who.Roles), "groups": stringsSet(who.Groups), "scopes": stringsSet(who.Scopes),
	}
	return principal, cedar.EntityMap{principal: {UID: principal, Attributes: cedar.NewRecord(callerFacts)}}
}

// toolEntity builds a tool's entity as Decide builds it, optionally without
// its upstream annotations.
func toolEntity(uid cedar.EntityUID, proxy, upstream, name string, t *tool, stripAnnotations bool) cedar.Entity {
	annotations := scalarFacts(nil).fields()
	if t.Definition != nil && !stripAnnotations {
		annotations = t.Definition.facts
	}
	return cedar.Entity{UID: uid, Attributes: cedar.NewRecord(cedar.RecordMap{
		"proxy": cedar.String(proxy), "upstream": cedar.String(upstream), "name": cedar.String(name),
		"reviewed": t.reviewed, "upstreamAnnotations": cedar.NewRecord(annotations),
	})}
}

// visibilityPolicy rewrites a policy so it decides whether some call
// arguments could make it apply, without reading them. Each condition is
// replaced by one of two versions in which every test that reads the call's
// arguments is replaced by a constant:
//
//   - "possibly true", where such a test counts as true wherever that could
//     make the condition hold, and
//   - "necessarily true", where it counts as false wherever that could make
//     the condition fail.
//
// The two are built together through "&&", "||", "!" and "if", so tests on
// the caller and tool keep deciding the result wherever they are written:
// a permit limited to one role still applies to no one else. A permit keeps
// the "possibly true" version of its when clauses and the opposite of the
// "necessarily true" version of its unless clauses, so it applies whenever
// some arguments could make it apply. A forbid does the reverse, so it applies
// only when every set of arguments would make it apply. A tool some arguments
// could let the caller call is therefore never hidden.
//
// Any other expression that reads arguments is replaced whole, including
// tests on the caller or tool inside it, such as in "(a && b) == true". Its
// result is then unclear, and an unclear tool is shown.
func visibilityPolicy(p *cedar.Policy) *cedar.Policy {
	original := (*ast.Policy)(p.AST())
	rewritten := *original
	rewritten.Conditions = make([]ast.ConditionType, 0, len(original.Conditions))
	permit := original.Effect == ast.EffectPermit
	for _, c := range original.Conditions {
		possible, necessary := bounds(c.Body)
		body := possible
		switch {
		case permit && c.Condition == ast.ConditionUnless:
			body = not(necessary)
		case !permit && c.Condition == ast.ConditionWhen:
			body = necessary
		case !permit && c.Condition == ast.ConditionUnless:
			body = not(possible)
		}
		rewritten.Conditions = append(rewritten.Conditions, ast.ConditionType{Condition: ast.ConditionWhen, Body: body})
	}
	return cedar.NewPolicyFromAST((*cedarast.Policy)(&rewritten))
}

// bounds returns the "possibly true" and "necessarily true" versions of a
// condition; see visibilityPolicy.
func bounds(node ast.IsNode) (possible, necessary ast.IsNode) {
	switch n := node.(type) {
	case ast.NodeTypeAnd:
		lp, ln := bounds(n.Left)
		rp, rn := bounds(n.Right)
		return ast.NodeTypeAnd{BinaryNode: ast.BinaryNode{Left: lp, Right: rp}}, ast.NodeTypeAnd{BinaryNode: ast.BinaryNode{Left: ln, Right: rn}}
	case ast.NodeTypeOr:
		lp, ln := bounds(n.Left)
		rp, rn := bounds(n.Right)
		return ast.NodeTypeOr{BinaryNode: ast.BinaryNode{Left: lp, Right: rp}}, ast.NodeTypeOr{BinaryNode: ast.BinaryNode{Left: ln, Right: rn}}
	case ast.NodeTypeNot:
		p, nec := bounds(n.Arg)
		return not(nec), not(p)
	case ast.NodeTypeIfThenElse:
		cp, cn := bounds(n.If)
		tp, tn := bounds(n.Then)
		ep, en := bounds(n.Else)
		// When the condition is known, its branch decides. Otherwise either
		// branch may be taken.
		choose := func(then, otherwise, either ast.IsNode) ast.IsNode {
			return ast.NodeTypeIfThenElse{If: cn, Then: then, Else: ast.NodeTypeIfThenElse{If: not(cp), Then: otherwise, Else: either}}
		}
		return choose(tp, ep, ast.NodeTypeOr{BinaryNode: ast.BinaryNode{Left: tp, Right: ep}}),
			choose(tn, en, ast.NodeTypeAnd{BinaryNode: ast.BinaryNode{Left: tn, Right: en}})
	}
	if !readsArguments(reflect.ValueOf(node)) {
		return node, node
	}
	return ast.NodeValue{Value: types.True}, ast.NodeValue{Value: types.False}
}

func not(node ast.IsNode) ast.IsNode { return ast.NodeTypeNot{UnaryNode: ast.UnaryNode{Arg: node}} }

// readsArguments reports whether an expression reads the request context,
// which holds the call's arguments. It walks every exported field of the
// expression, so a kind of expression added to cedar-go later is still
// searched.
func readsArguments(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		return !v.IsNil() && readsArguments(v.Elem())
	case reflect.Slice:
		for i := range v.Len() {
			if readsArguments(v.Index(i)) {
				return true
			}
		}
	case reflect.Struct:
		if variable, ok := v.Interface().(ast.NodeTypeVariable); ok {
			return variable.Name == "context"
		}
		if _, ok := v.Interface().(ast.NodeValue); ok {
			return false
		}
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() && readsArguments(v.Field(i)) {
				return true
			}
		}
	}
	return false
}
