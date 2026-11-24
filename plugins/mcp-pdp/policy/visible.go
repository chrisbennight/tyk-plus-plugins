package policy

import (
	"context"
	"encoding/json"
	"hash/maphash"
	"slices"
	"sync/atomic"

	"github.com/cedar-policy/cedar-go"
	cedarast "github.com/cedar-policy/cedar-go/ast"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/batch"
)

// Visibility decides which of a proxy's tools to show a caller. A tool is
// left out only when Cedar shows that no call arguments could let the caller
// call it; when that is unclear, the tool is shown. Call arguments are
// treated as unknown: a permit that depends on them may apply, and a forbid
// that depends on them is set aside.
//
// The check relies on cedar-go's experimental batch package, so cedar-go is
// pinned to an exact version and the accuracy tests run in CI.

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
// tool. It checks one tool exactly. An evaluation error shows the tool.
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
		permitted := false
		err := batch.Authorize(context.Background(), s.visibilityPolicies, entities, batch.Request{
			Principal: principal, Action: cedar.NewEntityUID("Action", "tools/call"), Resource: resource, Context: batch.Ignore(),
		}, func(r batch.Result) error {
			permitted = permitted || r.Decision == cedar.Allow
			return nil
		})
		return err != nil || permitted
	}
	if !allowed(false) {
		return false
	}
	// As for calls, upstream annotations may only narrow access: the call
	// must also be permitted without them.
	if t.Definition == nil || len(t.Definition.Annotations) == 0 {
		return true
	}
	return allowed(true)
}

// visibleInBatch returns the tools on a proxy that some call arguments could
// let this caller call, evaluating the whole proxy in one batch. It can
// include tools Visible would leave out. An evaluation error shows every tool
// it covers. Every tool's entity is present during the batch, where a call
// decision sees only its own; a rule could tell them apart only by naming
// another tool's entity, which rules about tools have no reason to do, since
// they match the requested tool through resource.
func (s *Snapshot) visibleInBatch(who Caller, proxy string) map[string]bool {
	inv := s.tools[proxy]
	principal, _ := callerEntity(who)
	pass := func(names []string, stripAnnotations bool) map[string]bool {
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
		allowed := make(map[string]bool, len(names))
		err := batch.Authorize(context.Background(), s.visibilityPolicies, entities, batch.Request{
			Principal: principal, Action: cedar.NewEntityUID("Action", "tools/call"),
			Resource: batch.Variable("tool"), Context: batch.Ignore(),
			Variables: batch.Variables{"tool": uids},
		}, func(r batch.Result) error {
			if r.Decision == cedar.Allow {
				allowed[byUID[r.Request.Resource]] = true
			}
			return nil
		})
		if err != nil {
			for _, name := range names {
				allowed[name] = true
			}
		}
		return allowed
	}
	names := make([]string, 0, len(inv.Tools))
	for name := range inv.Tools {
		names = append(names, name)
	}
	visible := pass(names, false)
	var recheck []string
	for name := range visible {
		if t := inv.Tools[name]; t.Definition != nil && len(t.Definition.Annotations) > 0 {
			recheck = append(recheck, name)
		}
	}
	if len(recheck) > 0 {
		without := pass(recheck, true)
		for _, name := range recheck {
			if !without[name] {
				delete(visible, name)
			}
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

// visibilityPolicy rewrites a policy for deciding visibility. With the call's
// arguments ignored, batch evaluation drops each permit condition that refers
// to them: a whole when clause, including conditions on the caller or tool
// that it also tests. Splitting a permit's when clauses at their top-level
// "&&" keeps those other conditions, whatever order they are written in;
// clauses in a policy must all hold, so the permit is unchanged. Only the
// parts that test arguments are then dropped, so the permit may still apply,
// but no longer to callers its other conditions exclude.
//
// Forbids are left as written: a forbid with a condition on arguments is set
// aside whole, so a tool some arguments could call is never hidden.
func visibilityPolicy(p *cedar.Policy) *cedar.Policy {
	original := (*ast.Policy)(p.AST())
	if original.Effect != ast.EffectPermit {
		return p
	}
	rewritten := *original
	rewritten.Conditions = nil
	var split func(node ast.IsNode)
	split = func(node ast.IsNode) {
		if and, ok := node.(ast.NodeTypeAnd); ok {
			split(and.Left)
			split(and.Right)
			return
		}
		rewritten.Conditions = append(rewritten.Conditions, ast.ConditionType{Condition: ast.ConditionWhen, Body: node})
	}
	// "unless a || b" holds exactly when "!a" and "!b" both do, so an unless
	// clause is split at its top-level "||" into when clauses too.
	var splitUnless func(node ast.IsNode)
	splitUnless = func(node ast.IsNode) {
		if or, ok := node.(ast.NodeTypeOr); ok {
			splitUnless(or.Left)
			splitUnless(or.Right)
			return
		}
		rewritten.Conditions = append(rewritten.Conditions, ast.ConditionType{Condition: ast.ConditionWhen, Body: ast.NodeTypeNot{UnaryNode: ast.UnaryNode{Arg: node}}})
	}
	for _, c := range original.Conditions {
		if c.Condition == ast.ConditionWhen {
			split(c.Body)
		} else {
			splitUnless(c.Body)
		}
	}
	return cedar.NewPolicyFromAST((*cedarast.Policy)(&rewritten))
}
