package policy

import (
	"context"
	"encoding/json"
	"hash/maphash"
	"slices"
	"sync/atomic"

	"github.com/cedar-policy/cedar-go"
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
	visible := make(map[string]bool, len(inv.Tools))
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
	principal, entities := callerEntity(who)
	toolID, _ := json.Marshal([2]string{proxy, name})
	resource := cedar.NewEntityUID("Tool", cedar.String(toolID))
	allowed := func(stripAnnotations bool) bool {
		entities[resource] = toolEntity(resource, proxy, inv.Upstream, name, t, stripAnnotations)
		permitted := false
		err := batch.Authorize(context.Background(), s.policies, entities, batch.Request{
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
// include tools Visible would leave out, but never leaves out one Visible
// would include. An evaluation error shows every tool it covers.
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
		err := batch.Authorize(context.Background(), s.policies, entities, batch.Request{
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
