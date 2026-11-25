package driftreview

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// ActiveSet loads the active set.
func ActiveSet(store string) (*policy.Snapshot, error) {
	pointer, err := policy.ReadPointer(store)
	if err != nil {
		return nil, err
	}
	snapshot, _, err := policy.LoadSet(store, pointer.Set)
	return snapshot, err
}

// PendingTool is a tool review entry with what the active set and the
// gateways' latest declarations say about it.
type PendingTool struct {
	Entry drift.ToolEntry
	// Kind is "new" for a tool with no approved definition, else "changed".
	Kind string
	// Latest is whether gateways saw the upstream declare this definition
	// last.
	Latest bool
	// Declared is whether any gateway has shared a declaration of the tool
	// from the reviewed upstream.
	Declared bool
}

// PendingTools returns a proxy's tool entries the active set neither
// approves nor rejects.
func PendingTools(review *drift.Review, view policy.DriftView, proxy string) ([]PendingTool, []error, error) {
	entries, problems, err := review.Tools(proxy)
	if err != nil {
		return nil, nil, err
	}
	var waiting []PendingTool
	// Each tool's declarations are read once, so at most one of its waiting
	// definitions is the latest, however gateways write meanwhile.
	latest := map[string]string{}
	for _, entry := range entries {
		approved, _, ok := view.Approved(entry.Tool)
		if approved == entry.Fingerprint || view.Rejected(entry.Tool, entry.Fingerprint) {
			continue
		}
		kind := "new"
		if ok {
			kind = "changed"
		}
		fingerprint, read := latest[entry.Tool]
		if !read {
			newest, found, err := review.Newest(proxy, entry.Tool, view.Upstream())
			if err != nil {
				problems = append(problems, err)
			}
			if found {
				fingerprint = newest.Fingerprint
			}
			latest[entry.Tool] = fingerprint
		}
		_, declared := latest[entry.Tool]
		declared = declared && fingerprint != ""
		waiting = append(waiting, PendingTool{Entry: entry, Kind: kind, Declared: declared, Latest: declared && fingerprint == entry.Fingerprint})
	}
	return waiting, problems, nil
}

// PendingInstructions returns a proxy's instructions entries the active set
// neither approves nor rejects.
func PendingInstructions(review *drift.Review, snapshot *policy.Snapshot, view policy.DriftView, proxy string) ([]drift.InstructionsEntry, []error, error) {
	entries, problems, err := review.Instructions(proxy)
	if err != nil {
		return nil, nil, err
	}
	approved, _ := snapshot.Instructions(proxy)
	approvedFingerprint := policy.InstructionsFingerprint(approved)
	var waiting []drift.InstructionsEntry
	for _, entry := range entries {
		if entry.Fingerprint != approvedFingerprint && !view.RejectedInstructions(entry.Fingerprint) {
			waiting = append(waiting, entry)
		}
	}
	return waiting, problems, nil
}

// MissingTools returns approved tools no gateway has shared a declaration of
// from the reviewed upstream.
func MissingTools(review *drift.Review, view policy.DriftView, proxy string) ([]string, error) {
	var missing []string
	for _, name := range view.ApprovedTools() {
		if _, found, err := review.Newest(proxy, name, view.Upstream()); err != nil {
			return nil, err
		} else if !found {
			missing = append(missing, name)
		}
	}
	return missing, nil
}

// RenameHints returns approved tools that take the same input or have the
// same description as a new tool and that the upstream's latest list no
// longer declares.
func RenameHints(review *drift.Review, view policy.DriftView, proxy string, entry drift.ToolEntry) ([]string, error) {
	listed, err := latestList(review, view, proxy)
	if err != nil {
		return nil, err
	}
	proposed := object(entry.Definition)
	var hints []string
	for _, name := range view.ApprovedTools() {
		if listed.has(name) {
			continue
		}
		_, approved, _ := view.Approved(name)
		old := object(jsontext.Value(approved))
		sameSchema := proposed["inputSchema"] != nil && Canonical(old["inputSchema"]) == Canonical(proposed["inputSchema"])
		sameDescription := proposed["description"] != nil && Canonical(old["description"]) == Canonical(proposed["description"])
		if sameSchema || sameDescription {
			hints = append(hints, name)
		}
	}
	return hints, nil
}

// listing is the newest declaration of each tool a proxy's reviewed upstream
// declared, and when the latest list was received.
type listing struct {
	newest map[string]drift.Declared
	at     time.Time
}

// has reports whether the upstream's latest list declared a tool. A list
// declares all its tools at the time it was received, so a tool whose newest
// declaration is older was left out of it.
func (l listing) has(tool string) bool {
	d, ok := l.newest[tool]
	return ok && !d.SeenAt.Before(l.at)
}

func latestList(review *drift.Review, view policy.DriftView, proxy string) (listing, error) {
	l := listing{newest: map[string]drift.Declared{}}
	tools, err := review.DeclaredTools(proxy)
	if err != nil {
		return l, err
	}
	for _, tool := range tools {
		d, found, err := review.Newest(proxy, tool, view.Upstream())
		if err != nil {
			return l, err
		}
		if found {
			l.newest[tool] = d
			if d.SeenAt.After(l.at) {
				l.at = d.SeenAt
			}
		}
	}
	return l, nil
}

// Decision is one approval or rejection to make in a new set.
type Decision struct {
	Proxy, Tool string
	// Instructions is set for a decision on the proxy's instructions rather
	// than a tool.
	Instructions bool
	Fingerprint  string
	// Definition is the tool definition, or Text the instructions, being
	// approved.
	Definition jsontext.Value
	Text       string
	// Approve is set to approve, and unset to reject.
	Approve bool
}

// Describe names a decision's subject for a terminal, with hidden
// characters written out, as tool and proxy names come from upstreams and
// operators.
func Describe(d Decision) string {
	if d.Instructions {
		return ShownName(d.Proxy) + " instructions"
	}
	return ShownName(d.Proxy) + "/" + ShownName(d.Tool)
}

// Apply writes decisions into a new set made from the active one,
// under the store's lock, and makes it active. The decisions were made
// against the set named base; if another set became active since, nothing is
// changed, so a decision never overrides one the reviewer did not see.
func Apply(store, base, label string, actor policy.Actor, now func() time.Time, decisions []Decision) (string, error) {
	return policy.Revise(store, label, actor, now, func(set string, active *policy.Snapshot, files map[string][]byte) ([]policy.LogEntry, error) {
		if set != base {
			return nil, fmt.Errorf("the active set changed to %s while you reviewed; nothing was changed, so review again", set)
		}
		var inventory map[string]map[string]jsontext.Value
		if err := jsonv2.Unmarshal(files["approved_tools.json"], &inventory); err != nil {
			return nil, fmt.Errorf("approved_tools.json: %w", err)
		}
		var instructions map[string]string
		if err := jsonv2.Unmarshal(files["approved_instructions.json"], &instructions); err != nil {
			return nil, fmt.Errorf("approved_instructions.json: %w", err)
		}
		if instructions == nil {
			instructions = map[string]string{}
		}
		entries := make([]policy.LogEntry, 0, len(decisions))
		for _, d := range decisions {
			view, ok := active.Drift(d.Proxy)
			if !ok {
				return nil, fmt.Errorf("proxy %q is not under drift review in the active set", d.Proxy)
			}
			if err := apply(inventory[d.Proxy], instructions, active, view, d); err != nil {
				return nil, fmt.Errorf("%s: %w", Describe(d), err)
			}
			action := "reject"
			if d.Approve {
				action = "approve"
			}
			entries = append(entries, policy.LogEntry{Action: action, Proxy: d.Proxy, Tool: d.Tool, Instructions: d.Instructions, Fingerprint: d.Fingerprint})
		}
		var err error
		if files["approved_tools.json"], err = marshalIndented(inventory); err != nil {
			return nil, err
		}
		files["approved_instructions.json"], err = marshalIndented(instructions)
		return entries, err
	})
}

// apply makes one decision in a proxy's inventory and the approved
// instructions.
func apply(proxy map[string]jsontext.Value, instructions map[string]string, active *policy.Snapshot, view policy.DriftView, d Decision) error {
	var settings map[string]jsontext.Value
	if err := jsonv2.Unmarshal(proxy["drift"], &settings); err != nil {
		return err
	}
	if settings == nil {
		settings = map[string]jsontext.Value{}
	}
	if d.Instructions {
		approved, _ := active.Instructions(d.Proxy)
		if d.Approve {
			instructions[d.Proxy] = d.Text
		} else if policy.InstructionsFingerprint(approved) == d.Fingerprint {
			return errors.New("these are the approved instructions")
		}
		var rejected []string
		if err := jsonv2.Unmarshal(orNull(settings["rejectedInstructions"]), &rejected); err != nil {
			return err
		}
		rejected = setMember(rejected, d.Fingerprint, !d.Approve)
		return setDrift(proxy, settings, "rejectedInstructions", rejected)
	}
	var tools map[string]map[string]jsontext.Value
	if err := jsonv2.Unmarshal(proxy["tools"], &tools); err != nil {
		return err
	}
	if d.Approve {
		if tools[d.Tool] == nil {
			tools[d.Tool] = map[string]jsontext.Value{}
		}
		// A definition's fingerprint leaves out its top-level _meta, so the
		// reviewer never approved it; the approved definition has none.
		definition, err := withoutMeta(d.Definition)
		if err != nil {
			return err
		}
		tools[d.Tool]["definition"] = definition
	} else if approved, _, _ := view.Approved(d.Tool); approved == d.Fingerprint {
		return errors.New("this is the approved definition")
	}
	encoded, err := jsonv2.Marshal(tools, jsonv2.Deterministic(true))
	if err != nil {
		return err
	}
	proxy["tools"] = encoded
	var rejected map[string][]string
	if err := jsonv2.Unmarshal(orNull(settings["rejectedTools"]), &rejected); err != nil {
		return err
	}
	if rejected == nil {
		rejected = map[string][]string{}
	}
	if rejected[d.Tool] = setMember(rejected[d.Tool], d.Fingerprint, !d.Approve); len(rejected[d.Tool]) == 0 {
		delete(rejected, d.Tool)
	}
	return setDrift(proxy, settings, "rejectedTools", rejected)
}

// withoutMeta returns a definition without its top-level _meta member.
func withoutMeta(definition jsontext.Value) (jsontext.Value, error) {
	var members map[string]jsontext.Value
	if err := jsonv2.Unmarshal(definition, &members); err != nil {
		return nil, err
	}
	delete(members, "_meta")
	return jsonv2.Marshal(members, jsonv2.Deterministic(true))
}

// setDrift writes a drift setting back, leaving it out when it is empty.
func setDrift[T any](proxy, settings map[string]jsontext.Value, key string, value T) error {
	encoded, err := jsonv2.Marshal(value, jsonv2.Deterministic(true))
	if err != nil {
		return err
	}
	if string(encoded) == "[]" || string(encoded) == "{}" || string(encoded) == "null" {
		delete(settings, key)
	} else {
		settings[key] = encoded
	}
	proxy["drift"], err = jsonv2.Marshal(settings, jsonv2.Deterministic(true))
	return err
}

func orNull(value jsontext.Value) jsontext.Value {
	if len(value) == 0 {
		return jsontext.Value("null")
	}
	return value
}

// setMember adds or removes a value, keeping the list sorted.
func setMember(list []string, value string, member bool) []string {
	list = slices.DeleteFunc(list, func(v string) bool { return v == value })
	if member {
		list = append(list, value)
		slices.Sort(list)
	}
	return list
}

func marshalIndented(v any) ([]byte, error) {
	data, err := jsonv2.Marshal(v, jsonv2.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Confirmation is a code for an exact list of decisions against one active
// set: their count and a digest of the set and of what each approves, so a
// Confirmation never covers a list, or a set, that changed after it was
// shown.
func Confirmation(set string, decisions []Decision) string {
	lines := make([]string, len(decisions))
	for i, d := range decisions {
		lines[i] = fmt.Sprintf("%s\x00%s\x00%t\x00%s", d.Proxy, d.Tool, d.Instructions, d.Fingerprint)
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(set + "\n" + strings.Join(lines, "\n")))
	return fmt.Sprintf("%d-%s", len(decisions), hex.EncodeToString(sum[:]))
}

func PruneSettled(review *drift.Review, snapshot *policy.Snapshot) (int, error) {
	removed := 0
	for _, proxy := range snapshot.DriftProxies() {
		view, _ := snapshot.Drift(proxy)
		entries, _, err := review.Tools(proxy)
		if err != nil {
			return removed, err
		}
		for _, entry := range entries {
			if approved, _, _ := view.Approved(entry.Tool); approved == entry.Fingerprint || view.Rejected(entry.Tool, entry.Fingerprint) {
				if err := review.RemoveTool(proxy, entry.Tool, entry.Fingerprint); err != nil {
					return removed, err
				}
				removed++
			}
		}
		instructions, _, err := review.Instructions(proxy)
		if err != nil {
			return removed, err
		}
		approved, _ := snapshot.Instructions(proxy)
		for _, entry := range instructions {
			if entry.Fingerprint == policy.InstructionsFingerprint(approved) || view.RejectedInstructions(entry.Fingerprint) {
				if err := review.RemoveInstructions(proxy, entry.Fingerprint); err != nil {
					return removed, err
				}
				removed++
			}
		}
	}
	return removed, nil
}
