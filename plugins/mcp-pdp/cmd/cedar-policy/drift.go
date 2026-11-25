package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

const driftUsage = `Usage:
  cedar-policy drift list -store DIR -pending DIR [-proxy NAME]
      List changes waiting for review on proxies under drift review: new and
      changed tools, changed instructions, and approved tools no gateway has
      seen the upstream declare.
  cedar-policy drift show -store DIR -pending DIR -proxy NAME (-tool NAME | -instructions) FINGERPRINT
      Show a waiting change in full, with a labelled diff against the approved
      version. Invisible and look-alike characters are written out.
  cedar-policy drift approve -store DIR -pending DIR -proxy NAME (-tool NAME | -instructions) [-label TEXT] FINGERPRINT
      Approve exactly the definition or instructions with this fingerprint,
      in a new set made from the active one and made active.
  cedar-policy drift reject -store DIR -pending DIR -proxy NAME (-tool NAME | -instructions) [-label TEXT] FINGERPRINT
      Record a rejection in a new active set, so gateways no longer queue it.
  cedar-policy drift approve-all -store DIR -pending DIR -proxy NAME [-count N] [-label TEXT]
      Adopt what a proxy's upstream now declares: approve, for each tool, the
      definition gateways saw last, and the waiting instructions when there
      is only one. Without -count it lists them; with -count it approves them
      if there are exactly that many.
  cedar-policy drift prune -store DIR -pending DIR
      Remove waiting changes the active set already approves or rejects.
  cedar-policy drift retire -pending DIR GATEWAY
      Remove the declarations a gateway shared, once it will not run again.
      A running gateway's sightings would be lost until it lists tools again.
`

// driftFlags are the options the drift commands share.
type driftFlags struct {
	store, pending, proxy, tool, label string
	instructions                       bool
	count                              int
}

func runDrift(args []string, out io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		return errors.New("a drift command is required")
	}
	command := args[0]
	flags := flag.NewFlagSet("drift "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var f driftFlags
	flags.StringVar(&f.store, "store", "", "policy store directory")
	flags.StringVar(&f.pending, "pending", "", "shared drift directory (CEDAR_PENDING_DIR)")
	flags.StringVar(&f.proxy, "proxy", "", "proxy ID")
	flags.StringVar(&f.tool, "tool", "", "tool name")
	flags.BoolVar(&f.instructions, "instructions", false, "the proxy's instructions rather than a tool")
	flags.StringVar(&f.label, "label", "", "label for the new set")
	flags.IntVar(&f.count, "count", -1, "number of changes approve-all should approve")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if f.pending == "" {
		return errors.New("-pending is required")
	}
	if f.store == "" && command != "retire" {
		return errors.New("-store is required")
	}
	review, err := drift.OpenReview(f.pending)
	if err != nil {
		return err
	}
	defer review.Close()
	switch command {
	case "list":
		return driftList(out, review, f)
	case "show":
		fingerprint, err := subject(flags, f)
		if err != nil {
			return err
		}
		return driftShow(out, review, f, fingerprint)
	case "approve", "reject":
		fingerprint, err := subject(flags, f)
		if err != nil {
			return err
		}
		return driftDecide(out, review, f, fingerprint, command == "approve", now)
	case "approve-all":
		if f.proxy == "" || flags.NArg() != 0 {
			return errors.New("approve-all expects -proxy and no arguments")
		}
		return driftApproveAll(out, review, f, now)
	case "prune":
		return driftPrune(out, review, f)
	case "retire":
		if flags.NArg() != 1 {
			return errors.New("retire expects the gateway's name")
		}
		removed, err := review.Retire(flags.Arg(0))
		fmt.Fprintf(out, "Removed %d declaration file(s) of gateway %s.\n", removed, shownName(flags.Arg(0)))
		return err
	}
	return fmt.Errorf("unknown drift command %q", command)
}

// subject checks that a command names one proxy, either a tool or the
// instructions, and one fingerprint, and returns the fingerprint.
func subject(flags *flag.FlagSet, f driftFlags) (string, error) {
	if f.proxy == "" || (f.tool == "") == !f.instructions || flags.NArg() != 1 {
		return "", errors.New("expects -proxy, either -tool or -instructions, and a fingerprint")
	}
	return flags.Arg(0), nil
}

// activeSet loads the active set.
func activeSet(store string) (*policy.Snapshot, error) {
	pointer, err := policy.ReadPointer(store)
	if err != nil {
		return nil, err
	}
	snapshot, _, err := policy.LoadSet(store, pointer.Set)
	return snapshot, err
}

// pendingTool is a tool review entry with what the active set and the
// gateways' latest declarations say about it.
type pendingTool struct {
	entry drift.ToolEntry
	kind  string
	// latest is whether gateways saw the upstream declare this definition
	// last.
	latest bool
}

// pendingTools returns a proxy's tool entries the active set neither
// approves nor rejects.
func pendingTools(review *drift.Review, view policy.DriftView, proxy string) ([]pendingTool, []error, error) {
	entries, problems, err := review.Tools(proxy)
	if err != nil {
		return nil, nil, err
	}
	var waiting []pendingTool
	for _, entry := range entries {
		approved, _, ok := view.Approved(entry.Tool)
		if approved == entry.Fingerprint || view.Rejected(entry.Tool, entry.Fingerprint) {
			continue
		}
		kind := "new"
		if ok {
			kind = "changed"
		}
		newest, found, err := review.Newest(proxy, entry.Tool, view.Upstream())
		if err != nil {
			problems = append(problems, err)
		}
		waiting = append(waiting, pendingTool{entry: entry, kind: kind, latest: found && newest.Fingerprint == entry.Fingerprint})
	}
	return waiting, problems, nil
}

// pendingInstructions returns a proxy's instructions entries the active set
// neither approves nor rejects.
func pendingInstructions(review *drift.Review, snapshot *policy.Snapshot, view policy.DriftView, proxy string) ([]drift.InstructionsEntry, []error, error) {
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

// missingTools returns approved tools no gateway has shared a declaration of
// from the reviewed upstream.
func missingTools(review *drift.Review, view policy.DriftView, proxy string) ([]string, error) {
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

func driftList(out io.Writer, review *drift.Review, f driftFlags) error {
	snapshot, err := activeSet(f.store)
	if err != nil {
		return err
	}
	proxies := snapshot.DriftProxies()
	if f.proxy != "" {
		if _, ok := snapshot.Drift(f.proxy); !ok {
			return fmt.Errorf("proxy %q is not under drift review in the active set", f.proxy)
		}
		proxies = []string{f.proxy}
	}
	shown := 0
	for _, proxy := range proxies {
		view, _ := snapshot.Drift(proxy)
		tools, problems, err := pendingTools(review, view, proxy)
		if err != nil {
			return err
		}
		instructions, instructionProblems, err := pendingInstructions(review, snapshot, view, proxy)
		if err != nil {
			return err
		}
		missing, err := missingTools(review, view, proxy)
		if err != nil {
			return err
		}
		for _, t := range tools {
			state := "superseded"
			if t.latest {
				state = "latest"
			}
			fmt.Fprintf(out, "%s\t%s\ttool %s\t%s\t%s, first seen %s on %s\n", shownName(proxy), t.kind, shownName(t.entry.Tool),
				t.entry.Fingerprint, state, t.entry.FirstSeen.Format(time.RFC3339), shownName(t.entry.Gateway))
			shown++
		}
		for _, entry := range instructions {
			fmt.Fprintf(out, "%s\tchanged\tinstructions\t%s\tfirst seen %s on %s\n", shownName(proxy), entry.Fingerprint,
				entry.FirstSeen.Format(time.RFC3339), shownName(entry.Gateway))
			shown++
		}
		for _, name := range missing {
			fmt.Fprintf(out, "%s\tmissing\ttool %s\t\tno gateway has shared a declaration of it from the reviewed upstream\n", shownName(proxy), shownName(name))
			shown++
		}
		for _, problem := range append(problems, instructionProblems...) {
			fmt.Fprintf(out, "%s\tunreadable\t%v\n", shownName(proxy), problem)
		}
	}
	if shown == 0 {
		fmt.Fprintln(out, "Nothing is waiting for review.")
	}
	return nil
}

func driftShow(out io.Writer, review *drift.Review, f driftFlags, fingerprint string) error {
	snapshot, err := activeSet(f.store)
	if err != nil {
		return err
	}
	view, ok := snapshot.Drift(f.proxy)
	if !ok {
		return fmt.Errorf("proxy %q is not under drift review in the active set", f.proxy)
	}
	var b strings.Builder
	if f.instructions {
		entry, err := review.InstructionsEntry(f.proxy, fingerprint)
		if err != nil {
			return err
		}
		approved, _ := snapshot.Instructions(f.proxy)
		_, invisible, lookAlike := visible(entry.Instructions)
		fmt.Fprintf(&b, "Instructions of %s\nFingerprint: %s\nFirst seen: %s on %s\n", shownName(f.proxy), fingerprint,
			entry.FirstSeen.Format(time.RFC3339), shownName(entry.Gateway))
		writeStatus(&b, view.RejectedInstructions(fingerprint), policy.InstructionsFingerprint(approved) == fingerprint)
		writeCounts(&b, invisible, lookAlike)
		b.WriteString("\nChanges from the approved instructions:\n")
		lineDiff(&b, approved, entry.Instructions)
		_, err = io.WriteString(out, b.String())
		return err
	}
	entry, err := review.Tool(f.proxy, f.tool, fingerprint)
	if err != nil {
		return err
	}
	approvedFingerprint, approved, isApproved := view.Approved(f.tool)
	invisible, lookAlike := hidden(entry.Definition)
	kind := "New tool"
	if isApproved {
		kind = "Changed tool"
	}
	fmt.Fprintf(&b, "%s %s on %s\nFingerprint: %s\nFirst seen: %s on %s\n", kind, shownName(f.tool), shownName(f.proxy), fingerprint,
		entry.FirstSeen.Format(time.RFC3339), shownName(entry.Gateway))
	writeStatus(&b, view.Rejected(f.tool, fingerprint), approvedFingerprint == fingerprint)
	if newest, found, err := review.Newest(f.proxy, f.tool, view.Upstream()); err != nil {
		fmt.Fprintf(&b, "Latest declarations: %v\n", err)
	} else if found && newest.Fingerprint != fingerprint {
		b.WriteString("Gateways have since seen the upstream declare a different definition.\n")
	}
	writeCounts(&b, invisible, lookAlike)
	if !isApproved {
		hints, err := renameHints(review, view, f.proxy, entry.Definition)
		if err != nil {
			return err
		}
		for _, name := range hints {
			fmt.Fprintf(&b, "This may be a rename of %s, which is approved but no longer declared.\n", shownName(name))
		}
	}
	if isApproved {
		b.WriteString("\nChanges from the approved definition:\n")
		b.WriteString(definitionDiff(jsontext.Value(approved), entry.Definition))
	}
	b.WriteString("\nDefinition:\n")
	b.WriteString(indented(entry.Definition))
	b.WriteString("\n")
	_, err = io.WriteString(out, b.String())
	return err
}

func writeStatus(b *strings.Builder, rejected, approved bool) {
	switch {
	case approved:
		b.WriteString("The active set already approves it.\n")
	case rejected:
		b.WriteString("The active set already rejects it.\n")
	}
}

func writeCounts(b *strings.Builder, invisible, lookAlike int) {
	if invisible > 0 {
		fmt.Fprintf(b, "Warning: contains %d invisible character(s), written as ⟨U+XXXX⟩.\n", invisible)
	}
	if lookAlike > 0 {
		fmt.Fprintf(b, "Warning: contains %d look-alike character(s), each followed by ⟨U+XXXX⟩.\n", lookAlike)
	}
}

// renameHints returns approved tools no gateway sees the upstream declare
// any more that take the same input or have the same description as a new
// tool.
func renameHints(review *drift.Review, view policy.DriftView, proxy string, definition jsontext.Value) ([]string, error) {
	missing, err := missingTools(review, view, proxy)
	if err != nil {
		return nil, err
	}
	proposed := object(definition)
	var hints []string
	for _, name := range missing {
		_, approved, _ := view.Approved(name)
		old := object(jsontext.Value(approved))
		sameSchema := proposed["inputSchema"] != nil && canonical(old["inputSchema"]) == canonical(proposed["inputSchema"])
		sameDescription := proposed["description"] != nil && canonical(old["description"]) == canonical(proposed["description"])
		if sameSchema || sameDescription {
			hints = append(hints, name)
		}
	}
	return hints, nil
}

// decision is one approval or rejection to make in a new set.
type decision struct {
	proxy, tool  string
	instructions bool
	fingerprint  string
	definition   jsontext.Value
	text         string
	approve      bool
}

func driftDecide(out io.Writer, review *drift.Review, f driftFlags, fingerprint string, approve bool, now func() time.Time) error {
	pointer, err := policy.ReadPointer(f.store)
	if err != nil {
		return err
	}
	d := decision{proxy: f.proxy, tool: f.tool, instructions: f.instructions, fingerprint: fingerprint, approve: approve}
	if f.instructions {
		entry, err := review.InstructionsEntry(f.proxy, fingerprint)
		if err != nil {
			return err
		}
		d.text = entry.Instructions
	} else {
		entry, err := review.Tool(f.proxy, f.tool, fingerprint)
		if err != nil {
			return err
		}
		d.definition = entry.Definition
	}
	verb := "reject"
	if approve {
		verb = "approve"
	}
	label := f.label
	if label == "" {
		label = fmt.Sprintf("drift %s %s %s", verb, describe(d), fingerprint[:12])
	}
	set, err := applyDecisions(f.store, pointer.Set, label, now, []decision{d})
	if err != nil {
		return err
	}
	fmt.Fprintln(out, set)
	removeEntries(out, review, []decision{d})
	return nil
}

func describe(d decision) string {
	if d.instructions {
		return d.proxy + " instructions"
	}
	return d.proxy + "/" + d.tool
}

// applyDecisions writes decisions into a new set made from the active one,
// under the store's lock, and makes it active. The decisions were made
// against the set named base; if another set became active since, nothing is
// changed, so a decision never overrides one the reviewer did not see.
func applyDecisions(store, base, label string, now func() time.Time, decisions []decision) (string, error) {
	return policy.Revise(store, label, now, func(set string, active *policy.Snapshot, files map[string][]byte) error {
		if set != base {
			return fmt.Errorf("the active set changed to %s while you reviewed; nothing was changed, so review again", set)
		}
		var inventory map[string]map[string]jsontext.Value
		if err := jsonv2.Unmarshal(files["approved_tools.json"], &inventory); err != nil {
			return fmt.Errorf("approved_tools.json: %w", err)
		}
		var instructions map[string]string
		if err := jsonv2.Unmarshal(files["approved_instructions.json"], &instructions); err != nil {
			return fmt.Errorf("approved_instructions.json: %w", err)
		}
		if instructions == nil {
			instructions = map[string]string{}
		}
		for _, d := range decisions {
			view, ok := active.Drift(d.proxy)
			if !ok {
				return fmt.Errorf("proxy %q is not under drift review in the active set", d.proxy)
			}
			if err := apply(inventory[d.proxy], instructions, active, view, d); err != nil {
				return fmt.Errorf("%s: %w", describe(d), err)
			}
		}
		var err error
		if files["approved_tools.json"], err = marshalIndented(inventory); err != nil {
			return err
		}
		files["approved_instructions.json"], err = marshalIndented(instructions)
		return err
	})
}

// apply makes one decision in a proxy's inventory and the approved
// instructions.
func apply(proxy map[string]jsontext.Value, instructions map[string]string, active *policy.Snapshot, view policy.DriftView, d decision) error {
	var settings map[string]jsontext.Value
	if err := jsonv2.Unmarshal(proxy["drift"], &settings); err != nil {
		return err
	}
	if settings == nil {
		settings = map[string]jsontext.Value{}
	}
	if d.instructions {
		approved, _ := active.Instructions(d.proxy)
		if d.approve {
			instructions[d.proxy] = d.text
		} else if policy.InstructionsFingerprint(approved) == d.fingerprint {
			return errors.New("these are the approved instructions")
		}
		var rejected []string
		if err := jsonv2.Unmarshal(orNull(settings["rejectedInstructions"]), &rejected); err != nil {
			return err
		}
		rejected = setMember(rejected, d.fingerprint, !d.approve)
		return setDrift(proxy, settings, "rejectedInstructions", rejected)
	}
	var tools map[string]map[string]jsontext.Value
	if err := jsonv2.Unmarshal(proxy["tools"], &tools); err != nil {
		return err
	}
	if d.approve {
		if tools[d.tool] == nil {
			tools[d.tool] = map[string]jsontext.Value{}
		}
		tools[d.tool]["definition"] = d.definition
	} else if approved, _, _ := view.Approved(d.tool); approved == d.fingerprint {
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
	if rejected[d.tool] = setMember(rejected[d.tool], d.fingerprint, !d.approve); len(rejected[d.tool]) == 0 {
		delete(rejected, d.tool)
	}
	return setDrift(proxy, settings, "rejectedTools", rejected)
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

// removeEntries removes the review entries of decisions now in the active
// set. The set already settles them, so a failure only leaves an entry that
// prune can remove later.
func removeEntries(out io.Writer, review *drift.Review, decisions []decision) {
	for _, d := range decisions {
		var err error
		if d.instructions {
			err = review.RemoveInstructions(d.proxy, d.fingerprint)
		} else {
			err = review.RemoveTool(d.proxy, d.tool, d.fingerprint)
		}
		if err != nil {
			fmt.Fprintf(out, "Warning: could not remove the review entry for %s: %v; drift prune removes it later.\n", describe(d), err)
		}
	}
}

func driftApproveAll(out io.Writer, review *drift.Review, f driftFlags, now func() time.Time) error {
	snapshot, err := activeSet(f.store)
	if err != nil {
		return err
	}
	view, ok := snapshot.Drift(f.proxy)
	if !ok {
		return fmt.Errorf("proxy %q is not under drift review in the active set", f.proxy)
	}
	tools, problems, err := pendingTools(review, view, f.proxy)
	if err != nil {
		return err
	}
	instructions, instructionProblems, err := pendingInstructions(review, snapshot, view, f.proxy)
	if err != nil {
		return err
	}
	for _, problem := range append(problems, instructionProblems...) {
		fmt.Fprintf(out, "Skipped: %v\n", problem)
	}
	var decisions []decision
	for _, t := range tools {
		// Only what gateways saw the upstream declare last is adopted; an
		// older definition would be refused at once anyway.
		if t.latest {
			decisions = append(decisions, decision{proxy: f.proxy, tool: t.entry.Tool, fingerprint: t.entry.Fingerprint, definition: t.entry.Definition, approve: true})
		}
	}
	switch len(instructions) {
	case 0:
	case 1:
		decisions = append(decisions, decision{proxy: f.proxy, instructions: true, fingerprint: instructions[0].Fingerprint, text: instructions[0].Instructions, approve: true})
	default:
		fmt.Fprintf(out, "Skipped: %d different instructions are waiting; approve one with drift approve -instructions.\n", len(instructions))
	}
	for _, d := range decisions {
		fmt.Fprintf(out, "%s\t%s\n", describe(d), d.fingerprint)
	}
	if f.count < 0 {
		return fmt.Errorf("%d change(s) would be approved; review them with drift show, then run again with -count %d", len(decisions), len(decisions))
	}
	if f.count != len(decisions) {
		return fmt.Errorf("%d change(s) are waiting, not %d; nothing was approved", len(decisions), f.count)
	}
	if len(decisions) == 0 {
		fmt.Fprintln(out, "Nothing to approve.")
		return nil
	}
	label := f.label
	if label == "" {
		label = fmt.Sprintf("drift approve-all %s (%d)", f.proxy, len(decisions))
	}
	set, err := applyDecisions(f.store, snapshot.Version, label, now, decisions)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, set)
	removeEntries(out, review, decisions)
	return nil
}

func driftPrune(out io.Writer, review *drift.Review, f driftFlags) error {
	snapshot, err := activeSet(f.store)
	if err != nil {
		return err
	}
	removed := 0
	for _, proxy := range snapshot.DriftProxies() {
		view, _ := snapshot.Drift(proxy)
		entries, _, err := review.Tools(proxy)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if approved, _, _ := view.Approved(entry.Tool); approved == entry.Fingerprint || view.Rejected(entry.Tool, entry.Fingerprint) {
				if err := review.RemoveTool(proxy, entry.Tool, entry.Fingerprint); err != nil {
					return err
				}
				removed++
			}
		}
		instructions, _, err := review.Instructions(proxy)
		if err != nil {
			return err
		}
		approved, _ := snapshot.Instructions(proxy)
		for _, entry := range instructions {
			if entry.Fingerprint == policy.InstructionsFingerprint(approved) || view.RejectedInstructions(entry.Fingerprint) {
				if err := review.RemoveInstructions(proxy, entry.Fingerprint); err != nil {
					return err
				}
				removed++
			}
		}
	}
	fmt.Fprintf(out, "Removed %d review entry(ies) the active set settles.\n", removed)
	return nil
}
