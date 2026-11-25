package main

import (
	"crypto/sha256"
	"encoding/hex"
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
  cedar-policy drift approve-all -store DIR -pending DIR -proxy NAME [-confirm CODE] [-label TEXT]
      Adopt what a proxy's upstream now declares: approve, for each tool, the
      definition gateways saw last, and the waiting instructions when there
      is only one. Without -confirm it lists them with their count and a
      confirmation code; with that code it approves exactly that list.
  cedar-policy drift prune -store DIR -pending DIR
      Remove review entries the active set already approves or rejects.
  cedar-policy drift retire -pending DIR GATEWAY
      Remove the declarations a gateway shared, once it will not run again.
      A running gateway's sightings would be lost until it lists tools again.
`

// driftFlags are the options the drift commands share.
type driftFlags struct {
	store, pending, proxy, tool, label, confirm string
	instructions                                bool
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
	flags.StringVar(&f.confirm, "confirm", "", "confirmation code approve-all printed for the list it showed")
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
	// declared is whether any gateway has shared a declaration of the tool
	// from the reviewed upstream.
	declared bool
}

// pendingTools returns a proxy's tool entries the active set neither
// approves nor rejects.
func pendingTools(review *drift.Review, view policy.DriftView, proxy string) ([]pendingTool, []error, error) {
	entries, problems, err := review.Tools(proxy)
	if err != nil {
		return nil, nil, err
	}
	var waiting []pendingTool
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
		waiting = append(waiting, pendingTool{entry: entry, kind: kind, declared: declared, latest: declared && fingerprint == entry.Fingerprint})
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
			switch {
			case t.latest:
				state = "latest"
			case !t.declared:
				// Entries and declarations are written separately, so an
				// entry can be read before its declaration.
				state = "no declaration yet"
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
			fmt.Fprintf(out, "%s\tunreadable\t%s\n", shownName(proxy), shownName(problem.Error()))
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
		fmt.Fprintf(&b, "Latest declarations: %s\n", shownName(err.Error()))
	} else if found && newest.Fingerprint != fingerprint {
		b.WriteString("Gateways have since seen the upstream declare a different definition.\n")
	}
	writeCounts(&b, invisible, lookAlike)
	if !isApproved {
		hints, err := renameHints(review, view, f.proxy, entry)
		if err != nil {
			return err
		}
		for _, name := range hints {
			fmt.Fprintf(&b, "This may be a rename of %s, which is approved but has not been declared since.\n", shownName(name))
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

// renameHints returns approved tools that take the same input or have the
// same description as a new tool and that the upstream's latest list no
// longer declares.
func renameHints(review *drift.Review, view policy.DriftView, proxy string, entry drift.ToolEntry) ([]string, error) {
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
		sameSchema := proposed["inputSchema"] != nil && canonical(old["inputSchema"]) == canonical(proposed["inputSchema"])
		sameDescription := proposed["description"] != nil && canonical(old["description"]) == canonical(proposed["description"])
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
	return nil
}

// describe names a decision's subject for a terminal, with hidden
// characters written out, as tool and proxy names come from upstreams and
// operators.
func describe(d decision) string {
	if d.instructions {
		return shownName(d.proxy) + " instructions"
	}
	return shownName(d.proxy) + "/" + shownName(d.tool)
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
		// A definition's fingerprint leaves out its top-level _meta, so the
		// reviewer never approved it; the approved definition has none.
		definition, err := withoutMeta(d.definition)
		if err != nil {
			return err
		}
		tools[d.tool]["definition"] = definition
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
		fmt.Fprintf(out, "Skipped: %s\n", shownName(problem.Error()))
	}
	var decisions []decision
	for _, t := range tools {
		// Only what gateways saw the upstream declare last is adopted; an
		// older definition would be refused at once anyway. A tool the
		// upstream has since withdrawn may be adopted too, but gateways list
		// only tools the upstream declares, so its definition reaches clients
		// only if the upstream declares exactly that definition again.
		if t.latest {
			decisions = append(decisions, decision{proxy: f.proxy, tool: t.entry.Tool, fingerprint: t.entry.Fingerprint, definition: t.entry.Definition, approve: true})
		}
	}
	// Gateways record no sighting of instructions that match the approved
	// text, so a waiting text may have been withdrawn since. Only a proxy
	// with no approved instructions yet adopts them in bulk.
	approvedText, _ := snapshot.Instructions(f.proxy)
	switch {
	case len(instructions) == 0:
	case approvedText != "":
		fmt.Fprintf(out, "Skipped: changed instructions; review them with drift show and approve them with drift approve -instructions.\n")
	case len(instructions) == 1:
		decisions = append(decisions, decision{proxy: f.proxy, instructions: true, fingerprint: instructions[0].Fingerprint, text: instructions[0].Instructions, approve: true})
	default:
		fmt.Fprintf(out, "Skipped: %d different instructions are waiting; approve one with drift approve -instructions.\n", len(instructions))
	}
	for _, d := range decisions {
		fmt.Fprintf(out, "%s\t%s\n", describe(d), d.fingerprint)
		if d.instructions {
			// Instructions reach clients as approved text, so the text
			// itself is shown, not just its fingerprint.
			shown, _, _ := visible(d.text)
			fmt.Fprintf(out, "%s\n", shown)
		}
	}
	code := confirmation(snapshot.Version, decisions)
	if f.confirm == "" {
		return fmt.Errorf("%d change(s) would be approved; review them with drift show, then run again with -confirm %s", len(decisions), code)
	}
	if f.confirm != code {
		return fmt.Errorf("the waiting changes are not the ones confirmed; nothing was approved. %d change(s) are waiting now, with code %s", len(decisions), code)
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
	return nil
}

// confirmation is a code for an exact list of decisions against one active
// set: their count and a digest of the set and of what each approves, so a
// confirmation never covers a list, or a set, that changed after it was
// shown.
func confirmation(set string, decisions []decision) string {
	lines := make([]string, len(decisions))
	for i, d := range decisions {
		lines[i] = fmt.Sprintf("%s\x00%s\x00%t\x00%s", d.proxy, d.tool, d.instructions, d.fingerprint)
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(set + "\n" + strings.Join(lines, "\n")))
	return fmt.Sprintf("%d-%s", len(decisions), hex.EncodeToString(sum[:]))
}

// driftPrune removes settled entries while holding the store's lock, so a
// rollback cannot make an entry waiting again while it is being removed.
func driftPrune(out io.Writer, review *drift.Review, f driftFlags) error {
	removed := 0
	err := policy.Locked(f.store, func(_ string, snapshot *policy.Snapshot) error {
		var err error
		removed, err = pruneSettled(review, snapshot)
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Removed %d review entry(ies) the active set settles.\n", removed)
	return nil
}

func pruneSettled(review *drift.Review, snapshot *policy.Snapshot) (int, error) {
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
