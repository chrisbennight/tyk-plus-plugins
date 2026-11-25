package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/driftreview"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
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
		fmt.Fprintf(out, "Removed %d declaration file(s) of gateway %s.\n", removed, driftreview.ShownName(flags.Arg(0)))
		return err
	}
	return fmt.Errorf("unknown drift command %q", command)
}

// localActor is the local user, who the decision log records for decisions
// made with the command line.
// The account comes from the system, not from the environment, which the
// caller controls; an account the system cannot name is recorded by number.
func localActor() policy.Actor {
	name := fmt.Sprintf("uid:%d", os.Getuid())
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	return policy.Actor{Issuer: "local", Subject: name, Name: name}
}

// subject checks that a command names one proxy, either a tool or the
// instructions, and one fingerprint, and returns the fingerprint.
func subject(flags *flag.FlagSet, f driftFlags) (string, error) {
	if f.proxy == "" || (f.tool == "") == !f.instructions || flags.NArg() != 1 {
		return "", errors.New("expects -proxy, either -tool or -instructions, and a fingerprint")
	}
	return flags.Arg(0), nil
}

func driftList(out io.Writer, review *drift.Review, f driftFlags) error {
	snapshot, err := driftreview.ActiveSet(f.store)
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
		tools, problems, err := driftreview.PendingTools(review, view, proxy)
		if err != nil {
			return err
		}
		instructions, instructionProblems, err := driftreview.PendingInstructions(review, snapshot, view, proxy)
		if err != nil {
			return err
		}
		missing, err := driftreview.MissingTools(review, view, proxy)
		if err != nil {
			return err
		}
		for _, t := range tools {
			state := "superseded"
			switch {
			case t.Latest:
				state = "latest"
			case !t.Declared:
				// Entries and declarations are written separately, so an
				// entry can be read before its declaration.
				state = "no declaration yet"
			}
			fmt.Fprintf(out, "%s\t%s\ttool %s\t%s\t%s, first seen %s on %s\n", driftreview.ShownName(proxy), t.Kind, driftreview.ShownName(t.Entry.Tool),
				t.Entry.Fingerprint, state, t.Entry.FirstSeen.Format(time.RFC3339), driftreview.ShownName(t.Entry.Gateway))
			shown++
		}
		for _, entry := range instructions {
			fmt.Fprintf(out, "%s\tchanged\tinstructions\t%s\tfirst seen %s on %s\n", driftreview.ShownName(proxy), entry.Fingerprint,
				entry.FirstSeen.Format(time.RFC3339), driftreview.ShownName(entry.Gateway))
			shown++
		}
		for _, name := range missing {
			fmt.Fprintf(out, "%s\tmissing\ttool %s\t\tno gateway has shared a declaration of it from the reviewed upstream\n", driftreview.ShownName(proxy), driftreview.ShownName(name))
			shown++
		}
		for _, problem := range append(problems, instructionProblems...) {
			fmt.Fprintf(out, "%s\tunreadable\t%s\n", driftreview.ShownName(proxy), driftreview.ShownName(problem.Error()))
		}
	}
	if shown == 0 {
		fmt.Fprintln(out, "Nothing is waiting for review.")
	}
	return nil
}

func driftShow(out io.Writer, review *drift.Review, f driftFlags, fingerprint string) error {
	snapshot, err := driftreview.ActiveSet(f.store)
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
		_, invisible, lookAlike := driftreview.Visible(entry.Instructions)
		fmt.Fprintf(&b, "Instructions of %s\nFingerprint: %s\nFirst seen: %s on %s\n", driftreview.ShownName(f.proxy), fingerprint,
			entry.FirstSeen.Format(time.RFC3339), driftreview.ShownName(entry.Gateway))
		writeStatus(&b, view.RejectedInstructions(fingerprint), policy.InstructionsFingerprint(approved) == fingerprint)
		writeCounts(&b, invisible, lookAlike)
		b.WriteString("\nChanges from the approved instructions:\n")
		driftreview.LineDiff(&b, approved, entry.Instructions)
		_, err = io.WriteString(out, b.String())
		return err
	}
	entry, err := review.Tool(f.proxy, f.tool, fingerprint)
	if err != nil {
		return err
	}
	approvedFingerprint, approved, isApproved := view.Approved(f.tool)
	invisible, lookAlike := driftreview.Hidden(entry.Definition)
	kind := "New tool"
	if isApproved {
		kind = "Changed tool"
	}
	fmt.Fprintf(&b, "%s %s on %s\nFingerprint: %s\nFirst seen: %s on %s\n", kind, driftreview.ShownName(f.tool), driftreview.ShownName(f.proxy), fingerprint,
		entry.FirstSeen.Format(time.RFC3339), driftreview.ShownName(entry.Gateway))
	writeStatus(&b, view.Rejected(f.tool, fingerprint), approvedFingerprint == fingerprint)
	if newest, found, err := review.Newest(f.proxy, f.tool, view.Upstream()); err != nil {
		fmt.Fprintf(&b, "Latest declarations: %s\n", driftreview.ShownName(err.Error()))
	} else if found && newest.Fingerprint != fingerprint {
		b.WriteString("Gateways have since seen the upstream declare a different definition.\n")
	}
	writeCounts(&b, invisible, lookAlike)
	if !isApproved {
		hints, err := driftreview.RenameHints(review, view, f.proxy, entry)
		if err != nil {
			return err
		}
		for _, name := range hints {
			fmt.Fprintf(&b, "This may be a rename of %s, which is approved but has not been declared since.\n", driftreview.ShownName(name))
		}
	}
	if isApproved {
		b.WriteString("\nChanges from the approved definition:\n")
		b.WriteString(driftreview.DefinitionDiff(jsontext.Value(approved), entry.Definition))
	}
	b.WriteString("\nDefinition:\n")
	b.WriteString(driftreview.Indented(entry.Definition))
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

func driftDecide(out io.Writer, review *drift.Review, f driftFlags, fingerprint string, approve bool, now func() time.Time) error {
	pointer, err := policy.ReadPointer(f.store)
	if err != nil {
		return err
	}
	d := driftreview.Decision{Proxy: f.proxy, Tool: f.tool, Instructions: f.instructions, Fingerprint: fingerprint, Approve: approve}
	if f.instructions {
		entry, err := review.InstructionsEntry(f.proxy, fingerprint)
		if err != nil {
			return err
		}
		d.Text = entry.Instructions
	} else {
		entry, err := review.Tool(f.proxy, f.tool, fingerprint)
		if err != nil {
			return err
		}
		d.Definition = entry.Definition
	}
	verb := "reject"
	if approve {
		verb = "approve"
	}
	label := f.label
	if label == "" {
		label = fmt.Sprintf("drift %s %s %s", verb, driftreview.Describe(d), fingerprint[:12])
	}
	set, err := driftreview.Apply(f.store, pointer.Set, label, localActor(), now, []driftreview.Decision{d})
	if err != nil {
		return err
	}
	fmt.Fprintln(out, set)
	return nil
}

func driftApproveAll(out io.Writer, review *drift.Review, f driftFlags, now func() time.Time) error {
	snapshot, err := driftreview.ActiveSet(f.store)
	if err != nil {
		return err
	}
	view, ok := snapshot.Drift(f.proxy)
	if !ok {
		return fmt.Errorf("proxy %q is not under drift review in the active set", f.proxy)
	}
	tools, problems, err := driftreview.PendingTools(review, view, f.proxy)
	if err != nil {
		return err
	}
	instructions, instructionProblems, err := driftreview.PendingInstructions(review, snapshot, view, f.proxy)
	if err != nil {
		return err
	}
	for _, problem := range append(problems, instructionProblems...) {
		fmt.Fprintf(out, "Skipped: %s\n", driftreview.ShownName(problem.Error()))
	}
	var decisions []driftreview.Decision
	for _, t := range tools {
		// Only what gateways saw the upstream declare last is adopted; an
		// older definition would be refused at once anyway. A tool the
		// upstream has since withdrawn may be adopted too, but gateways list
		// only tools the upstream declares, so its definition reaches clients
		// only if the upstream declares exactly that definition again.
		if t.Latest {
			decisions = append(decisions, driftreview.Decision{Proxy: f.proxy, Tool: t.Entry.Tool, Fingerprint: t.Entry.Fingerprint, Definition: t.Entry.Definition, Approve: true})
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
		decisions = append(decisions, driftreview.Decision{Proxy: f.proxy, Instructions: true, Fingerprint: instructions[0].Fingerprint, Text: instructions[0].Instructions, Approve: true})
	default:
		fmt.Fprintf(out, "Skipped: %d different instructions are waiting; approve one with drift approve -instructions.\n", len(instructions))
	}
	for _, d := range decisions {
		fmt.Fprintf(out, "%s\t%s\n", driftreview.Describe(d), d.Fingerprint)
		if d.Instructions {
			// Instructions reach clients as approved text, so the text
			// itself is shown, not just its fingerprint.
			shown, _, _ := driftreview.Visible(d.Text)
			fmt.Fprintf(out, "%s\n", shown)
		}
	}
	code := driftreview.Confirmation(snapshot.Version, decisions)
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
	set, err := driftreview.Apply(f.store, snapshot.Version, label, localActor(), now, decisions)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, set)
	return nil
}

// driftPrune removes settled entries while holding the store's lock, so a
// rollback cannot make an entry waiting again while it is being removed.
func driftPrune(out io.Writer, review *drift.Review, f driftFlags) error {
	removed := 0
	err := policy.Locked(f.store, func(_ string, snapshot *policy.Snapshot) error {
		var err error
		removed, err = driftreview.PruneSettled(review, snapshot)
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Removed %d review entry(ies) the active set settles.\n", removed)
	return nil
}
