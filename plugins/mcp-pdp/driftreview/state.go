package driftreview

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

// DiffLine is one line of a DefinitionDiff or LineDiff: a heading, or a
// line kept, removed or added.
type DiffLine struct {
	// Op is 'h' for a heading, ' ' for a kept line, '-' for a removed line
	// and '+' for an added one.
	Op   byte
	Text string
}

// ParseDiff splits a diff into lines. Diff lines start with two spaces,
// "- " or "+ "; every other line is a heading. Names and values in headings
// are written on one line, so no heading can start like a diff line.
func ParseDiff(diff string) []DiffLine {
	var lines []DiffLine
	for _, line := range strings.Split(strings.TrimSuffix(diff, "\n"), "\n") {
		switch {
		case line == "":
		case strings.HasPrefix(line, "  "), strings.HasPrefix(line, "- "), strings.HasPrefix(line, "+ "):
			lines = append(lines, DiffLine{Op: line[0], Text: line[2:]})
		default:
			lines = append(lines, DiffLine{Op: 'h', Text: line})
		}
	}
	return lines
}

// ToolState is how gateways treat one tool of a proxy, as the shared
// declarations stand.
type ToolState struct {
	Tool string
	// Approved is the approved definition's fingerprint, or empty.
	Approved string
	// Declared is the definition gateways saw the upstream declare last, or
	// empty when none has been shared or it could not be identified.
	Declared string
	// Seen is when that declaration was received, and Found whether any was.
	Seen  time.Time
	Found bool
	// Callable is whether gateways let calls to the tool reach the rules.
	Callable bool
	// Reason says, in plain words, why calls are refused or allowed.
	Reason string
	// Waiting is the fingerprint of a review entry that resolves the state,
	// if one is waiting.
	Waiting string
	// Problem reports declarations that could not be read.
	Problem error
}

// ToolStates returns, sorted by name, the state of every tool the active set
// reviews for a proxy and every new tool waiting for review. It follows the
// rule gateways apply to calls: a tool must be approved, and the definition
// last declared, where one has been, must be the approved one.
func ToolStates(review *drift.Review, snapshot *policy.Snapshot, proxy string) ([]ToolState, error) {
	view, ok := snapshot.Drift(proxy)
	if !ok {
		return nil, fmt.Errorf("proxy %q is not under drift review in the active set", proxy)
	}
	pending, _, err := PendingTools(review, view, proxy)
	if err != nil {
		return nil, err
	}
	waiting := map[string]string{}
	for _, t := range pending {
		if t.Latest || waiting[t.Entry.Tool] == "" {
			waiting[t.Entry.Tool] = t.Entry.Fingerprint
		}
	}
	names := view.Tools()
	for tool := range waiting {
		if !slices.Contains(names, tool) {
			names = append(names, tool)
		}
	}
	slices.Sort(names)
	states := make([]ToolState, 0, len(names))
	for _, tool := range names {
		s := ToolState{Tool: tool, Waiting: waiting[tool]}
		s.Approved, _, _ = view.Approved(tool)
		newest, found, err := review.Newest(proxy, tool, view.Upstream())
		s.Problem = err
		s.Found, s.Declared, s.Seen = found, newest.Fingerprint, newest.SeenAt
		if s.Approved != "" && s.Waiting != s.Declared {
			// For an approved tool, only an entry for what the upstream
			// declares now resolves a refusal.
			s.Waiting = ""
		}
		switch {
		case err != nil:
			s.Reason = "Refused: the shared declarations of this tool cannot be read."
		case !drift.Shareable(tool, view.Upstream()):
			s.Reason = "Refused: the tool's name or upstream is too long for its declarations to be shared, so gateways refuse its calls."
		case s.Approved == "" && s.Waiting != "":
			s.Reason = "Refused: a new tool waiting for review."
		case s.Approved == "":
			s.Reason = "Refused: no approved definition."
		case !found:
			s.Callable = true
			s.Reason = "Approved; no gateway has shared a declaration of it yet, so gateways decide on approval until they see one."
		case s.Declared == s.Approved:
			s.Callable = true
			s.Reason = "Approved, and the upstream declares the approved definition."
		case s.Declared == "":
			s.Reason = "Refused: the upstream's latest definition could not be identified."
		case view.Rejected(tool, s.Declared):
			s.Reason = "Refused: the upstream declares a definition that was rejected."
		case s.Waiting != "":
			s.Reason = "Refused: the upstream declares a changed definition, waiting for review."
		default:
			s.Reason = "Refused: the upstream declares a changed definition; no review entry has been shared yet."
		}
		states = append(states, s)
	}
	// A gateway that cannot read the declarations of a tool the active set
	// reviews, on any proxy, refuses every call under drift review until it
	// can.
	if where := unreadable(review, snapshot); where != "" {
		for i := range states {
			if states[i].Callable {
				states[i].Callable = false
				states[i].Reason = "Refused: gateways cannot read the shared declarations of " + where + ", so they refuse every call under drift review until they can."
			}
		}
	}
	return states, nil
}

// unreadable names the first tool the active set reviews whose shared
// declarations cannot be read, or returns "".
func unreadable(review *drift.Review, snapshot *policy.Snapshot) string {
	for _, proxy := range snapshot.DriftProxies() {
		view, _ := snapshot.Drift(proxy)
		for _, tool := range view.Tools() {
			if _, _, err := review.Newest(proxy, tool, view.Upstream()); err != nil {
				return ShownName(proxy) + "/" + ShownName(tool)
			}
		}
	}
	return ""
}
