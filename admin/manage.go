package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/driftreview"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

// historyRow is one decision on the History page.
type historyRow struct {
	Time, Who, Issuer, Action, Subject, Fingerprint, Set, Base, Label string
}

func (s *server) history(w http.ResponseWriter, r *http.Request, sess *session) {
	pointer, err := policy.ReadPointer(s.cfg.store)
	if err != nil {
		s.fail(w, sess, http.StatusServiceUnavailable, "The policy store's active pointer cannot be read.")
		return
	}
	entries, logErr := policy.ReadLog(s.cfg.store)
	rows := make([]historyRow, 0, len(entries))
	for _, e := range slices.Backward(entries) {
		subject := "the active set"
		switch {
		case e.Instructions:
			subject = driftreview.ShownName(e.Proxy) + " instructions"
		case e.Tool != "":
			subject = driftreview.ShownName(e.Proxy) + "/" + driftreview.ShownName(e.Tool)
		}
		// People's names and labels are prose, so only invisible characters
		// and mixed-script words are marked, not every accented letter.
		rows = append(rows, historyRow{Time: e.Time, Who: driftreview.VisibleLine(firstOf(e.Actor.Name, e.Actor.Subject)),
			Issuer: driftreview.VisibleLine(e.Actor.Issuer), Action: e.Action, Subject: subject, Fingerprint: e.Fingerprint,
			Set: e.Set, Base: e.Base, Label: driftreview.VisibleLine(e.Label)})
	}
	data := map[string]any{"Rows": rows, "Set": pointer.Set, "Previous": pointer.Previous, "Promoted": pointer.PromotedAt,
		"Done": doneMessage(r.URL.Query().Get("done"))}
	if logErr != nil {
		data["Problem"] = driftreview.ShownName(logErr.Error())
	}
	if pointer.Previous != "" {
		if manifest, _, err := policy.ReadSet(s.cfg.store, pointer.Previous); err == nil {
			data["PreviousLabel"] = manifest.Label
		}
	}
	s.render(w, "history", s.page(sess, "History", data))
}

// rollback makes the previous set active again, provided the set the page
// showed is still the active one.
func (s *server) rollback(w http.ResponseWriter, r *http.Request, sess *session) {
	set, err := policy.Rollback(s.cfg.store, r.PostFormValue("base"), r.PostFormValue("target"), r.PostFormValue("promoted"), sess.actor, s.now)
	switch {
	case errors.Is(err, policy.ErrMoved):
		http.Redirect(w, r, s.auth.link("/history?done=stale"), http.StatusSeeOther)
		return
	case err != nil:
		slog.Error("A rollback failed", "issuer", sess.actor.Issuer, "subject", sess.actor.Subject, "error", err)
		s.fail(w, sess, http.StatusInternalServerError, driftreview.ShownName(err.Error()))
		return
	}
	slog.Info("Rolled back", "set", set, "issuer", sess.actor.Issuer, "subject", sess.actor.Subject)
	http.Redirect(w, r, s.auth.link("/history?done=rolled-back"), http.StatusSeeOther)
}

// toolNames lists the proxy's tools for the cross-tool reference flag: the
// ones the active set reviews and the new ones waiting for review, so a new
// tool that mentions another new tool is flagged too.
func toolNames(review *drift.Review, view policy.DriftView, proxy string) []string {
	names := slices.Clone(view.Tools())
	pending, _, _ := driftreview.PendingTools(review, view, proxy)
	for _, t := range pending {
		if !slices.Contains(names, t.Entry.Tool) {
			names = append(names, t.Entry.Tool)
		}
	}
	return names
}

// permitChecks counts the activation checks of a set that expect a proxy's
// tool to be permitted.
func (s *server) permitChecks(set, proxy, tool string) int {
	snapshot, _, err := policy.LoadSet(s.cfg.store, set)
	if err != nil {
		return 0
	}
	_, contents, err := policy.ReadSet(s.cfg.store, set)
	if err != nil {
		return 0
	}
	view, _ := snapshot.Drift(proxy)
	found, _ := driftreview.PermitChecks(contents["checks.json"], proxy, tool, view.Upstream())
	return len(found)
}

// sameActivation reports whether the activation a form was made against,
// its set and the time it became active, is still in force. A roll back can
// make the same set active again, so the set alone does not identify it.
func (s *server) sameActivation(r *http.Request) bool {
	pointer, err := policy.ReadPointer(s.cfg.store)
	return err == nil && pointer.Set == r.PostFormValue("base") && pointer.PromotedAt == r.PostFormValue("promoted")
}

// revoke withdraws a tool's approved definition, the one the page showed.
func (s *server) revoke(w http.ResponseWriter, r *http.Request, sess *session) {
	proxy, tool, fingerprint := r.PostFormValue("proxy"), r.PostFormValue("tool"), r.PostFormValue("fingerprint")
	label := fmt.Sprintf("dashboard revoke %s %s", driftreview.Describe(driftreview.Decision{Proxy: proxy, Tool: tool}), short(fingerprint))
	back := s.auth.link("/tools?proxy=" + url.QueryEscape(proxy))
	if !s.sameActivation(r) {
		http.Redirect(w, r, back+"&done=stale", http.StatusSeeOther)
		return
	}
	removeChecks := r.PostFormValue("remove_checks") == "1"
	if !removeChecks {
		// Activation checks that expect the tool to be permitted refuse a
		// set without its approval; the reviewer decides whether they go.
		if n := s.permitChecks(r.PostFormValue("base"), proxy, tool); n > 0 {
			s.fail(w, sess, http.StatusConflict, fmt.Sprintf("%d activation check(s) expect calls to this tool to be permitted, so its approval cannot be revoked while they stay. Tick the box to remove them with it, or change them with cedar-policy promote.", n))
			return
		}
	} else {
		label += " and its permit checks"
	}
	set, err := driftreview.Revoke(s.cfg.store, r.PostFormValue("base"), label, sess.actor, s.now, proxy, tool, fingerprint, removeChecks)
	switch {
	case errors.Is(err, driftreview.ErrStale):
		http.Redirect(w, r, back+"&done=stale", http.StatusSeeOther)
		return
	case err != nil:
		slog.Error("A revocation failed", "proxy", proxy, "tool", tool, "fingerprint", fingerprint, "issuer", sess.actor.Issuer, "subject", sess.actor.Subject, "error", err)
		s.fail(w, sess, http.StatusInternalServerError, driftreview.ShownName(err.Error()))
		return
	}
	slog.Info("Revoked", "proxy", proxy, "tool", tool, "fingerprint", fingerprint, "set", set, "issuer", sess.actor.Issuer, "subject", sess.actor.Subject)
	http.Redirect(w, r, back+"&done=revoked", http.StatusSeeOther)
}

// item is one waiting change named in a bulk form: a tool definition or
// instructions, by fingerprint.
type item struct {
	Tool         string
	Instructions bool
	Fingerprint  string
}

// encode writes an item as a form value; tool names are base64url-encoded,
// so any name survives.
func (i item) encode() string {
	if i.Instructions {
		return "i." + i.Fingerprint
	}
	return "t." + i.Fingerprint + "." + base64.RawURLEncoding.EncodeToString([]byte(i.Tool))
}

func decodeItem(value string) (item, bool) {
	kind, rest, _ := strings.Cut(value, ".")
	switch kind {
	case "i":
		return item{Instructions: true, Fingerprint: rest}, rest != ""
	case "t":
		fp, encoded, ok := strings.Cut(rest, ".")
		tool, err := base64.RawURLEncoding.DecodeString(encoded)
		return item{Tool: string(tool), Fingerprint: fp}, ok && err == nil && fp != "" && len(tool) > 0
	}
	return item{}, false
}

// candidate is a selected change with the content its decision applies to
// and its advisory flags.
type candidate struct {
	item
	Value, Shown string
	Flags        []driftreview.Flag
	decision     driftreview.Decision
}

// skippedItem is a selected change a bulk decision leaves out, and why.
type skippedItem struct {
	Shown, Fingerprint, Reason string
}

// candidates reads the selected changes a bulk decision can apply to, and
// says why each other selection is left out: it is no longer waiting, or
// the change page's rules refuse to approve it here.
func candidates(review *drift.Review, snapshot *policy.Snapshot, view policy.DriftView, proxy string, values []string, approve bool) ([]candidate, []skippedItem) {
	approvedText, _ := snapshot.Instructions(proxy)
	names := toolNames(review, view, proxy)
	var out []candidate
	var skipped []skippedItem
	// A batch approves each tool, and the instructions, at most once, and
	// decides each fingerprint at most once.
	decided := map[string]bool{}
	for _, value := range values {
		it, ok := decodeItem(value)
		if !ok {
			skipped = append(skipped, skippedItem{Shown: "(unreadable selection)", Reason: "it does not name a change"})
			continue
		}
		shown := driftreview.ShownName(it.Tool)
		if it.Instructions {
			shown = "instructions"
		}
		skip := func(reason string) {
			skipped = append(skipped, skippedItem{Shown: shown, Fingerprint: it.Fingerprint, Reason: reason})
		}
		key := "tool:" + it.Tool
		if it.Instructions {
			key = "instructions"
		}
		if !approve {
			key += ":" + it.Fingerprint
		}
		if decided[key] || decided["fingerprint:"+key+":"+it.Fingerprint] {
			skip("another selected version is already decided in this batch")
			continue
		}
		c := candidate{item: it, Value: value, Shown: shown}
		d := driftreview.Decision{Proxy: proxy, Tool: it.Tool, Instructions: it.Instructions, Fingerprint: it.Fingerprint, Approve: approve}
		if it.Instructions {
			entry, err := review.InstructionsEntry(proxy, it.Fingerprint)
			if err != nil || policy.InstructionsFingerprint(approvedText) == it.Fingerprint || view.RejectedInstructions(it.Fingerprint) {
				skip("it is no longer waiting")
				continue
			}
			d.Text = entry.Instructions
			c.Flags = driftreview.Flags(nil, entry.Instructions, names)
		} else {
			entry, err := review.Tool(proxy, it.Tool, it.Fingerprint)
			approvedFP, _, _ := view.Approved(it.Tool)
			if err != nil || approvedFP == it.Fingerprint || view.Rejected(it.Tool, it.Fingerprint) {
				skip("it is no longer waiting")
				continue
			}
			if approve && driftreview.Current(review, view, proxy, it.Tool, it.Fingerprint) != nil {
				// Only what gateways last saw the upstream declare, as on
				// the change page.
				skip("it is not what gateways last saw the upstream declare")
				continue
			}
			d.Definition = entry.Definition
			c.Flags = driftreview.Flags(entry.Definition, "", driftreview.OtherTools(names, it.Tool))
		}
		if approve && max(len(d.Definition), len(d.Text)) > longDefinition {
			// Long text must be opened in full on its change page before
			// it is approved, so it is not approved in bulk.
			skip("it is long, so open it in full and approve it on its change page")
			continue
		}
		decided[key] = true
		decided["fingerprint:"+key+":"+it.Fingerprint] = true
		c.decision = d
		out = append(out, c)
	}
	return out, skipped
}

// bulkReview shows exactly what a bulk decision would apply to, before it is
// made: each change with its flags, and the count.
func (s *server) bulkReview(w http.ResponseWriter, r *http.Request, sess *session) {
	st, view, proxy, ok := s.proxyForm(w, r, sess)
	if !ok {
		return
	}
	defer st.review.Close()
	action := r.PostFormValue("action")
	if action != "approve" && action != "reject" {
		s.fail(w, sess, http.StatusBadRequest, "Unknown decision.")
		return
	}
	if !s.sameActivation(r) {
		// The selection was made against an activation no longer in force.
		http.Redirect(w, r, s.auth.link("/queue?proxy="+url.QueryEscape(proxy))+"&done=stale", http.StatusSeeOther)
		return
	}
	cands, skipped := candidates(st.review, st.snapshot, view, proxy, r.PostForm["item"], action == "approve")
	flagged := 0
	for _, c := range cands {
		if len(c.Flags) > 0 {
			flagged++
		}
	}
	s.render(w, "bulk", s.page(sess, "Confirm", map[string]any{
		"Proxy": proxy, "ProxyShown": driftreview.ShownName(proxy), "Action": action, "Items": cands,
		"Count": len(cands), "Flagged": flagged, "Unflagged": len(cands) - flagged, "Skipped": len(skipped), "SkippedItems": skipped, "Base": st.set, "Promoted": st.promoted,
	}))
}

// bulkDecide makes the decision confirmed on the bulk page. Flagged changes
// are included only when the reviewer confirmed them separately; changes
// that are no longer waiting are skipped and counted.
func (s *server) bulkDecide(w http.ResponseWriter, r *http.Request, sess *session) {
	st, view, proxy, ok := s.proxyForm(w, r, sess)
	if !ok {
		return
	}
	defer st.review.Close()
	action := r.PostFormValue("action")
	if action != "approve" && action != "reject" {
		s.fail(w, sess, http.StatusBadRequest, "Unknown decision.")
		return
	}
	cands, skipped := candidates(st.review, st.snapshot, view, proxy, r.PostForm["item"], action == "approve")
	includeFlagged := r.PostFormValue("include_flagged") == "1"
	// Selections the confirmation page already left out are counted too, so
	// the result accounts for every selection.
	earlier, _ := strconv.Atoi(r.PostFormValue("skipped"))
	earlier = max(earlier, 0)
	var decisions []driftreview.Decision
	left := 0
	for _, c := range cands {
		if len(c.Flags) > 0 && !includeFlagged {
			left++
			continue
		}
		decisions = append(decisions, c.decision)
	}
	back := s.auth.link("/queue?proxy=" + url.QueryEscape(proxy))
	if len(decisions) > 0 {
		label := fmt.Sprintf("dashboard bulk %s on %s (%d)", action, driftreview.ShownName(proxy), len(decisions))
		if !s.sameActivation(r) {
			http.Redirect(w, r, back+"&done=stale", http.StatusSeeOther)
			return
		}
		set, err := driftreview.Apply(s.cfg.store, r.PostFormValue("base"), label, sess.actor, s.now, decisions)
		switch {
		case errors.Is(err, driftreview.ErrStale):
			http.Redirect(w, r, back+"&done=stale", http.StatusSeeOther)
			return
		case err != nil:
			slog.Error("A bulk decision failed", "action", action, "proxy", proxy, "count", len(decisions), "issuer", sess.actor.Issuer, "subject", sess.actor.Subject, "error", err)
			s.fail(w, sess, http.StatusInternalServerError, driftreview.ShownName(err.Error()))
			return
		}
		slog.Info("Bulk decision made", "action", action, "proxy", proxy, "count", len(decisions), "set", set,
			"issuer", sess.actor.Issuer, "subject", sess.actor.Subject)
	}
	done := map[string]string{"approve": "bulk-approved", "reject": "bulk-rejected"}[action]
	http.Redirect(w, r, fmt.Sprintf("%s&done=%s&n=%d&skipped=%d&left=%d", back, done, len(decisions), len(skipped)+earlier, left), http.StatusSeeOther)
}

// bulkMessage builds the message after a bulk decision from counts only, so
// the page never echoes text from its URL.
func bulkMessage(q url.Values) string {
	verb := map[string]string{"bulk-approved": "Approved", "bulk-rejected": "Rejected"}[q.Get("done")]
	if verb == "" {
		return ""
	}
	count := func(name string) int { n, _ := strconv.Atoi(q.Get(name)); return max(n, 0) }
	msg := fmt.Sprintf("%s %d.", verb, count("n"))
	if n := count("skipped"); n > 0 {
		msg += fmt.Sprintf(" Skipped %d that were no longer waiting or that the approval rules leave to their change pages.", n)
	}
	if n := count("left"); n > 0 {
		msg += fmt.Sprintf(" Left %d flagged change(s) waiting, as they were not confirmed.", n)
	}
	return msg
}

// proxyForm is proxy for a form, which names the proxy in its body.
func (s *server) proxyForm(w http.ResponseWriter, r *http.Request, sess *session) (*state, policy.DriftView, string, bool) {
	q := r.URL.Query()
	q.Set("proxy", r.PostFormValue("proxy"))
	r.URL.RawQuery = q.Encode()
	return s.proxy(w, r, sess)
}

// gatewayRow is one gateway on the Maintenance page.
type gatewayRow struct {
	Name, Shown string
	Seen        time.Time
}

func (s *server) maintenance(w http.ResponseWriter, r *http.Request, sess *session) {
	review, err := drift.OpenReview(s.cfg.pending)
	if err != nil {
		s.fail(w, sess, http.StatusServiceUnavailable, "The shared drift directory cannot be opened.")
		return
	}
	defer review.Close()
	var rows []gatewayRow
	if seen, err := review.Gateways(); err == nil {
		for name, at := range seen {
			rows = append(rows, gatewayRow{Name: name, Shown: driftreview.ShownName(name), Seen: at})
		}
		slices.SortFunc(rows, func(a, b gatewayRow) int { return a.Seen.Compare(b.Seen) })
	}
	data := map[string]any{"Gateways": rows, "Done": maintenanceMessage(r.URL.Query())}
	s.render(w, "maintenance", s.page(sess, "Maintenance", data))
}

func maintenanceMessage(q url.Values) string {
	n, _ := strconv.Atoi(q.Get("n"))
	switch q.Get("done") {
	case "pruned":
		return fmt.Sprintf("Removed %d review entries the active set settles.", max(n, 0))
	case "retired":
		return fmt.Sprintf("Removed %d declaration files of the retired gateway.", max(n, 0))
	case "unconfirmed":
		return "Nothing was removed: confirm that the gateway will not run again."
	}
	return ""
}

// prune removes the review entries the active set settles, holding the
// store's lock so no set becomes active meanwhile.
func (s *server) prune(w http.ResponseWriter, r *http.Request, sess *session) {
	review, err := drift.OpenReview(s.cfg.pending)
	if err != nil {
		s.fail(w, sess, http.StatusServiceUnavailable, "The shared drift directory cannot be opened.")
		return
	}
	defer review.Close()
	removed := 0
	err = policy.Locked(s.cfg.store, func(_ string, snapshot *policy.Snapshot) error {
		var err error
		removed, err = driftreview.PruneSettled(review, snapshot)
		return err
	})
	if err != nil {
		// Entries are removed one at a time, so some may be gone already.
		slog.Error("Pruning failed", "removed", removed, "issuer", sess.actor.Issuer, "subject", sess.actor.Subject, "error", err)
		s.fail(w, sess, http.StatusInternalServerError, driftreview.ShownName(err.Error()))
		return
	}
	slog.Info("Pruned settled review entries", "removed", removed, "issuer", sess.actor.Issuer, "subject", sess.actor.Subject)
	http.Redirect(w, r, s.auth.link(fmt.Sprintf("/maintenance?done=pruned&n=%d", removed)), http.StatusSeeOther)
}

// retire removes a gateway's declarations, once the reviewer confirms it
// will not run again: a running gateway's sightings would be lost until it
// lists tools again.
func (s *server) retire(w http.ResponseWriter, r *http.Request, sess *session) {
	if r.PostFormValue("confirm") != "1" {
		http.Redirect(w, r, s.auth.link("/maintenance?done=unconfirmed"), http.StatusSeeOther)
		return
	}
	review, err := drift.OpenReview(s.cfg.pending)
	if err != nil {
		s.fail(w, sess, http.StatusServiceUnavailable, "The shared drift directory cannot be opened.")
		return
	}
	defer review.Close()
	gateway := r.PostFormValue("gateway")
	removed, err := review.Retire(gateway)
	if err != nil {
		slog.Error("Retiring a gateway failed", "gateway", gateway, "removed", removed, "issuer", sess.actor.Issuer, "subject", sess.actor.Subject, "error", err)
		s.fail(w, sess, http.StatusInternalServerError, driftreview.ShownName(err.Error()))
		return
	}
	slog.Info("Retired a gateway", "gateway", gateway, "removed", removed, "issuer", sess.actor.Issuer, "subject", sess.actor.Subject)
	http.Redirect(w, r, s.auth.link(fmt.Sprintf("/maintenance?done=retired&n=%d", removed)), http.StatusSeeOther)
}
