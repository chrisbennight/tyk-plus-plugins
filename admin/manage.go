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
	data := map[string]any{"Rows": rows, "Set": pointer.Set, "Previous": pointer.Previous,
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
	set, err := policy.Rollback(s.cfg.store, r.PostFormValue("base"), r.PostFormValue("target"), sess.actor, s.now)
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

// revoke withdraws a tool's approved definition, the one the page showed.
func (s *server) revoke(w http.ResponseWriter, r *http.Request, sess *session) {
	proxy, tool, fingerprint := r.PostFormValue("proxy"), r.PostFormValue("tool"), r.PostFormValue("fingerprint")
	label := fmt.Sprintf("dashboard revoke %s %s", driftreview.Describe(driftreview.Decision{Proxy: proxy, Tool: tool}), short(fingerprint))
	back := s.auth.link("/tools?proxy=" + url.QueryEscape(proxy))
	set, err := driftreview.Revoke(s.cfg.store, r.PostFormValue("base"), label, sess.actor, s.now, proxy, tool, fingerprint)
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

// candidates reads the selected changes that are still waiting for review.
// A selection that no longer names a waiting change, because it was decided
// or its entry is gone or altered, is counted as skipped, as is a tool
// definition to approve that the upstream has since replaced.
func candidates(review *drift.Review, snapshot *policy.Snapshot, view policy.DriftView, proxy string, values []string, approve bool) ([]candidate, int) {
	approvedText, _ := snapshot.Instructions(proxy)
	// As on the change page, instructions are approved only while one
	// changed text is waiting.
	// When they cannot be counted, none is approved.
	waitingTexts := 0
	if approve {
		texts, _, err := driftreview.PendingInstructions(review, snapshot, view, proxy)
		waitingTexts = len(texts)
		if err != nil {
			waitingTexts = -1
		}
	}
	var out []candidate
	skipped := 0
	// A batch decides each tool, and the instructions, at most once.
	decided := map[string]bool{}
	for _, value := range values {
		it, ok := decodeItem(value)
		key := "tool:" + it.Tool
		if it.Instructions {
			key = "instructions"
		}
		if !ok || decided[key] {
			skipped++
			continue
		}
		decided[key] = true
		c := candidate{item: it, Value: value}
		d := driftreview.Decision{Proxy: proxy, Tool: it.Tool, Instructions: it.Instructions, Fingerprint: it.Fingerprint, Approve: approve}
		if it.Instructions {
			entry, err := review.InstructionsEntry(proxy, it.Fingerprint)
			if err != nil || policy.InstructionsFingerprint(approvedText) == it.Fingerprint || view.RejectedInstructions(it.Fingerprint) || (approve && waitingTexts != 1) {
				skipped++
				continue
			}
			d.Text = entry.Instructions
			c.Shown, c.Flags = "instructions", driftreview.Flags(nil, entry.Instructions, view.Tools())
		} else {
			entry, err := review.Tool(proxy, it.Tool, it.Fingerprint)
			approvedFP, _, _ := view.Approved(it.Tool)
			if err != nil || approvedFP == it.Fingerprint || view.Rejected(it.Tool, it.Fingerprint) {
				skipped++
				continue
			}
			if approve {
				// Only what gateways last saw the upstream declare, as on
				// the change page.
				if driftreview.Current(review, view, proxy, it.Tool, it.Fingerprint) != nil {
					skipped++
					continue
				}
			}
			d.Definition = entry.Definition
			c.Shown = driftreview.ShownName(it.Tool)
			c.Flags = driftreview.Flags(entry.Definition, "", driftreview.OtherTools(view.Tools(), it.Tool))
		}
		if approve && max(len(d.Definition), len(d.Text)) > longDefinition {
			// Long text must be opened in full on its change page before
			// it is approved, so it is not approved in bulk.
			skipped++
			continue
		}
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
	if r.PostFormValue("base") != st.set {
		// The selection was made against a set that is no longer active.
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
		"Count": len(cands), "Flagged": flagged, "Unflagged": len(cands) - flagged, "Skipped": skipped, "Base": st.set,
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
	http.Redirect(w, r, fmt.Sprintf("%s&done=%s&n=%d&skipped=%d&left=%d", back, done, len(decisions), skipped, left), http.StatusSeeOther)
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
		msg += fmt.Sprintf(" Skipped %d that were no longer waiting or had been superseded.", n)
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
		slog.Error("Pruning failed", "error", err)
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
		slog.Error("Retiring a gateway failed", "error", err)
		s.fail(w, sess, http.StatusInternalServerError, driftreview.ShownName(err.Error()))
		return
	}
	slog.Info("Retired a gateway", "gateway", gateway, "removed", removed, "issuer", sess.actor.Issuer, "subject", sess.actor.Subject)
	http.Redirect(w, r, s.auth.link(fmt.Sprintf("/maintenance?done=retired&n=%d", removed)), http.StatusSeeOther)
}
