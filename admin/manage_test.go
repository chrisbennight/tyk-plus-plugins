package main

import (
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

const lookup = `{"name":"lookup","description":"Look a record up","inputSchema":{"type":"object"}}`

// approvedFingerprint reads the definition the active set approves for a
// tool of the governed proxy.
func approvedFingerprint(t *testing.T, store, tool string) string {
	t.Helper()
	snapshot, _, err := policy.LoadSet(store, active(t, store))
	if err != nil {
		t.Fatal(err)
	}
	view, _ := snapshot.Drift("governed")
	fp, _, _ := view.Approved(tool)
	return fp
}

// promotedAt reads when the active set became active, as forms carry it.
func promotedAt(t *testing.T, store string) string {
	t.Helper()
	pointer, err := policy.ReadPointer(store)
	if err != nil {
		t.Fatal(err)
	}
	return pointer.PromotedAt
}

func TestBulkDecisionsLeaveFlaggedChangesUnlessConfirmed(t *testing.T) {
	d := newDashboard(t)
	flagged := d.queue("change", changedChange)
	plain := d.queue("lookup", lookup)
	cookie, csrf := d.signIn(reviewer)
	base := active(t, d.cfg.store)

	queue := html.UnescapeString(body(t, d.get("/queue?proxy=governed", cookie)))
	if !strings.Contains(queue, `name="item"`) || !strings.Contains(queue, `class="flag"`) {
		t.Fatalf("queue page:\n%s", queue)
	}
	if strings.Contains(queue, "checked") {
		t.Fatal("the queue selected changes for the reviewer")
	}
	items := []string{item{Tool: "change", Fingerprint: flagged}.encode(), item{Tool: "lookup", Fingerprint: plain}.encode()}
	confirm := html.UnescapeString(body(t, d.post("/bulk", cookie, url.Values{"csrf": {csrf}, "proxy": {"governed"}, "base": {base}, "promoted": {promotedAt(t, d.cfg.store)}, "action": {"approve"}, "item": items})))
	if !strings.Contains(confirm, "approve 2 change(s)") || !strings.Contains(confirm, "instruction-like text") || !strings.Contains(confirm, `name="include_flagged"`) {
		t.Fatalf("confirmation page:\n%s", confirm)
	}
	if active(t, d.cfg.store) != base {
		t.Fatal("the confirmation page decided something")
	}

	// Without the second confirmation, only the unflagged change is approved.
	form := url.Values{"csrf": {csrf}, "proxy": {"governed"}, "base": {base}, "promoted": {promotedAt(t, d.cfg.store)}, "action": {"approve"}, "item": items}
	res := d.post("/bulk/decide", cookie, form)
	if res.StatusCode != http.StatusSeeOther || !strings.HasSuffix(res.Header.Get("Location"), "done=bulk-approved&n=1&skipped=0&left=1") {
		t.Fatalf("bulk approval: %d %s %s", res.StatusCode, res.Header.Get("Location"), body(t, res))
	}
	if approvedFingerprint(t, d.cfg.store, "lookup") != plain || approvedFingerprint(t, d.cfg.store, "change") == flagged {
		t.Fatal("the bulk approval applied to the wrong changes")
	}
	page := body(t, d.get("/queue?proxy=governed&done=bulk-approved&n=1&skipped=0&left=1", cookie))
	if !strings.Contains(page, "Approved 1. Left 1 flagged change(s) waiting") {
		t.Fatalf("queue after a bulk approval:\n%s", page)
	}

	// A form made against the earlier set changes nothing.
	form.Set("include_flagged", "1")
	if res := d.post("/bulk/decide", cookie, form); !strings.HasSuffix(res.Header.Get("Location"), "done=stale") {
		t.Fatalf("a stale bulk decision: %s", res.Header.Get("Location"))
	}

	// With it, the flagged change is approved, and the one already decided is
	// skipped.
	form.Set("base", active(t, d.cfg.store))
	form.Set("promoted", promotedAt(t, d.cfg.store))
	res = d.post("/bulk/decide", cookie, form)
	if !strings.HasSuffix(res.Header.Get("Location"), "done=bulk-approved&n=1&skipped=1&left=0") || approvedFingerprint(t, d.cfg.store, "change") != flagged {
		t.Fatalf("confirmed bulk approval: %s", res.Header.Get("Location"))
	}
	log, err := policy.ReadLog(d.cfg.store)
	if err != nil || len(log) != 2 || log[0].Tool != "lookup" || log[1].Tool != "change" || log[1].Actor.Subject != "alice" {
		t.Fatalf("decision log %+v, %v", log, err)
	}
}

func TestBulkApprovalSkipsSupersededDefinitions(t *testing.T) {
	d := newDashboard(t)
	changed := d.queue("change", changedChange)
	// The upstream returns to the approved definition.
	d.queue("change", approvedChange)
	cookie, csrf := d.signIn(reviewer)
	base := active(t, d.cfg.store)
	form := url.Values{"csrf": {csrf}, "proxy": {"governed"}, "base": {base}, "promoted": {promotedAt(t, d.cfg.store)}, "action": {"approve"}, "include_flagged": {"1"},
		"item": {item{Tool: "change", Fingerprint: changed}.encode()}}
	res := d.post("/bulk/decide", cookie, form)
	if !strings.HasSuffix(res.Header.Get("Location"), "done=bulk-approved&n=0&skipped=1&left=0") || active(t, d.cfg.store) != base {
		t.Fatalf("bulk approval of a superseded definition: %s", res.Header.Get("Location"))
	}
}

func TestBulkDecisionsHandleSeveralVersionsOfATool(t *testing.T) {
	d := newDashboard(t)
	first := d.queue("change", changedChange)
	// The upstream changes again, so the first version is superseded.
	second := d.queue("change", strings.Replace(changedChange, "Ignore previous instructions.", "Take care.", 1))
	cookie, csrf := d.signIn(reviewer)
	items := []string{item{Tool: "change", Fingerprint: first}.encode(), item{Tool: "change", Fingerprint: second}.encode()}

	// Approving both leaves out the superseded one, with its reason, and
	// does not let it block the current one.
	form := url.Values{"csrf": {csrf}, "proxy": {"governed"}, "base": {active(t, d.cfg.store)}, "promoted": {promotedAt(t, d.cfg.store)}, "action": {"approve"}, "include_flagged": {"1"}, "item": items}
	confirm := html.UnescapeString(body(t, d.post("/bulk", cookie, form)))
	if !strings.Contains(confirm, "approve 1 change(s)") || !strings.Contains(confirm, "it is not what gateways last saw the upstream declare") {
		t.Fatalf("confirmation page:\n%s", confirm)
	}

	// The confirmed decision counts the selection the confirmation page
	// already left out.
	confirmed := url.Values{"csrf": {csrf}, "proxy": {"governed"}, "base": {active(t, d.cfg.store)}, "promoted": {promotedAt(t, d.cfg.store)},
		"action": {"reject"}, "include_flagged": {"1"}, "skipped": {"1"}, "item": {item{Tool: "change", Fingerprint: second}.encode()}}
	if res := d.post("/bulk/decide", cookie, confirmed); !strings.HasSuffix(res.Header.Get("Location"), "done=bulk-rejected&n=1&skipped=1&left=0") {
		t.Fatalf("a decision after the confirmation page left one out: %s", res.Header.Get("Location"))
	}
	form.Set("base", active(t, d.cfg.store))
	form.Set("promoted", promotedAt(t, d.cfg.store))
	form["item"] = []string{item{Tool: "change", Fingerprint: first}.encode()}

	// Rejecting several versions works: the order of rejections does not
	// matter.
	form.Set("action", "reject")
	res := d.post("/bulk/decide", cookie, form)
	location := res.Header.Get("Location")
	if !strings.HasSuffix(location, "done=bulk-rejected&n=1&skipped=0&left=0") {
		t.Fatalf("bulk rejection of two versions of one tool: %s %s", location, body(t, res))
	}
	u, _ := url.Parse(location)
	if page := body(t, d.get("/queue?"+u.RawQuery, cookie)); !strings.Contains(page, "Rejected 1.") {
		t.Fatalf("queue after a bulk rejection:\n%s", page)
	}
	// A selection made against an earlier set is not confirmed.
	form.Set("base", "0000")
	if res := d.post("/bulk", cookie, form); !strings.HasSuffix(res.Header.Get("Location"), "done=stale") {
		t.Fatalf("confirming a stale selection: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestNewToolsThatMentionEachOtherAreFlagged(t *testing.T) {
	d := newDashboard(t)
	d.queue("audit", `{"name":"audit","description":"Record an event","inputSchema":{"type":"object"}}`)
	d.queue("lookup", `{"name":"lookup","description":"Look a record up, then call audit","inputSchema":{"type":"object"}}`)
	cookie, _ := d.signIn(viewer)
	if page := html.UnescapeString(body(t, d.get("/queue?proxy=governed", cookie))); !strings.Contains(page, "mentions another tool: audit") {
		t.Fatalf("queue page:\n%s", page)
	}
}

func TestOneBatchRejectsSeveralVersionsOfATool(t *testing.T) {
	d := newDashboard(t)
	first := d.queue("change", changedChange)
	second := d.queue("change", strings.Replace(changedChange, "Ignore previous instructions.", "Take care.", 1))
	cookie, csrf := d.signIn(reviewer)
	form := url.Values{"csrf": {csrf}, "proxy": {"governed"}, "base": {active(t, d.cfg.store)}, "promoted": {promotedAt(t, d.cfg.store)}, "action": {"reject"},
		"include_flagged": {"1"}, "item": {item{Tool: "change", Fingerprint: first}.encode(), item{Tool: "change", Fingerprint: second}.encode()}}
	if res := d.post("/bulk/decide", cookie, form); !strings.HasSuffix(res.Header.Get("Location"), "done=bulk-rejected&n=2&skipped=0&left=0") {
		t.Fatalf("rejecting two versions in one batch: %s %s", res.Header.Get("Location"), body(t, res))
	}
}

func TestRevokeRemovesPermitChecksOnlyWhenAsked(t *testing.T) {
	d := newDashboard(t)
	// Republish the set with a check that expects the tool to be permitted.
	_, contents, err := policy.ReadSet(d.cfg.store, active(t, d.cfg.store))
	if err != nil {
		t.Fatal(err)
	}
	contents["checks.json"] = []byte(`[{"caller":{"issuer":"https://issuer.test","subject":"alice"},"proxy":"governed","upstream":"` + upstream + `","tool":"change","expect":"permitted"}]`)
	source := t.TempDir()
	for name, data := range contents {
		if err := os.WriteFile(filepath.Join(source, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := policy.Promote(d.cfg.store, source, "checked", time.Now); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := d.signIn(reviewer)
	if page := body(t, d.get("/tools?proxy=governed", cookie)); !strings.Contains(page, "Also remove the 1 activation check(s)") {
		t.Fatalf("tools page:\n%s", page)
	}
	form := url.Values{"csrf": {csrf}, "proxy": {"governed"}, "tool": {"change"}, "fingerprint": {fingerprint(t, approvedChange)},
		"base": {active(t, d.cfg.store)}, "promoted": {promotedAt(t, d.cfg.store)}}
	if res := d.post("/revoke", cookie, form); res.StatusCode != http.StatusConflict {
		t.Fatalf("revoking without removing the checks: %d", res.StatusCode)
	}
	form.Set("remove_checks", "1")
	if res := d.post("/revoke", cookie, form); !strings.HasSuffix(res.Header.Get("Location"), "done=revoked") {
		t.Fatalf("revoking and removing the checks: %s %s", res.Header.Get("Location"), body(t, res))
	}
	_, contents, err = policy.ReadSet(d.cfg.store, active(t, d.cfg.store))
	if err != nil || strings.Contains(string(contents["checks.json"]), "change") {
		t.Fatalf("checks after revoking: %s, %v", contents["checks.json"], err)
	}
	log, err := policy.ReadLog(d.cfg.store)
	if err != nil || len(log) != 2 || log[0].Action != "revoke" || log[1].Action != "remove-permit-check" {
		t.Fatalf("decision log %+v, %v", log, err)
	}
}

func TestADecisionFormForAnEarlierActivationChangesNothing(t *testing.T) {
	d := newDashboard(t)
	fp := d.queue("change", changedChange)
	cookie, csrf := d.signIn(reviewer)
	base := active(t, d.cfg.store)
	res := d.post("/decide", cookie, url.Values{"csrf": {csrf}, "proxy": {"governed"}, "tool": {"change"}, "fingerprint": {fp}, "base": {base},
		"promoted": {"2000-01-01T00:00:00Z"}, "action": {"approve"}})
	if !strings.HasSuffix(res.Header.Get("Location"), "done=stale") || active(t, d.cfg.store) != base {
		t.Fatalf("a decision for an earlier activation: %s", res.Header.Get("Location"))
	}
}

func TestItemsNameAnyTool(t *testing.T) {
	for _, it := range []item{{Tool: "a.b.c", Fingerprint: "ff"}, {Tool: "ünï\u200bcode/..", Fingerprint: "aa"}, {Instructions: true, Fingerprint: "ee"}} {
		got, ok := decodeItem(it.encode())
		if !ok || got != it {
			t.Fatalf("%+v came back as %+v, %v", it, got, ok)
		}
	}
	for _, bad := range []string{"", "t.", "t.ff", "t.ff.!!", "i.", "x.ff"} {
		if _, ok := decodeItem(bad); ok {
			t.Fatalf("%q decoded", bad)
		}
	}
}

func TestRevokeAndRollBack(t *testing.T) {
	d := newDashboard(t)
	cookie, csrf := d.signIn(reviewer)
	first := active(t, d.cfg.store)
	approved := fingerprint(t, approvedChange)

	tools := html.UnescapeString(body(t, d.get("/tools?proxy=governed", cookie)))
	if !strings.Contains(tools, `action="/extensions/admin/revoke"`) || !strings.Contains(tools, `value="`+approved+`"`) {
		t.Fatalf("tools page:\n%s", tools)
	}
	// A form for an earlier activation of the same set changes nothing.
	if res := d.post("/revoke", cookie, url.Values{"csrf": {csrf}, "proxy": {"governed"}, "tool": {"change"}, "fingerprint": {approved}, "base": {first}, "promoted": {"2000-01-01T00:00:00Z"}}); !strings.HasSuffix(res.Header.Get("Location"), "done=stale") {
		t.Fatalf("a revocation for an earlier activation: %s", res.Header.Get("Location"))
	}
	res := d.post("/revoke", cookie, url.Values{"csrf": {csrf}, "proxy": {"governed"}, "tool": {"change"}, "fingerprint": {approved}, "base": {first}, "promoted": {promotedAt(t, d.cfg.store)}})
	if res.StatusCode != http.StatusSeeOther || !strings.HasSuffix(res.Header.Get("Location"), "done=revoked") {
		t.Fatalf("revoke: %d %s %s", res.StatusCode, res.Header.Get("Location"), body(t, res))
	}
	if approvedFingerprint(t, d.cfg.store, "change") != "" {
		t.Fatal("the approval was not withdrawn")
	}
	revoked := active(t, d.cfg.store)
	// The same form again was made against a set no longer active.
	if res := d.post("/revoke", cookie, url.Values{"csrf": {csrf}, "proxy": {"governed"}, "tool": {"change"}, "fingerprint": {approved}, "base": {first}}); !strings.HasSuffix(res.Header.Get("Location"), "done=stale") {
		t.Fatalf("a stale revocation: %s", res.Header.Get("Location"))
	}

	history := html.UnescapeString(body(t, d.get("/history", cookie)))
	if !strings.Contains(history, "revoke") || !strings.Contains(history, "governed/change") || !strings.Contains(history, `name="base" value="`+revoked+`"`) {
		t.Fatalf("history page:\n%s", history)
	}
	if res := d.post("/rollback", cookie, url.Values{"csrf": {csrf}, "base": {first}, "target": {first}}); !strings.HasSuffix(res.Header.Get("Location"), "done=stale") || active(t, d.cfg.store) != revoked {
		t.Fatalf("a stale rollback: %s", res.Header.Get("Location"))
	}
	// A form naming the active set but another target changes nothing.
	if res := d.post("/rollback", cookie, url.Values{"csrf": {csrf}, "base": {revoked}, "target": {revoked}}); !strings.HasSuffix(res.Header.Get("Location"), "done=stale") || active(t, d.cfg.store) != revoked {
		t.Fatalf("a rollback to another target: %s", res.Header.Get("Location"))
	}
	pointer, _ := policy.ReadPointer(d.cfg.store)
	// A form for an earlier activation of the same pair changes nothing.
	if res := d.post("/rollback", cookie, url.Values{"csrf": {csrf}, "base": {revoked}, "target": {first}, "promoted": {"2000-01-01T00:00:00Z"}}); !strings.HasSuffix(res.Header.Get("Location"), "done=stale") {
		t.Fatalf("a rollback for an earlier activation: %s", res.Header.Get("Location"))
	}
	res = d.post("/rollback", cookie, url.Values{"csrf": {csrf}, "base": {revoked}, "target": {first}, "promoted": {pointer.PromotedAt}})
	if !strings.HasSuffix(res.Header.Get("Location"), "done=rolled-back") || active(t, d.cfg.store) != first || approvedFingerprint(t, d.cfg.store, "change") != approved {
		t.Fatalf("rollback: %s", res.Header.Get("Location"))
	}
	log, err := policy.ReadLog(d.cfg.store)
	if err != nil || len(log) != 2 || log[0].Action != "revoke" || log[1].Action != "rollback" || log[1].Set != first {
		t.Fatalf("decision log %+v, %v", log, err)
	}
}

func TestMaintenanceRemovesOnlyWhatItSays(t *testing.T) {
	d := newDashboard(t)
	settled := d.queue("change", approvedChange)
	d.queue("lookup", lookup)
	cookie, csrf := d.signIn(reviewer)

	page := html.UnescapeString(body(t, d.get("/maintenance", cookie)))
	if !strings.Contains(page, "<td>one</td>") || !strings.Contains(page, `action="/extensions/admin/retire"`) {
		t.Fatalf("maintenance page:\n%s", page)
	}
	res := d.post("/prune", cookie, url.Values{"csrf": {csrf}})
	if !strings.HasSuffix(res.Header.Get("Location"), "done=pruned&n=1") {
		t.Fatalf("prune: %s %s", res.Header.Get("Location"), body(t, res))
	}
	if _, err := os.Stat(filepath.Join(d.cfg.pending, encode("governed"), "tools", encode("change"), settled+".json")); !os.IsNotExist(err) {
		t.Fatalf("the settled entry remains: %v", err)
	}
	if res := d.post("/retire", cookie, url.Values{"csrf": {csrf}, "gateway": {"one"}}); !strings.HasSuffix(res.Header.Get("Location"), "done=unconfirmed") {
		t.Fatalf("an unconfirmed retirement: %s", res.Header.Get("Location"))
	}
	res = d.post("/retire", cookie, url.Values{"csrf": {csrf}, "gateway": {"one"}, "confirm": {"1"}})
	if !strings.HasSuffix(res.Header.Get("Location"), "done=retired&n=2") {
		t.Fatalf("retire: %s %s", res.Header.Get("Location"), body(t, res))
	}
	if page := body(t, d.get("/maintenance", cookie)); !strings.Contains(page, "No gateway has shared declarations.") {
		t.Fatalf("maintenance after retiring:\n%s", page)
	}
}

func TestViewersChangeNothing(t *testing.T) {
	d := newDashboard(t)
	d.queue("lookup", lookup)
	cookie, csrf := d.signIn(viewer)
	base := active(t, d.cfg.store)
	for _, path := range []string{"/bulk", "/bulk/decide", "/revoke", "/rollback", "/prune", "/retire"} {
		if res := d.post(path, cookie, url.Values{"csrf": {csrf}, "base": {base}, "proxy": {"governed"}}); res.StatusCode != http.StatusForbidden {
			t.Fatalf("a viewer's POST %s: %d", path, res.StatusCode)
		}
	}
	for _, path := range []string{"/history", "/maintenance", "/queue?proxy=governed", "/tools?proxy=governed"} {
		page := body(t, d.get(path, cookie))
		if strings.Contains(page, `type="checkbox"`) || strings.Contains(page, "<button type=\"submit\" class=\"secondary\"") {
			t.Fatalf("a viewer was shown controls on %s:\n%s", path, page)
		}
	}
}
