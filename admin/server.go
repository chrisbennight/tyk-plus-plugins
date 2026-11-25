package main

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/driftreview"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
	"github.com/go-json-experiment/json/jsontext"
)

//go:embed templates/*.html static/style.css
var assets embed.FS

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"when": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"short": func(fp string) string {
		if len(fp) > 12 {
			return fp[:12]
		}
		return fp
	},
}).ParseFS(assets, "templates/*.html"))

// longDefinition is the size past which a definition must be opened in
// full before it can be approved, so no part of it goes unread.
const longDefinition = 2000

// server serves the dashboard's pages. Every page reads the store and the
// shared directory afresh; decisions go through driftreview, the same code
// cedar-policy drift uses.
type server struct {
	cfg  config
	auth *auth
	now  func() time.Time
}

func newServer(cfg config, a *auth) *server { return &server{cfg: cfg, auth: a, now: time.Now} }

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /style.css", s.style)
	mux.HandleFunc("GET /login", s.auth.login)
	mux.HandleFunc("GET /callback", s.auth.callback)
	mux.HandleFunc("GET /signed-out", s.signedOut)
	mux.HandleFunc("POST /logout", s.signedIn(viewer, true, func(w http.ResponseWriter, r *http.Request, _ *session) { s.auth.logout(w, r) }))
	mux.HandleFunc("GET /{$}", s.signedIn(viewer, false, s.overview))
	mux.HandleFunc("GET /queue", s.signedIn(viewer, false, s.queue))
	mux.HandleFunc("GET /change", s.signedIn(viewer, false, s.change))
	mux.HandleFunc("GET /tools", s.signedIn(viewer, false, s.tools))
	mux.HandleFunc("POST /decide", s.signedIn(reviewer, true, s.decide))
	return headers(mux)
}

// headers sets the security headers every response carries: nothing is
// loaded from elsewhere, framed, cached, or sent on as a referrer.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// signedIn admits operators with at least the given role. A page request
// without a session starts a sign-in; a form without one is refused. Forms
// must carry the session's CSRF token.
func (s *server) signedIn(need role, form bool, page func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.auth.current(r)
		switch {
		case sess == nil && !form:
			http.Redirect(w, r, s.auth.link("/login?next="+url.QueryEscape(r.URL.RequestURI())), http.StatusFound)
			return
		case sess == nil:
			http.Error(w, "Your session has ended. Sign in again.", http.StatusUnauthorized)
			return
		case sess.role < need:
			http.Error(w, "Only reviewers can make decisions.", http.StatusForbidden)
			return
		}
		if form {
			if err := r.ParseForm(); err != nil || s.auth.checkForm(r, sess) != nil {
				http.Error(w, "This form did not come from your dashboard session. Reload the page and try again.", http.StatusForbidden)
				return
			}
		}
		page(w, r, sess)
	}
}

func (s *server) style(w http.ResponseWriter, _ *http.Request) {
	css, _ := assets.ReadFile("static/style.css")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write(css)
}

func (s *server) signedOut(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "signed-out", page{Title: "Signed out", Base: s.auth.public.Path})
}

// page is what every page shows besides its own content.
type page struct {
	Title    string
	Base     string
	User     string
	Role     string
	CSRF     string
	Reviewer bool
	Content  any
}

func (s *server) page(sess *session, title string, content any) page {
	return page{Title: title, Base: s.auth.public.Path, User: sess.actor.Name, Role: sess.role.String(),
		CSRF: sess.csrf, Reviewer: sess.role == reviewer, Content: content}
}

func (s *server) render(w http.ResponseWriter, name string, data page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("Rendering a page failed", "page", name, "error", err)
	}
}

func (s *server) fail(w http.ResponseWriter, sess *session, status int, message string) {
	w.WriteHeader(status)
	s.render(w, "problem", s.page(sess, "Problem", message))
}

// state is the active set and the shared directory, read for one request.
type state struct {
	set      string
	label    string
	promoted string
	snapshot *policy.Snapshot
	review   *drift.Review
}

func (s *server) read() (*state, error) {
	pointer, err := policy.ReadPointer(s.cfg.store)
	if err != nil {
		return nil, fmt.Errorf("the policy store's active pointer cannot be read: %w", err)
	}
	snapshot, manifest, err := policy.LoadSet(s.cfg.store, pointer.Set)
	if err != nil {
		return nil, fmt.Errorf("the active policy set cannot be loaded: %w", err)
	}
	review, err := drift.OpenReview(s.cfg.pending)
	if err != nil {
		return nil, fmt.Errorf("the shared drift directory cannot be opened: %w", err)
	}
	return &state{set: pointer.Set, label: manifest.Label, promoted: pointer.PromotedAt, snapshot: snapshot, review: review}, nil
}

// proxySummary is one proxy's line on the overview.
type proxySummary struct {
	Name, Shown      string
	Waiting, Blocked int
	Problem          string
}

type gatewaySeen struct {
	Name string
	Seen time.Time
}

func (s *server) overview(w http.ResponseWriter, r *http.Request, sess *session) {
	st, err := s.read()
	if err != nil {
		s.fail(w, sess, http.StatusServiceUnavailable, err.Error())
		return
	}
	defer st.review.Close()
	var proxies []proxySummary
	for _, proxy := range st.snapshot.DriftProxies() {
		view, _ := st.snapshot.Drift(proxy)
		p := proxySummary{Name: proxy, Shown: driftreview.ShownName(proxy)}
		tools, _, err := driftreview.PendingTools(st.review, view, proxy)
		instructions, _, err2 := driftreview.PendingInstructions(st.review, st.snapshot, view, proxy)
		states, err3 := driftreview.ToolStates(st.review, view, proxy)
		if err := errors.Join(err, err2, err3); err != nil {
			p.Problem = err.Error()
		}
		p.Waiting = len(tools) + len(instructions)
		for _, t := range states {
			if !t.Callable {
				p.Blocked++
			}
		}
		proxies = append(proxies, p)
	}
	var gateways []gatewaySeen
	if seen, err := st.review.Gateways(); err == nil {
		for name, at := range seen {
			gateways = append(gateways, gatewaySeen{Name: driftreview.ShownName(name), Seen: at})
		}
		slices.SortFunc(gateways, func(a, b gatewaySeen) int { return strings.Compare(a.Name, b.Name) })
	}
	s.render(w, "overview", s.page(sess, "Overview", map[string]any{
		"Proxies": proxies, "Gateways": gateways, "Set": st.set, "Label": st.label, "Promoted": st.promoted,
	}))
}

// queueItem is one waiting change on the review queue.
type queueItem struct {
	Tool, Shown, Kind, Fingerprint, State, Gateway string
	FirstSeen                                      time.Time
	Instructions                                   bool
}

func (s *server) queue(w http.ResponseWriter, r *http.Request, sess *session) {
	st, view, proxy, ok := s.proxy(w, r, sess)
	if !ok {
		return
	}
	defer st.review.Close()
	tools, problems, err := driftreview.PendingTools(st.review, view, proxy)
	if err != nil {
		s.fail(w, sess, http.StatusServiceUnavailable, err.Error())
		return
	}
	instructions, more, err := driftreview.PendingInstructions(st.review, st.snapshot, view, proxy)
	if err != nil {
		s.fail(w, sess, http.StatusServiceUnavailable, err.Error())
		return
	}
	var items []queueItem
	for _, t := range tools {
		state := "superseded: the upstream has changed it again"
		switch {
		case t.Latest:
			state = "what the upstream declares now"
		case !t.Declared:
			state = "no declaration shared yet"
		}
		items = append(items, queueItem{Tool: t.Entry.Tool, Shown: driftreview.ShownName(t.Entry.Tool), Kind: t.Kind + " tool",
			Fingerprint: t.Entry.Fingerprint, State: state, Gateway: driftreview.ShownName(t.Entry.Gateway), FirstSeen: t.Entry.FirstSeen})
	}
	for _, e := range instructions {
		items = append(items, queueItem{Shown: "instructions", Kind: "changed instructions", Fingerprint: e.Fingerprint,
			Gateway: driftreview.ShownName(e.Gateway), FirstSeen: e.FirstSeen, Instructions: true})
	}
	var shown []string
	for _, p := range append(problems, more...) {
		shown = append(shown, driftreview.ShownName(p.Error()))
	}
	s.render(w, "queue", s.page(sess, "Review queue", map[string]any{
		"Proxy": proxy, "ProxyShown": driftreview.ShownName(proxy), "Items": items, "Problems": shown, "Done": doneMessage(r.URL.Query().Get("done")),
	}))
}

// doneMessage turns a fixed outcome code into the message shown after a
// decision; the page never echoes text from its URL.
func doneMessage(code string) string {
	return map[string]string{
		"approved": "Approved. Gateways enforce the new set within their refresh interval.",
		"rejected": "Rejected. The definition will not be queued again.",
		"stale":    "Nothing was changed: the active set or the change moved on while you reviewed. Review it again.",
	}[code]
}

// proxy reads the state and the proxy a request names, which must be under
// drift review.
func (s *server) proxy(w http.ResponseWriter, r *http.Request, sess *session) (*state, policy.DriftView, string, bool) {
	st, err := s.read()
	if err != nil {
		s.fail(w, sess, http.StatusServiceUnavailable, err.Error())
		return nil, policy.DriftView{}, "", false
	}
	proxy := r.URL.Query().Get("proxy")
	view, ok := st.snapshot.Drift(proxy)
	if !ok {
		st.review.Close()
		s.fail(w, sess, http.StatusNotFound, "That proxy is not under drift review in the active set.")
		return nil, policy.DriftView{}, "", false
	}
	return st, view, proxy, true
}

// diffPart is a run of a diff line's text, changed or not.
type diffPart struct {
	Text    string
	Changed bool
}

// diffRow is one line of a diff as the page shows it.
type diffRow struct {
	Op    string
	Parts []diffPart
}

func (s *server) change(w http.ResponseWriter, r *http.Request, sess *session) {
	st, view, proxy, ok := s.proxy(w, r, sess)
	if !ok {
		return
	}
	defer st.review.Close()
	q := r.URL.Query()
	fingerprint, tool, instructions := q.Get("fp"), q.Get("tool"), q.Get("instructions") == "1"
	data := map[string]any{"Proxy": proxy, "ProxyShown": driftreview.ShownName(proxy), "Tool": tool, "Instructions": instructions, "Fingerprint": fingerprint, "Base": st.set, "Full": q.Get("full") == "1"}
	var diff string
	var length int
	if instructions {
		entry, err := st.review.InstructionsEntry(proxy, fingerprint)
		if err != nil {
			s.fail(w, sess, http.StatusNotFound, driftreview.ShownName(err.Error()))
			return
		}
		approved, _ := st.snapshot.Instructions(proxy)
		var b strings.Builder
		driftreview.LineDiff(&b, approved, entry.Instructions)
		diff = "Instructions changed:\n" + b.String()
		invisible, lookAlike := countText(entry.Instructions)
		shown, _, _ := driftreview.Visible(entry.Instructions)
		length = len(entry.Instructions)
		data["Kind"], data["FirstSeen"], data["Gateway"] = "Changed instructions", entry.FirstSeen, driftreview.ShownName(entry.Gateway)
		data["Invisible"], data["LookAlike"], data["Definition"] = invisible, lookAlike, shown
		data["Approved"] = policy.InstructionsFingerprint(approved) == fingerprint
		data["Rejected"] = view.RejectedInstructions(fingerprint)
	} else {
		entry, err := st.review.Tool(proxy, tool, fingerprint)
		if err != nil {
			s.fail(w, sess, http.StatusNotFound, driftreview.ShownName(err.Error()))
			return
		}
		approvedFingerprint, approved, isApproved := view.Approved(tool)
		kind := "New tool"
		if isApproved {
			kind = "Changed tool"
			diff = driftreview.DefinitionDiff(jsontext.Value(approved), entry.Definition)
		}
		invisible, lookAlike := driftreview.Hidden(entry.Definition)
		hints, _ := driftreview.RenameHints(st.review, view, proxy, entry)
		for i := range hints {
			hints[i] = driftreview.ShownName(hints[i])
		}
		if newest, found, err := st.review.Newest(proxy, tool, view.Upstream()); err == nil && found && newest.Fingerprint != fingerprint {
			data["Superseded"] = true
		}
		length = len(entry.Definition)
		data["Kind"], data["FirstSeen"], data["Gateway"] = kind, entry.FirstSeen, driftreview.ShownName(entry.Gateway)
		data["Invisible"], data["LookAlike"], data["Hints"] = invisible, lookAlike, hints
		data["Definition"] = driftreview.Indented(entry.Definition)
		data["Approved"] = approvedFingerprint == fingerprint
		data["Rejected"] = view.Rejected(tool, fingerprint)
		data["ToolShown"] = driftreview.ShownName(tool)
	}
	data["Diff"] = highlight(driftreview.ParseDiff(diff))
	data["Long"] = length > longDefinition
	s.render(w, "change", s.page(sess, "Change", data))
}

// countText counts the invisible and look-alike characters in a text.
func countText(text string) (int, int) {
	_, invisible, lookAlike := driftreview.Visible(text)
	return invisible, lookAlike
}

// highlight turns diff lines into rows, marking the words that differ when
// removed lines are followed by as many added ones.
func highlight(lines []driftreview.DiffLine) []diffRow {
	var rows []diffRow
	for i := 0; i < len(lines); {
		if lines[i].Op != '-' {
			rows = append(rows, diffRow{Op: string(lines[i].Op), Parts: []diffPart{{Text: lines[i].Text}}})
			i++
			continue
		}
		removed := i
		for i < len(lines) && lines[i].Op == '-' {
			i++
		}
		added := i
		for i < len(lines) && lines[i].Op == '+' {
			i++
		}
		if added-removed == i-added {
			var olds, news []diffRow
			for k := 0; k < added-removed; k++ {
				o, n := wordDiff(lines[removed+k].Text, lines[added+k].Text)
				olds = append(olds, diffRow{Op: "-", Parts: o})
				news = append(news, diffRow{Op: "+", Parts: n})
			}
			rows = append(append(rows, olds...), news...)
			continue
		}
		for k := removed; k < i; k++ {
			rows = append(rows, diffRow{Op: string(lines[k].Op), Parts: []diffPart{{Text: lines[k].Text}}})
		}
	}
	return rows
}

// maxWords bounds the words compared on one line; longer lines are marked
// as wholly changed.
const maxWords = 500

// wordDiff marks the words of two lines that are not part of their longest
// common run of words.
func wordDiff(before, after string) ([]diffPart, []diffPart) {
	old, new := strings.SplitAfter(before, " "), strings.SplitAfter(after, " ")
	if len(old) > maxWords || len(new) > maxWords {
		return []diffPart{{Text: before, Changed: true}}, []diffPart{{Text: after, Changed: true}}
	}
	common := make([][]int, len(old)+1)
	for i := range common {
		common[i] = make([]int, len(new)+1)
	}
	for i := len(old) - 1; i >= 0; i-- {
		for j := len(new) - 1; j >= 0; j-- {
			if old[i] == new[j] {
				common[i][j] = common[i+1][j+1] + 1
			} else {
				common[i][j] = max(common[i+1][j], common[i][j+1])
			}
		}
	}
	var o, n []diffPart
	add := func(parts []diffPart, text string, changed bool) []diffPart {
		if len(parts) > 0 && parts[len(parts)-1].Changed == changed {
			parts[len(parts)-1].Text += text
			return parts
		}
		return append(parts, diffPart{Text: text, Changed: changed})
	}
	i, j := 0, 0
	for i < len(old) || j < len(new) {
		switch {
		case i < len(old) && j < len(new) && old[i] == new[j]:
			o, n = add(o, old[i], false), add(n, new[j], false)
			i, j = i+1, j+1
		case i < len(old) && (j == len(new) || common[i+1][j] >= common[i][j+1]):
			o = add(o, old[i], true)
			i++
		default:
			n = add(n, new[j], true)
			j++
		}
	}
	return o, n
}

// toolRow is one tool on the Tools page.
type toolRow struct {
	Tool, Name, Reason, Waiting string
	Callable                    bool
	Seen                        time.Time
	Found                       bool
}

func (s *server) tools(w http.ResponseWriter, r *http.Request, sess *session) {
	st, view, proxy, ok := s.proxy(w, r, sess)
	if !ok {
		return
	}
	defer st.review.Close()
	states, err := driftreview.ToolStates(st.review, view, proxy)
	if err != nil {
		s.fail(w, sess, http.StatusServiceUnavailable, err.Error())
		return
	}
	rows := make([]toolRow, 0, len(states))
	for _, t := range states {
		rows = append(rows, toolRow{Tool: t.Tool, Name: driftreview.ShownName(t.Tool), Reason: t.Reason, Waiting: t.Waiting,
			Callable: t.Callable, Seen: t.Seen, Found: t.Found})
	}
	s.render(w, "tools", s.page(sess, "Tools", map[string]any{"Proxy": proxy, "ProxyShown": driftreview.ShownName(proxy), "Rows": rows}))
}

// decide approves or rejects exactly the fingerprint the page showed,
// against the set the page was made from.
func (s *server) decide(w http.ResponseWriter, r *http.Request, sess *session) {
	proxy, tool, fingerprint, base := r.PostFormValue("proxy"), r.PostFormValue("tool"), r.PostFormValue("fingerprint"), r.PostFormValue("base")
	instructions, action := r.PostFormValue("instructions") == "1", r.PostFormValue("action")
	if action != "approve" && action != "reject" {
		s.fail(w, sess, http.StatusBadRequest, "Unknown decision.")
		return
	}
	review, err := drift.OpenReview(s.cfg.pending)
	if err != nil {
		s.fail(w, sess, http.StatusServiceUnavailable, "The shared drift directory cannot be opened.")
		return
	}
	defer review.Close()
	d := driftreview.Decision{Proxy: proxy, Tool: tool, Instructions: instructions, Fingerprint: fingerprint, Approve: action == "approve"}
	if instructions {
		entry, err := review.InstructionsEntry(proxy, fingerprint)
		if err != nil {
			s.fail(w, sess, http.StatusNotFound, driftreview.ShownName(err.Error()))
			return
		}
		d.Tool, d.Text = "", entry.Instructions
	} else {
		entry, err := review.Tool(proxy, tool, fingerprint)
		if err != nil {
			s.fail(w, sess, http.StatusNotFound, driftreview.ShownName(err.Error()))
			return
		}
		d.Definition = entry.Definition
	}
	label := fmt.Sprintf("dashboard %s %s %s by %s", action, driftreview.Describe(d), short(fingerprint), sess.actor.Name)
	back := s.auth.link("/queue?proxy=" + url.QueryEscape(proxy))
	set, err := driftreview.Apply(s.cfg.store, base, label, sess.actor, s.now, []driftreview.Decision{d})
	switch {
	case errors.Is(err, driftreview.ErrStale):
		http.Redirect(w, r, back+"&done=stale", http.StatusSeeOther)
		return
	case err != nil:
		slog.Error("A decision failed", "proxy", proxy, "fingerprint", fingerprint, "error", err)
		s.fail(w, sess, http.StatusInternalServerError, driftreview.ShownName(err.Error()))
		return
	}
	slog.Info("Decision made", "action", action, "proxy", proxy, "tool", tool, "instructions", instructions,
		"fingerprint", fingerprint, "set", set, "issuer", sess.actor.Issuer, "subject", sess.actor.Subject)
	http.Redirect(w, r, back+"&done="+map[string]string{"approve": "approved", "reject": "rejected"}[action], http.StatusSeeOther)
}

func short(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}
