package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// dashboardURL is the review dashboard as operators reach it: through the
// gateway, which routes /extensions/admin to it.
const dashboardURL = "http://gateway:8080/extensions/admin"

// operator is a browser signed in to the dashboard as one person in the
// test issuer's deck.
type operator struct {
	name   string
	client *http.Client
}

// signIn signs a person in through the dashboard's OpenID Connect flow,
// choosing them at the issuer, and returns the browser and the status of the
// page it lands on.
func signIn(name string) (*operator, int, string) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 10 * time.Second, Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// The issuer's sign-in page lists its people; a browser here picks
		// one by name.
		if req.URL.Path == "/oauth/authorize" && req.URL.Query().Get("login_hint") == "" {
			q := req.URL.Query()
			q.Set("login_hint", name)
			req.URL.RawQuery = q.Encode()
		}
		if len(via) > 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}}
	o := &operator{name: name, client: client}
	status, page := o.get("/")
	return o, status, page
}

func (o *operator) get(path string) (int, string) {
	res, err := o.client.Get(dashboardURL + path)
	check(err == nil, "dashboard %s as %s: %v", path, o.name, err)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, html.UnescapeString(string(body))
}

func (o *operator) post(path string, form url.Values) (int, string) {
	req, _ := http.NewRequest(http.MethodPost, dashboardURL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://gateway:8080")
	res, err := o.client.Do(req)
	check(err == nil, "dashboard POST %s as %s: %v", path, o.name, err)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, html.UnescapeString(string(body))
}

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([a-z]+)" value="([^"]*)">`)

// decisionForm reads the hidden fields of a change page's decision form.
func decisionForm(page string) url.Values {
	form := url.Values{}
	for _, m := range hiddenInput.FindAllStringSubmatch(page, -1) {
		form.Set(m[1], m[2])
	}
	return form
}

// checkDashboardReads checks what each kind of operator can see of a queued
// change: a viewer reads the queue, the change and why the tool is refused,
// but cannot decide; someone in neither group is refused.
func checkDashboardReads(version, fingerprint string) {
	viewer, status, page := signIn("viewer")
	check(status == http.StatusOK && strings.Contains(page, "Overview") && strings.Contains(page, "viewer"), "%s: viewer sign-in: %d\n%s", version, status, page)
	status, page = viewer.get("/queue?proxy=governed")
	check(status == http.StatusOK && strings.Contains(page, "fp="+fingerprint) && strings.Contains(page, "changed tool"), "%s: dashboard queue: %d\n%s", version, status, page)
	status, page = viewer.get("/change?proxy=governed&tool=change&fp=" + fingerprint)
	check(status == http.StatusOK && strings.Contains(page, "Description changed:") && strings.Contains(page, "An approved description the upstream no longer declares") &&
		!strings.Contains(page, `name="action"`), "%s: dashboard change as viewer: %d\n%s", version, status, page)
	status, page = viewer.get("/tools?proxy=governed")
	check(status == http.StatusOK && strings.Contains(page, "Refused: the upstream declares a changed definition, waiting for review."), "%s: dashboard tools: %d\n%s", version, status, page)
	form := decisionForm(page)
	form.Set("proxy", "governed")
	form.Set("tool", "change")
	form.Set("fingerprint", fingerprint)
	form.Set("action", "approve")
	status, _ = viewer.post("/decide", form)
	check(status == http.StatusForbidden, "%s: a viewer's decision answered %d", version, status)

	_, status, _ = signIn("outsider")
	check(status == http.StatusForbidden, "%s: an account in neither group signed in with %d", version, status)
}

// approveInDashboard approves a queued change as a reviewer, through the
// change page's form, and returns the set it made active.
func approveInDashboard(version, fingerprint string) string {
	reviewer, status, page := signIn("reviewer")
	check(status == http.StatusOK && strings.Contains(page, "reviewer"), "%s: reviewer sign-in: %d\n%s", version, status, page)
	status, page = reviewer.get("/change?proxy=governed&tool=change&fp=" + fingerprint)
	check(status == http.StatusOK && strings.Contains(page, `value="approve"`), "%s: dashboard change as reviewer: %d\n%s", version, status, page)
	form := decisionForm(page)
	form.Set("action", "approve")
	status, page = reviewer.post("/decide", form)
	check(status == http.StatusOK && strings.Contains(page, "Approved."), "%s: dashboard approval: %d\n%s", version, status, page)
	pointer, err := os.ReadFile(filepath.Join(policyDir, "active"))
	check(err == nil, "%s: active pointer: %v", version, err)
	var active struct{ Set string }
	json.Unmarshal(pointer, &active)
	checkLastDecision(version, fingerprint, active.Set)
	return active.Set
}

// checkLastDecision checks that the decision log's last entry records the
// reviewer's verified identity from the issuer, and the approval made.
func checkLastDecision(version, fingerprint, set string) {
	data, err := os.ReadFile(filepath.Join(policyDir, "decisions.log"))
	check(err == nil, "%s: decision log: %v", version, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var last struct {
		Action, Fingerprint, Set string
		Actor                    struct{ Issuer, Subject, Name string }
	}
	check(json.Unmarshal([]byte(lines[len(lines)-1]), &last) == nil, "%s: decision log line %q", version, lines[len(lines)-1])
	check(last.Action == "approve" && last.Fingerprint == fingerprint && last.Set == set &&
		last.Actor.Issuer == "https://issuer.test" && last.Actor.Subject == "reviewer" && last.Actor.Name == "Rita Reviewer",
		"%s: last decision %+v", version, last)
}
