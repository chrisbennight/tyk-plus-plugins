package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// The policy store holds immutable sets and an active pointer, and the gateway
// reports the set it enforces. The probe publishes sets in the documented store
// format and waits for that report, so every outcome is observed, not assumed.
const (
	policyDir  = "/policy"
	statusFile = "/status/status.json"
	upstream   = "http://upstream:8000/mcp"
)

var files = []string{"rules.cedar", "tools.json", "checks.json"}

// staged holds the files of the set the probe will publish next.
var staged = map[string]string{}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func writeSet(contents map[string]string, manifestFiles map[string]string) string {
	hashes := map[string]string{}
	var joined strings.Builder
	for _, name := range files {
		hashes[name] = digest(contents[name])
		fmt.Fprintf(&joined, "%s\n%s\n", name, hashes[name])
	}
	set := digest(joined.String())
	final := filepath.Join(policyDir, "sets", set)
	if _, err := os.Stat(final); err == nil {
		return set
	}
	staging := filepath.Join(policyDir, "sets", ".staging-"+set)
	must(os.Mkdir(staging, 0o755))
	for _, name := range files {
		must(os.WriteFile(filepath.Join(staging, name), []byte(contents[name]), 0o644))
	}
	if manifestFiles == nil {
		manifestFiles = hashes
	}
	manifest, _ := json.Marshal(map[string]any{"format": 1, "files": manifestFiles})
	must(os.WriteFile(filepath.Join(staging, "manifest.json"), manifest, 0o644))
	must(os.Rename(staging, final))
	return set
}

func pointTo(set, expect string) map[string]any {
	next := filepath.Join(policyDir, ".active-next")
	pointer, _ := json.Marshal(map[string]string{"set": set})
	must(os.WriteFile(next, pointer, 0o644))
	must(os.Rename(next, filepath.Join(policyDir, "active")))
	return awaitReport(set, expect)
}

func readReport() map[string]any {
	report := map[string]any{}
	if data, err := os.ReadFile(statusFile); err == nil {
		json.Unmarshal(data, &report)
	}
	return report
}

func awaitReport(set, expect string) map[string]any {
	deadline := time.Now().Add(10 * time.Second)
	var report map[string]any
	for time.Now().Before(deadline) {
		report = readReport()
		if report["active"] == set && report["outcome"] == expect {
			if expect == "activated" {
				check(report["enforcing"] == set, "activated set not enforced: %v", report)
			}
			return report
		}
		time.Sleep(50 * time.Millisecond)
	}
	panic(fmt.Sprintf("set %s was not %s: %v", set, expect, report))
}

// publish stages the given files over the current ones and activates the set.
func publish(expect string, changes map[string]string) map[string]any {
	for name, text := range changes {
		staged[name] = text
	}
	return pointTo(writeSet(staged, nil), expect)
}

func publishInventory(tools map[string]any, upstreamURL, expect string) {
	data, _ := json.Marshal(map[string]any{"governed": map[string]any{"upstream": upstreamURL, "tools": tools}})
	publish(expect, map[string]string{"tools.json": string(data)})
}

// observed reports how many requests reached the upstream and the arguments
// of the last tool it ran.
func observed() (int, any) {
	res, err := httpClient.Get("http://upstream:8000/requests")
	check(err == nil, "upstream: %v", err)
	defer res.Body.Close()
	var body struct {
		Requests  int `json:"requests"`
		Arguments any `json:"arguments"`
	}
	check(json.NewDecoder(res.Body).Decode(&body) == nil, "upstream reply")
	return body.Requests, body.Arguments
}

func key(role string) string {
	body, _ := json.Marshal(map[string]any{"org_id": "default",
		"access_rights": map[string]any{"governed": map[string]any{"api_id": "governed", "versions": []string{"Default"}}},
		"quota_max":     -1, "rate": 100, "per": 1,
		"meta_data": map[string]any{"cedar": map[string]any{"issuer": "integration", "subject": role, "roles": []string{role}}}})
	req, _ := http.NewRequest(http.MethodPost, "http://gateway:9696/tyk/keys/create", bytes.NewReader(body))
	req.Header.Set("X-Tyk-Authorization", os.Getenv("TYK_GW_SECRET"))
	req.Header.Set("Content-Type", "application/json")
	res, err := httpClient.Do(req)
	check(err == nil && res.StatusCode == http.StatusOK, "creating key: %v", err)
	defer res.Body.Close()
	var created struct{ Key string }
	check(json.NewDecoder(res.Body).Decode(&created) == nil, "key reply")
	return created.Key
}

// token asks the test issuer to sign claims. A nil value removes a claim.
func token(signingKey string, claims map[string]any) string {
	all := map[string]any{"iss": "https://issuer.test", "aud": "governed-mcp", "sub": "alice", "exp": time.Now().Add(5 * time.Minute).Unix()}
	for k, v := range claims {
		if v == nil {
			delete(all, k)
		} else {
			all[k] = v
		}
	}
	body, _ := json.Marshal(all)
	res, err := httpClient.Post("http://issuer:8000/token?key="+signingKey, "application/json", bytes.NewReader(body))
	check(err == nil && res.StatusCode == http.StatusOK, "issuing token: %v", err)
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return string(data)
}

// call makes a tool call and checks where it went. With no expected text the
// call must be refused before reaching the upstream; otherwise it must reach
// the upstream exactly once with these arguments and return that text.
func call(c *conn, cred credential, name string, arguments map[string]any, expected ...string) response {
	before, _ := observed()
	r := c.rpc(cred, "tools/call", map[string]any{"name": name, "arguments": arguments})
	after, args := observed()
	if len(expected) == 0 {
		check(r.Status == http.StatusForbidden && after == before, "%s: expected refusal with no dispatch, got %d %+v (requests %d -> %d)", name, r.Status, r, before, after)
		return r
	}
	var result struct {
		Content []map[string]any `json:"content"`
	}
	check(r.Status == http.StatusOK && json.Unmarshal(r.Result, &result) == nil, "%s: expected success, got %v", name, r)
	check(reflect.DeepEqual(result.Content, []map[string]any{{"type": "text", "text": expected[0]}}), "%s: content %v", name, result.Content)
	check(after == before+1, "%s: expected one dispatch, requests %d -> %d", name, before, after)
	check(sameJSON(args, arguments), "%s: upstream saw %v, sent %v", name, args, arguments)
	return r
}

func sameJSON(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	var x, y any
	json.Unmarshal(ja, &x)
	json.Unmarshal(jb, &y)
	return reflect.DeepEqual(x, y)
}

// refused checks that the gateway refuses a call before the upstream sees it.
func refused(c *conn, cred credential) {
	before, _ := observed()
	r := c.rpc(cred, "tools/call", map[string]any{"name": "lookup", "arguments": map[string]any{}})
	after, _ := observed()
	check((r.Status == http.StatusUnauthorized || r.Status == http.StatusForbidden) && after == before, "expected refusal, got %v", r)
}

func sameRefusal(a, b response) bool {
	return a.Status == b.Status && reflect.DeepEqual(a.Error, b.Error) && string(a.ID) == string(b.ID)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
