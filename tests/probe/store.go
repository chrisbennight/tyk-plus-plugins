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

var files = []string{"rules.cedar", "approved_tools.json", "approved_instructions.json", "checks.json"}

// legacyFiles are the files of a format-1 set, published by earlier builds.
var legacyFiles = []string{"rules.cedar", "tools.json", "checks.json"}

// staged holds the files of the set the probe will publish next.
var staged = map[string]string{}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func writeSet(contents map[string]string, manifestFiles map[string]string) string {
	return writeSetFormat(2, files, contents, manifestFiles)
}

// writeSetFormat stores a set of the given format and returns its fingerprint.
func writeSetFormat(format int, files []string, contents map[string]string, manifestFiles map[string]string) string {
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
	manifest, _ := json.Marshal(map[string]any{"format": format, "files": manifestFiles})
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
	publish(expect, map[string]string{"approved_tools.json": string(data)})
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
		"access_rights": map[string]any{
			"governed":  map[string]any{"api_id": "governed", "versions": []string{"Default"}},
			"governed2": map[string]any{"api_id": "governed2", "versions": []string{"Default"}},
			"governed3": map[string]any{"api_id": "governed3", "versions": []string{"Default"}},
			"governed4": map[string]any{"api_id": "governed4", "versions": []string{"Default"}},
		},
		"quota_max": -1, "rate": 100, "per": 1,
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
	check(len(r.ID) > 0, "%s: reply has no ID: %v", name, r)
	if len(expected) == 0 {
		// Refused tool calls carry the plug-in's denial, whatever the reason.
		check(r.Status == http.StatusForbidden && r.Error != nil && r.Error.Code == -32002 && r.Error.Message == "Tool call denied" && after == before,
			"%s: expected the plug-in's refusal with no dispatch, got %v (requests %d -> %d)", name, r, before, after)
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

// refusedRequest sends a tools/call whose top-level members the caller
// supplies, beside the usual jsonrpc, id and method, and checks that it never
// reached the upstream. Tyk itself refuses case variants of some members it
// routes on, so only a call Tyk passes on must carry the plug-in's refusal.
func refusedRequest(c *conn, cred credential, name string, members map[string]any, byPlugin bool) {
	before, _ := observed()
	c.lastID++
	id := c.lastID
	body := map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call"}
	for k, v := range members {
		body[k] = v
	}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(data))
	req.Header = c.headers(cred, "tools/call", name)
	res, err := httpClient.Do(req)
	check(err == nil, "%s: %v", data, err)
	defer res.Body.Close()
	r := decode(res, id)
	after, _ := observed()
	check(after == before, "%s: reached the upstream (requests %d -> %d)", data, before, after)
	if byPlugin {
		check(r.Status == http.StatusForbidden && r.Error != nil && r.Error.Code == -32002 && r.Error.Message == "Tool call denied",
			"%s: expected the plug-in's refusal, got %v", data, r)
		return
	}
	check(r.Status >= 400 && r.Error != nil, "%s: expected a refusal, got %v", data, r)
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

// sameRefusal reports whether two refusals are indistinguishable to a client:
// the same status and the same reply body apart from the echoed request ID.
func sameRefusal(a, b response) bool {
	body := func(r response) map[string]any {
		var m map[string]any
		if json.Unmarshal(r.Raw, &m) != nil {
			return nil
		}
		delete(m, "id")
		return m
	}
	ab, bb := body(a), body(b)
	return a.Error != nil && b.Error != nil && ab != nil && a.Status == b.Status && reflect.DeepEqual(ab, bb)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// upstreamVersion reports the protocol version the gateway sent upstream on
// the last request that reached it.
func upstreamVersion() string {
	res, err := httpClient.Get("http://upstream:8000/requests")
	check(err == nil, "upstream: %v", err)
	defer res.Body.Close()
	var body struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	check(json.NewDecoder(res.Body).Decode(&body) == nil, "upstream reply")
	return body.ProtocolVersion
}

// upstreamRejectsNewer asks the upstream directly, bypassing the gateway,
// whether it refuses the newer protocol version: an older-only server
// rejects the request and lists only older versions.
func upstreamRejectsNewer() (bool, string) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": map[string]any{"_meta": map[string]any{
		"io.modelcontextprotocol/protocolVersion": newerProtocol, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}}})
	req, _ := http.NewRequest(http.MethodPost, upstream, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", newerProtocol)
	req.Header.Set("Mcp-Method", "server/discover")
	res, err := httpClient.Do(req)
	check(err == nil, "upstream discovery: %v", err)
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	text := string(data)
	return res.StatusCode == http.StatusBadRequest && strings.Contains(text, "Unsupported protocol version") &&
		strings.Contains(text, olderProtocol) && !strings.Contains(text, newerProtocol), text
}
