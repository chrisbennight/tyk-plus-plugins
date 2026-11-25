package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"
)

const (
	codeMode = "codemode.execute"
	// secondGateway is the second proxy of the gateway under test.
	secondGateway = "http://gateway:8080/mcp2/"
	// runHeader is the header that marks a nested call from a Code Mode run.
	runHeader = "X-Code-Mode-Call"
)

// codeModeRules extend the example rules: support and operator callers may
// run programs, and guests may not. Code Mode tools have no reviewed facts,
// so the forbid on tools not marked read-only leaves them out by name.
const codeModeRules = `
@id("support-read")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("support") && resource.reviewed.flags.contains({name: "readOnly", value: true}) };

@id("operator-call")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("operator") };

@id("operator-required-for-changes")
forbid (principal, action == Action::"tools/call", resource)
when { !resource.reviewed.flags.contains({name: "readOnly", value: true}) && !principal.roles.contains("operator") && !(resource.name like "codemode.*") };

@id("support-code-mode")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("support") && resource.name == "codemode.execute" };
`

// tryCall is a program that makes one call named by its input and returns
// the result or the error the program saw.
const tryCall = `try {
  return { ok: await connectors[input.proxy][input.tool](input.args) };
} catch (e) {
  return { code: e.code, message: e.message };
}`

// run is what a codemode.execute call returned.
type run struct {
	reply   response
	isError bool
	Result  json.RawMessage `json:"result"`
	Console []string        `json:"console"`
	Error   *struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
	} `json:"error"`
}

// execute runs a program through codemode.execute.
func execute(c *conn, cred credential, source string, input any, extra map[string]any) run {
	arguments := map[string]any{"source": source}
	if input != nil {
		arguments["input"] = input
	}
	for k, v := range extra {
		arguments[k] = v
	}
	r := c.rpc(cred, "tools/call", map[string]any{"name": codeMode, "arguments": arguments})
	out := run{reply: r}
	if r.Error != nil {
		return out
	}
	var result struct {
		IsError    bool            `json:"isError"`
		Structured json.RawMessage `json:"structuredContent"`
	}
	check(r.Status == http.StatusOK && json.Unmarshal(r.Result, &result) == nil && json.Unmarshal(result.Structured, &out) == nil,
		"codemode.execute: unreadable reply %v", r)
	out.isError = result.IsError
	return out
}

func (r run) String() string {
	if r.Error != nil {
		return fmt.Sprintf("run failed (%s): %s; console %v", r.Error.Kind, r.Error.Message, r.Console)
	}
	if r.reply.Error != nil {
		return r.reply.String()
	}
	return fmt.Sprintf("result %s, console %v", r.Result, r.Console)
}

// succeeded checks that a run returned a result equal to want.
func (r run) succeeded(what string, want any) {
	var got any
	check(r.reply.Error == nil && !r.isError && json.Unmarshal(r.Result, &got) == nil && sameJSON(got, want), "%s: %v, want %v", what, r, want)
}

// failedWith checks that a run failed with a limit or other failure kind
// whose message mentions says.
func (r run) failedWith(what, kind, says string) {
	check(r.isError && r.Error != nil && r.Error.Kind == kind && strings.Contains(r.Error.Message, says), "%s: %v, want a %s failure mentioning %q", what, r, kind, says)
}

// programCall makes one call from inside a program and returns what the
// program saw, and how many requests reached the upstream.
func programCall(c *conn, cred credential, proxy, tool string, arguments map[string]any) (map[string]any, int) {
	before, _ := observed()
	r := execute(c, cred, tryCall, map[string]any{"proxy": proxy, "tool": tool, "args": arguments}, nil)
	after, _ := observed()
	var seen map[string]any
	check(r.reply.Error == nil && !r.isError && json.Unmarshal(r.Result, &seen) == nil, "program calling %s/%s: %v", proxy, tool, r)
	return seen, after - before
}

// codeModeSuite checks codemode.execute end to end: through Tyk, the
// plug-in and a real sandbox host.
func codeModeSuite(k keys) {
	tools := map[string]any{
		"lookup": map[string]any{"facts": args("readOnly", true), "arguments": args("count", "long")},
		"change": map[string]any{"arguments": args("count", "long")},
	}
	inventory, _ := json.Marshal(map[string]any{
		"governed":  map[string]any{"upstream": upstream, "tools": tools},
		"governed2": map[string]any{"upstream": upstream, "tools": tools},
	})
	publish("activated", map[string]string{"rules.cedar": codeModeRules, "approved_tools.json": string(inventory), "checks.json": "[]"})
	supportToken := bearerCred(token("published", args("app_roles", []string{"support"})))

	for _, version := range []string{olderProtocol, newerProtocol} {
		c := connect(k.support, version)

		// Starting a run needs a permit: a guest is refused like any tool
		// call, and nothing reaches the upstream.
		before, _ := observed()
		guest := execute(c, k.guest, "return 1", nil, nil)
		after, _ := observed()
		check(guest.reply.Status == http.StatusForbidden && guest.reply.Error != nil && guest.reply.Error.Message == "Tool call denied" && after == before,
			"%s: a guest started a run: %v", version, guest)

		// Two calls in parallel, one on each proxy, build one result.
		parallel := execute(c, k.support, `
const [a, b] = await Promise.all([connectors.governed.lookup({ count: 7 }), connectors.governed2.lookup({ count: 7 })]);
console.log("called both");
return [a.content[0].text, b.content[0].text];`, nil, nil)
		parallel.succeeded(version+" parallel calls", []string{"found", "found"})
		check(reflect.DeepEqual(parallel.Console, []string{"called both"}), "%s: console %v", version, parallel.Console)
		// The run closes any session it opened on the second proxy after it
		// replies; counts of upstream requests start once that has finished.
		quiet()

		// A call inside a program gets the decision and refusal a direct call
		// gets. Each caller's own rules apply, and a refusal reaches no upstream.
		for _, caller := range []struct {
			name      string
			cred      credential
			mayChange bool
		}{{"support", k.support, false}, {"operator", k.operator, true}, {"support token", supportToken, false}} {
			seen, dispatched := programCall(c, caller.cred, "governed", "lookup", args("count", 7))
			call(c, caller.cred, "lookup", args("count", 7), "found")
			ok, _ := seen["ok"].(map[string]any)
			check(dispatched == 1 && sameJSON(ok["content"], []any{map[string]any{"type": "text", "text": "found"}}),
				"%s %s: lookup in a program: %v, %d dispatched", version, caller.name, seen, dispatched)
			seen, dispatched = programCall(c, caller.cred, "governed", "change", args("count", 9))
			if caller.mayChange {
				call(c, caller.cred, "change", args("count", 9), "updated")
				check(dispatched == 1 && seen["ok"] != nil, "%s %s: change in a program: %v", version, caller.name, seen)
				continue
			}
			direct := call(c, caller.cred, "change", args("count", 9))
			check(dispatched == 0 && seen["code"] == float64(direct.Error.Code) && seen["message"] == direct.Error.Message,
				"%s %s: refused change in a program: %v, direct %v, %d dispatched", version, caller.name, seen, direct, dispatched)
			// An unknown tool is refused exactly as a hidden one.
			unknown, dispatched := programCall(c, caller.cred, "governed", "unknown", args("count", 9))
			check(dispatched == 0 && reflect.DeepEqual(unknown, seen), "%s %s: unknown tool: %v, refused %v", version, caller.name, unknown, seen)
		}

		// Tyk's own checks apply to nested calls too: token callers have no
		// access right to the second proxy, so a program sees the refusal a
		// direct request gets.
		// Calls to another proxy use the older protocol, which every upstream
		// speaks, so the direct request does too.
		second := &conn{url: secondGateway, version: olderProtocol}
		direct := second.rpc(supportToken, "tools/call", map[string]any{"name": "lookup", "arguments": args("count", 7)})
		seen, _ := programCall(c, supportToken, "governed2", "lookup", args("count", 7))
		check(direct.Status == http.StatusForbidden && direct.Error != nil && seen["code"] == float64(direct.Error.Code) && seen["message"] == direct.Error.Message,
			"%s: token caller on the second proxy: program saw %v, direct %v", version, seen, direct)

		// Programs cannot run programs, and an unknown proxy is refused like
		// a hidden tool.
		seen, dispatched := programCall(c, k.support, "governed", codeMode, map[string]any{"source": "return 1"})
		check(dispatched == 0 && seen["code"] == float64(-32002) && seen["message"] == "Tool call denied", "%s: a program ran a program: %v", version, seen)
		seen, dispatched = programCall(c, k.support, "elsewhere", "lookup", args("count", 7))
		check(dispatched == 0 && seen["message"] == "Tool call denied", "%s: unknown proxy: %v", version, seen)

		// A header claiming to be a nested call grants nothing and never
		// reaches the upstream, which rejects any request carrying it.
		forged := k.guest.with(credential{runHeader: strings.Repeat("ab", 16)})
		check(execute(c, forged, "return 1", nil, nil).reply.Status == http.StatusForbidden, "%s: a forged header let a guest run a program", version)
		call(c, k.support.with(credential{runHeader: strings.Repeat("cd", 16)}), "lookup", args("count", 7), "found")

		// Each limit ends the run with an error naming it, and a caller can
		// lower a limit but not raise one.
		execute(c, k.support, "for (const n of [1, 2, 3]) await connectors.governed.lookup({ count: n }); return 1;", nil,
			map[string]any{"limits": map[string]any{"calls": 2}}).failedWith(version+" calls per run", "limit", "tool calls")
		execute(c, k.support, "while (true) {}", nil, map[string]any{"timeout_seconds": 1}).failedWith(version+" run time", "limit", "exceeded")
		execute(c, k.support, `console.log("x".repeat(300 * 1024)); return 1;`, nil,
			map[string]any{"limits": map[string]any{"console_bytes": 64 << 20}}).failedWith(version+" console", "limit", "console")
		execute(c, k.support, "return input.length;", strings.Repeat("x", 2000), map[string]any{"limits": map[string]any{"value_bytes": 1000}}).
			failedWith(version+" input size", "limit", "value size limit")
		execute(c, k.support, "throw new Error('stop here');", nil, nil).failedWith(version+" exception", "exception", "stop here")
		fmt.Printf("Verified Code Mode runs with the %s protocol.\n", version)
	}

	// A gateway without Code Mode treats codemode.execute as an unknown tool.
	peer := connectAt(peerGateway, k.support, olderProtocol)
	before, _ := observed()
	off := execute(peer, k.support, "return 1", nil, nil)
	after, _ := observed()
	check(off.reply.Status == http.StatusForbidden && off.reply.Error != nil && off.reply.Error.Message == "Tool call denied" && after == before,
		"Code Mode ran on a gateway where it is off: %v", off)
	fmt.Println("Verified that Code Mode is off where it is not configured.")
}

// quiet waits until no request has reached the upstream for a moment.
func quiet() {
	last, _ := observed()
	for range 50 {
		time.Sleep(200 * time.Millisecond)
		now, _ := observed()
		if now == last {
			return
		}
		last = now
	}
	panic("the upstream kept receiving requests")
}
