package main

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// program makes each call in input.calls in turn and reports, for each,
// whether it was permitted, and the error a refused call rejected with.
const program = `const outcomes = [];
for (const c of input.calls) {
  try {
    const result = await connectors[c.server][c.tool](c.arguments);
    outcomes.push({ permitted: !result.isError });
  } catch (e) {
    outcomes.push({ permitted: false, code: e.code, message: e.message });
  }
}
return outcomes;`

// outcome is what the program reports for one call.
type outcome struct {
	Permitted bool   `json:"permitted"`
	Code      int64  `json:"code"`
	Message   string `json:"message"`
}

// codeMode runs each program in expected.json with clients of both protocol
// versions, and confirms that every call it makes gets the outcome the same
// caller's direct call gets: a permitted call reaches its server, and a
// refused one is refused exactly as a direct call is, without reaching it.
func (r *runner) codeMode() {
	cm := r.e.expected.CodeMode
	if cm == nil {
		return
	}
	for _, p := range cm.Programs {
		cred, err := r.creds.of(p.Caller)
		if err != nil {
			fail(err)
		}
		for _, version := range versions {
			what := fmt.Sprintf("%s runs a program on %s with a %s client (%s)", p.Caller, p.Server, version, p.Why)
			session, err := r.session(p.Caller, cred, version, p.Server)
			if err != nil {
				r.fail(what, "could not connect: "+err.Error())
				continue
			}
			if p.Expect == "refused" {
				r.checkCall(what+": refused", session, version, p.Server, "codemode.execute", map[string]any{"source": program, "input": map[string]any{"calls": []call{}}}, "refused")
				continue
			}
			r.runProgram(what, session, p)
		}
	}
}

func (r *runner) runProgram(what string, session *mcp.ClientSession, p codeProgram) {
	// What each server should run: one tool call for each permitted call. A
	// run opens a session on another proxy before calling it, so tool calls
	// are counted rather than requests.
	want := map[string]int{}
	for _, c := range p.Calls {
		want[c.Server] += 0
		if c.Expect == "permitted" {
			want[c.Server]++
		}
	}
	before := map[string]int{}
	for server := range want {
		o, err := observe(server)
		if err != nil {
			r.fail(what, err.Error())
			return
		}
		before[server] = o.Calls
	}
	calls := make([]map[string]any, len(p.Calls))
	for i, c := range p.Calls {
		calls[i] = map[string]any{"server": c.Server, "tool": c.Tool, "arguments": c.Arguments}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "codemode.execute", Arguments: map[string]any{"source": program, "input": map[string]any{"calls": calls}}})
	if err != nil {
		r.fail(what, "codemode.execute failed: "+err.Error())
		return
	}
	var run struct {
		Result []outcome `json:"result"`
		Error  *struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		} `json:"error"`
	}
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &run); err != nil || res.IsError || len(run.Result) != len(p.Calls) {
		detail := string(raw)
		if run.Error != nil {
			detail = run.Error.Kind + ": " + run.Error.Message
		}
		r.fail(what, "the run did not report every call: "+detail)
		return
	}
	for i, c := range p.Calls {
		got := run.Result[i]
		callWhat := fmt.Sprintf("%s: %s.%s %s is %s, as when called directly", what, c.Server, c.Tool, arguments(c.Arguments), c.Expect)
		switch {
		case c.Expect == "permitted" && !got.Permitted:
			r.fail(callWhat, fmt.Sprintf("refused with %d %q", got.Code, got.Message))
		case c.Expect == "refused" && got.Permitted:
			r.fail(callWhat, "permitted")
		case c.Expect == "refused" && (r.refusal == nil || got.Code != r.refusal.Code || got.Message != r.refusal.Message):
			r.fail(callWhat, fmt.Sprintf("refused with %d %q, unlike a direct refusal %+v", got.Code, got.Message, r.refusal))
		default:
			r.pass(callWhat)
		}
	}
	// The last permitted call to each server is the one it records, so its
	// tool and arguments show the program's calls arrived as written.
	last := map[string]call{}
	for _, c := range p.Calls {
		if c.Expect == "permitted" {
			last[c.Server] = c
		}
	}
	for _, server := range slices.Sorted(maps.Keys(want)) {
		o, err := observe(server)
		reachWhat := fmt.Sprintf("%s: %s ran %d tool calls", what, server, want[server])
		c, called := last[server]
		switch {
		case err != nil:
			r.fail(reachWhat, err.Error())
		case o.Calls-before[server] != want[server]:
			r.fail(reachWhat, fmt.Sprintf("it ran %d", o.Calls-before[server]))
		case called && (o.Tool == nil || *o.Tool != c.Tool || !sameJSON(o.Arguments, c.Arguments)):
			r.fail(reachWhat, fmt.Sprintf("its last call was not %s %s", c.Tool, arguments(c.Arguments)))
		default:
			r.pass(reachWhat)
		}
	}
}
