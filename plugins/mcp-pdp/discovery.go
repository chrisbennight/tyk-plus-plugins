package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"sync"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/codemode"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/identity"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

// answerCodeMode answers a call to a Code Mode tool the caller's rules
// permit.
func answerCodeMode(w http.ResponseWriter, r *http.Request, id json.RawMessage, name string, params json.RawMessage, who policy.Caller, method identity.Method, proxy string) {
	var call struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	_ = json.Unmarshal(params, &call)
	switch name {
	case codemode.ExecuteTool:
		execute(w, r, id, params, who, method, proxy)
	case codemode.LimitsTool:
		writeStructured(w, id, codemode.LimitsReport(codeMode))
	case codemode.SearchTool:
		var args struct {
			Query  string `json:"query"`
			Detail string `json:"detail"`
			Limit  int    `json:"limit"`
			Cursor string `json:"cursor"`
		}
		if len(call.Arguments) > 0 && json.Unmarshal(call.Arguments, &args) != nil {
			writeToolError(w, id, "invalid", "codemode.search takes an optional query, detail, limit and cursor", nil)
			return
		}
		state := current()
		found, err := codemode.Search(callable(r, state, who), args.Query, args.Detail, args.Limit, args.Cursor, state.Version)
		if err != nil {
			writeToolError(w, id, "invalid", err.Error(), nil)
			return
		}
		writeStructured(w, id, found)
	case codemode.DescribeTool:
		var args struct {
			Proxy string `json:"proxy"`
			Name  string `json:"name"`
		}
		if json.Unmarshal(call.Arguments, &args) != nil || args.Proxy == "" || args.Name == "" {
			writeToolError(w, id, "invalid", "codemode.describe takes a proxy and a tool name", nil)
			return
		}
		for _, e := range callable(r, current(), who) {
			if e.Proxy == args.Proxy && e.Name == args.Name {
				writeStructured(w, id, codemode.Describe(e))
				return
			}
		}
		// A tool the caller cannot call is described exactly as a tool that
		// does not exist.
		writeToolError(w, id, "not_found", "No such tool", nil)
	}
}

func writeStructured(w http.ResponseWriter, id json.RawMessage, value map[string]any) {
	text, _ := json.Marshal(value)
	writeResult(w, id, map[string]any{"content": []map[string]any{{"type": "text", "text": string(text)}}, "structuredContent": value})
}

// callable lists the approved tools, on proxies where Code Mode is on, that
// the caller could call from a program: on proxies its Tyk session may use,
// passing the drift check that refuses calls, and visible to it under its
// rules. The order is stable for a policy set.
func callable(r *http.Request, state *policy.Snapshot, who policy.Caller) []codemode.Entry {
	proxies := make([]string, 0, len(codeMode.Proxies))
	for proxy := range codeMode.Proxies {
		proxies = append(proxies, proxy)
	}
	slices.Sort(proxies)
	var entries []codemode.Entry
	for _, proxy := range proxies {
		if !mayUse(r, proxy) {
			continue
		}
		_, tools := state.ApprovedTools(proxy)
		for _, t := range tools {
			if isCodeModeTool(t.Name) || driftReason(state, proxy, t.Name) != "" || !state.Visible(who, proxy, t.Name) {
				continue
			}
			entries = append(entries, codemode.Entry{Proxy: proxy, Name: t.Name, Definition: t.Definition})
		}
	}
	return entries
}

// mayUse reports whether the caller's Tyk session grants access to a proxy.
// Tyk treats a session without access rights as granting every API.
func mayUse(r *http.Request, proxy string) bool {
	session := ctx.GetSession(r)
	if session == nil {
		return false
	}
	if len(session.AccessRights) == 0 {
		return true
	}
	_, ok := session.AccessRights[proxy]
	return ok
}

// codeModeListing returns the Code Mode tools to add to a caller's list on a
// proxy: those the caller's rules permit, on a Code Mode proxy, on the first
// page only.
func codeModeListing(req *http.Request, state *policy.Snapshot, proxy, upstream string) []json.RawMessage {
	if !codeModeOn(proxy) || !firstPage(req) || state == nil {
		return nil
	}
	who := requestCaller(req)
	var tools []json.RawMessage
	for _, name := range codemode.Tools {
		if reason, _ := state.DecideBuiltIn(who, proxy, upstream, name); reason == "permitted" {
			tools = append(tools, codemode.Definition(name))
		}
	}
	return tools
}

// reservedReported keeps the upstream tools already reported for using the
// reserved prefix, so each is logged once.
var reservedReported sync.Map

func reportReserved(proxy string) func(name string) {
	return func(name string) {
		if _, seen := reservedReported.LoadOrStore(proxy+"\x00"+name, true); !seen {
			slog.Warn("Upstream tool hidden: its name uses the reserved Code Mode prefix", "proxy", proxy, "tool", name)
		}
	}
}
