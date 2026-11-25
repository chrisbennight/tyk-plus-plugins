package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/codemode"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/identity"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
	jsonv2 "github.com/go-json-experiment/json"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
	var metadata map[string]any
	if session := ctx.GetSession(r); session != nil {
		metadata = session.MetaData
	}
	// The context also holds the raw credential, so only claims are read from it.
	data, _ := r.Context().Value(ctx.ContextData).(map[string]any)
	who, method, callerErr := identity.Resolve(data, metadata, claimNames)
	// A nested call from a Code Mode run carries the plug-in's own header,
	// which is removed here so it never reaches an upstream.
	nested, isNested := takeNested(r)
	if isNested {
		// Every nested request, including a session's handshake and teardown,
		// must arrive at the proxy the plug-in sent it to. Otherwise the listen
		// path Code Mode was given for that proxy leads elsewhere.
		if oas := ctx.GetOASDefinition(r); oas == nil || oas.GetTykExtension() == nil || oas.GetTykExtension().Info.ID != nested.Proxy {
			var envelope struct {
				ID json.RawMessage `json:"id"`
			}
			body, _ := readBody(r)
			_ = json.Unmarshal(body, &envelope)
			slog.Warn("Code Mode request refused", "code_mode_run", nested.Run, "method", ctx.GetMCPMethod(r), "reason", "code_mode_wrong_proxy")
			refuse(w, envelope.ID, "Tool call denied")
			return
		}
	}
	// Every request needs an identifiable caller, not only tool calls, so a
	// credential the plug-in rejects cannot reach any other MCP method. Tool
	// calls are refused below, through the logged decision. Other requests
	// pass through without their bodies being read.
	if ctx.GetMCPMethod(r) != "tools/call" {
		if callerErr != nil {
			var envelope struct {
				ID json.RawMessage `json:"id"`
			}
			body, _ := readBody(r)
			_ = json.Unmarshal(body, &envelope)
			slog.Info("Caller refused", "identity", method, "method", ctx.GetMCPMethod(r), "reason", "invalid_caller")
			refuse(w, envelope.ID, "Caller not identified")
			return
		}
		// CheckResponse reads some replies on proxies under drift
		// review, so there the client's request for compression is not
		// passed upstream. A Go HTTP client that asks for compression on its
		// own also decompresses the reply itself.
		if checkedMethods[ctx.GetMCPMethod(r)] {
			// Drift review can start before the reply arrives, so the ID of
			// every request whose reply may be checked is kept for the
			// gateway's own errors.
			rememberRequestID(r)
			rememberCaller(r, who)
			// Every tools/list reply is read, to keep reserved names out
			// and add Code Mode's tools.
			if underDriftReview(r) || ctx.GetMCPMethod(r) == "tools/list" {
				r.Header.Del("Accept-Encoding")
			}
		}
		return
	}
	var call struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	// builtIn is set when the plug-in answers the call itself.
	builtIn := false
	body, readErr := readBody(r)
	validBody := readErr == nil && jsonv2.Unmarshal(body, &call) == nil
	name := ctx.GetMCPPrimitiveName(r)
	oas := ctx.GetOASDefinition(r)
	state := current()
	var rules []string
	version, label, reason := "", "", "unavailable"
	if state != nil {
		version, label = state.Version, state.Label
	}
	switch {
	case state == nil:
	case callerErr != nil:
		reason = "invalid_caller"
	case oas == nil || oas.GetTykExtension() == nil:
		reason = "missing_proxy"
	case isNested && isCodeModeTool(name):
		reason = "code_mode_recursion"
	case codeModeOn(oas.GetTykExtension().Info.ID) && isCodeModeTool(name):
		// Code Mode tools ship with the plug-in, so they are not drift
		// reviewed, but the caller's rules must permit them like any tool.
		reason = "unknown_tool"
		if validBody && call.Method == "tools/call" && call.Params.Name == name && codemode.IsTool(name) {
			builtIn = true
			reason, rules = state.DecideBuiltIn(who, oas.GetTykExtension().Info.ID, oas.GetTykExtension().Upstream.URL, name)
		}
	case isCodeModeTool(name):
		// The prefix is reserved for the plug-in's own tools, so an upstream
		// tool with it is never called, and rules naming Code Mode tools can
		// only ever refer to the plug-in's.
		reason = "unknown_tool"
	default:
		reason = "invalid_call"
		proxy := oas.GetTykExtension().Info.ID
		if validBody && call.Method == "tools/call" && call.Params.Name == name {
			reason = driftReason(state, proxy, name)
			if reason == "" {
				reason, rules = state.Decide(who, proxy, oas.GetTykExtension().Upstream.URL, name, call.Params.Arguments)
			}
		}
	}
	attrs := []any{"identity", method, "issuer", who.Issuer, "subject", who.Subject, "tool", name, "allowed", reason == "permitted", "reason", reason, "policy_version", version, "policy_label", label, "rules", rules}
	if isNested {
		attrs = append(attrs, "code_mode_run", nested.Run)
	}
	slog.Info("Cedar authorization", attrs...)
	if reason == "permitted" && builtIn {
		var outer struct {
			Params json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &outer)
		answerCodeMode(w, r, call.ID, name, outer.Params, who, method, oas.GetTykExtension().Info.ID)
		return
	}
	if reason == "permitted" {
		return
	}
	refuse(w, call.ID, "Tool call denied")
}

// driftReason returns why a tool on a proxy under drift enforcement may not
// be called, or "" when Cedar decides: the tool must be approved, and the
// definition its upstream last declared must be the approved one.
func driftReason(state *policy.Snapshot, proxy, name string) string {
	view, enforcing := state.Drift(proxy)
	if !enforcing {
		return ""
	}
	// What this gateway saw, and what any gateway shared, from the reviewed
	// upstream; declarations from another upstream say nothing about its
	// tools.
	observedProxy := drift.ObservedProxy(proxy, view.Upstream())
	latest, at, seen := observed.LatestAt(observedProxy, name)
	current, d, ok := shared.Lookup(state.Version, proxy, name, view.Upstream(), seen)
	if ok && (!seen || d.SeenAt.After(at)) {
		latest, seen = d.Fingerprint, true
	}
	if !current {
		// The shared declarations were not read for this set, after a set
		// change or a failed read; calls wait for a read that succeeds.
		return drift.UnapprovedDefinition
	}
	return drift.CallReason(view, name, latest, seen, observed.Complete(observedProxy))
}

// readBody reads the request body up to the MCP ingress limit of the pinned
// Tyk gateway and puts it back for the upstream.
func readBody(r *http.Request) ([]byte, error) {
	const maxBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err == nil && len(body) > maxBody {
		err = errors.New("request body exceeds the MCP limit")
	}
	return body, err
}

func refuse(w http.ResponseWriter, id json.RawMessage, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32002, "message": message}})
}

func main() {}
