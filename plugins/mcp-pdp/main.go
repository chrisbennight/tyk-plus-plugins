package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/identity"
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
	// Every request needs an identifiable caller, not only tool calls, so a
	// credential the plug-in rejects cannot reach any other MCP method.
	if callerErr != nil {
		slog.Info("Caller refused", "identity", method, "method", ctx.GetMCPMethod(r), "reason", "invalid_caller")
		refuse(w, nil, "Caller not identified")
		return
	}
	if ctx.GetMCPMethod(r) != "tools/call" {
		return
	}
	name := ctx.GetMCPPrimitiveName(r)
	oas := ctx.GetOASDefinition(r)
	state := current()
	var call struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	// Match the MCP ingress limit in the pinned Tyk gateway.
	const maxBody = 1 << 20
	body, readErr := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	r.Body = io.NopCloser(bytes.NewReader(body))
	validBody := readErr == nil && len(body) <= maxBody && jsonv2.Unmarshal(body, &call) == nil
	var rules []string
	version, label, reason := "", "", "unavailable"
	if state != nil {
		version, label = state.Version, state.Label
	}
	switch {
	case state == nil:
	case oas == nil || oas.GetTykExtension() == nil:
		reason = "missing_proxy"
	default:
		reason = "invalid_call"
		if validBody && call.Method == "tools/call" && call.Params.Name == name {
			reason, rules = state.Decide(who, oas.GetTykExtension().Info.ID, oas.GetTykExtension().Upstream.URL, name, call.Params.Arguments)
		}
	}
	slog.Info("Cedar authorization", "identity", method, "issuer", who.Issuer, "subject", who.Subject, "tool", name, "allowed", reason == "permitted", "reason", reason, "policy_version", version, "policy_label", label, "rules", rules)
	if reason == "permitted" {
		return
	}
	refuse(w, call.ID, "Tool call denied")
}

func refuse(w http.ResponseWriter, id json.RawMessage, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32002, "message": message}})
}

func main() {}
