package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
	jsonv2 "github.com/go-json-experiment/json"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
	if ctx.GetMCPMethod(r) != "tools/call" {
		return
	}
	name := ctx.GetMCPPrimitiveName(r)
	var who policy.Caller
	if session := ctx.GetSession(r); session != nil {
		data, err := json.Marshal(session.MetaData["cedar"])
		if err == nil {
			if err = json.Unmarshal(data, &who); err != nil {
				who = policy.Caller{}
			}
		}
	}
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
	case who.Issuer == "" || who.Subject == "":
		reason = "invalid_caller_metadata"
	case oas == nil || oas.GetTykExtension() == nil:
		reason = "missing_proxy"
	default:
		reason = "invalid_call"
		if validBody && call.Method == "tools/call" && call.Params.Name == name {
			reason, rules = state.Decide(who, oas.GetTykExtension().Info.ID, oas.GetTykExtension().Upstream.URL, name, call.Params.Arguments)
		}
	}
	slog.Info("Cedar authorization", "issuer", who.Issuer, "subject", who.Subject, "tool", name, "allowed", reason == "permitted", "reason", reason, "policy_version", version, "policy_label", label, "rules", rules)
	if reason == "permitted" {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "error": map[string]any{"code": -32002, "message": "Tool call denied"}})
}

func main() {}
