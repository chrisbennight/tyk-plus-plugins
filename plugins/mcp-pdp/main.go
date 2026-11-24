package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
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
	default:
		reason = "invalid_call"
		proxy := oas.GetTykExtension().Info.ID
		if validBody && call.Method == "tools/call" && call.Params.Name == name {
			// Under drift enforcement a tool must be approved, and the
			// definition its upstream last declared must be the approved one.
			if view, enforcing := state.Drift(proxy); enforcing {
				latest, seen := observed.Latest(proxy, name)
				reason = drift.CallReason(view, name, latest, seen)
			} else {
				reason = ""
			}
			if reason == "" {
				reason, rules = state.Decide(who, proxy, oas.GetTykExtension().Upstream.URL, name, call.Params.Arguments)
			}
		}
	}
	slog.Info("Cedar authorization", "identity", method, "issuer", who.Issuer, "subject", who.Subject, "tool", name, "allowed", reason == "permitted", "reason", reason, "policy_version", version, "policy_label", label, "rules", rules)
	if reason == "permitted" {
		return
	}
	refuse(w, call.ID, "Tool call denied")
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
