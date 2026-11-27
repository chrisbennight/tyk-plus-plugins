package main

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/identity"
)

// OneCredential is a Tyk hook that runs before authentication. A request that
// carries credentials for more than one of the proxy's security schemes has
// no single caller, so it is refused before Tyk tries any of them. This also
// keeps such requests away from a Tyk defect: when one scheme rejects a
// credential and a later one accepts another, an MCP proxy forwards the
// request without its body. The policy guide links the upstream report.
func OneCredential(w http.ResponseWriter, r *http.Request) {
	if identity.Credentials(r.Header, credentialHeaders(r)) <= 1 {
		return
	}
	var envelope struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	body, _ := readBody(r)
	_ = json.Unmarshal(body, &envelope)
	// The method Tyk parsed is logged, never the caller's own string, which
	// could be as long as the body.
	slog.Info("Caller refused", "method", ctx.GetMCPMethod(r), "reason", "multiple_credentials")
	// Tool calls get the one refusal every denied tool call gets.
	message := "Caller not identified"
	if envelope.Method == "tools/call" {
		message = "Tool call denied"
	}
	refuse(w, envelope.ID, message)
}

// credentialHeaders lists the request headers that carry the proxy's
// credentials: the header of each header API key scheme, and Authorization
// for HTTP, OAuth 2.0 and OpenID Connect schemes.
func credentialHeaders(r *http.Request) []string {
	oas := ctx.GetOASDefinition(r)
	if oas == nil || oas.Components == nil {
		return nil
	}
	var names []string
	for _, scheme := range oas.Components.SecuritySchemes {
		if scheme == nil || scheme.Value == nil {
			continue
		}
		switch s := scheme.Value; s.Type {
		case "apiKey":
			if s.In == "header" && s.Name != "" {
				names = append(names, s.Name)
			}
		case "http", "oauth2", "openIdConnect":
			names = append(names, "Authorization")
		}
	}
	return names
}
