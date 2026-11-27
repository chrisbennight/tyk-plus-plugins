package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/exchange"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/identity"
)

// Token exchange state, set once when the plug-in loads.
var (
	// exchangeSettings is nil when token exchange is not configured.
	exchangeSettings *exchange.Settings
	// exchangeProblem explains why configured token exchange cannot run;
	// every proxy with exchange on then refuses requests it would forward.
	exchangeProblem string
	exchanger       *exchange.Client
)

func init() {
	settings, err := exchange.Load(os.Getenv)
	if settings == nil {
		return
	}
	exchangeSettings = settings
	if err != nil {
		exchangeProblem = err.Error()
		slog.Error("Token exchange is unavailable", "reason", exchangeProblem)
		return
	}
	exchanger = exchange.New(settings)
	slog.Info("Token exchange is on", "proxies", len(settings.Proxies))
}

// exchangeOn reports whether a request's proxy forwards exchanged tokens.
func exchangeOn(r *http.Request) bool {
	return exchangeSettings.On(proxyOf(r))
}

func proxyOf(r *http.Request) string {
	if def := ctx.GetOASDefinition(r); def != nil && def.GetTykExtension() != nil {
		return def.GetTykExtension().Info.ID
	}
	return ""
}

// upstreamCredential sets the credential a permitted request carries to its
// upstream. On a proxy with exchange on, that is a token the identity
// provider issued to the upstream for the caller; on failure it writes the
// refusal and returns false, and the request must not be forwarded. id is the
// request's JSON-RPC ID when it has already been read, or nil.
func upstreamCredential(w http.ResponseWriter, r *http.Request, method identity.Method, data map[string]any, id json.RawMessage) bool {
	if !exchangeOn(r) {
		return true
	}
	proxy := proxyOf(r)
	if method != identity.Token {
		// A key caller has no token to exchange.
		slog.Info("Caller refused", "identity", method, "method", ctx.GetMCPMethod(r), "proxy", proxy, "reason", "token_required")
		refuse(w, jsonRPCID(r, id), "This proxy accepts token callers only")
		return false
	}
	reason := ""
	switch {
	case exchangeProblem != "":
		reason = "exchange_unavailable"
	case stripsAuthorization(ctx.GetOASDefinition(r)):
		reason = "strip_authorization_data_on"
	case conflictingUpstreamAuth(ctx.GetOASDefinition(r)):
		reason = "conflicting_upstream_credential"
	}
	if reason != "" {
		slog.Warn("Upstream credential unavailable", "proxy", proxy, "method", ctx.GetMCPMethod(r), "reason", reason)
		unavailable(w, r, id)
		return false
	}
	bearer, _ := r.Context().Value(bearerKey{}).(string)
	subject := bearerToken(bearer)
	expiry, ok := identity.Expiry(data)
	if subject == "" || !ok {
		slog.Warn("Upstream credential unavailable", "proxy", proxy, "method", ctx.GetMCPMethod(r), "reason", "no_caller_token")
		unavailable(w, r, id)
		return false
	}
	token, err := exchanger.Exchange(r.Context(), proxy, subject, expiry)
	if err != nil {
		// The exchange logged why, without the tokens.
		unavailable(w, r, id)
		return false
	}
	r.Header.Set("Authorization", "Bearer "+token)
	return true
}

// bearerToken returns the token of an Authorization header using the Bearer
// scheme, whose name is case-insensitive, and empty otherwise.
func bearerToken(header string) string {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// stripsAuthorization reports whether Tyk strips the caller's credential
// from the request. On an MCP proxy Tyk strips it again on each internal pass
// of a request, where the plug-in's hooks do not run, so it would also remove
// the exchanged token. A proxy with exchange on must leave stripping to the
// plug-in, which replaces the caller's token or refuses the request.
func stripsAuthorization(def *oas.OAS) bool {
	if def == nil || def.GetTykExtension() == nil {
		return false
	}
	auth := def.GetTykExtension().Server.Authentication
	return auth != nil && auth.StripAuthorizationData
}

// conflictingUpstreamAuth reports whether Tyk itself is configured to set the
// upstream's credential, through upstream authentication or an Authorization
// header added to every request. Either could replace or contradict the
// exchanged token, so such a proxy refuses its requests instead.
func conflictingUpstreamAuth(def *oas.OAS) bool {
	if def == nil || def.GetTykExtension() == nil {
		return false
	}
	ext := def.GetTykExtension()
	if auth := ext.Upstream.Authentication; auth != nil && auth.Enabled {
		return true
	}
	if ext.Middleware != nil && ext.Middleware.Global != nil {
		if headers := ext.Middleware.Global.TransformRequestHeaders; headers != nil && headers.Enabled {
			for _, h := range headers.Add {
				if strings.EqualFold(h.Name, "Authorization") {
					return true
				}
			}
		}
	}
	return false
}

// unavailable answers a request the gateway cannot forward because it has no
// credential for the upstream: 503, with a JSON-RPC error when the request
// has an ID. Notifications, and the GET and DELETE requests of the older
// protocol, carry no ID, so they get the status alone.
func unavailable(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
	id = jsonRPCID(r, id)
	if len(bytes.TrimSpace(id)) == 0 || string(id) == "null" {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32603, "message": "Upstream credentials unavailable"}})
}

// jsonRPCID returns id when it is known, and otherwise reads the request's
// JSON-RPC ID from its body, which is put back for the upstream.
func jsonRPCID(r *http.Request, id json.RawMessage) json.RawMessage {
	if id != nil || r.Method != http.MethodPost {
		return id
	}
	var envelope struct {
		ID json.RawMessage `json:"id"`
	}
	body, _ := readBody(r)
	_ = json.Unmarshal(body, &envelope)
	return envelope.ID
}
