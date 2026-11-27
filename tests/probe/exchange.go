package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// exchangeGateway is the proxy with token exchange on. Its token endpoint
// cannot be reached in this environment, so every request it would forward
// must fail closed.
const exchangeGateway = "http://gateway:8080/mcp3/"

// exchangeSuite checks that a proxy with token exchange on forwards nothing
// it has no exchanged token for: token callers get 503 on every method that
// would reach the upstream, including tool calls the rules permit; a call the
// rules refuse is refused as anywhere else, before any exchange; and key
// callers are refused every request, even for Code Mode's own tools, and do
// not find the proxy's tools through Code Mode on another proxy.
func exchangeSuite(k keys, version string) {
	tools := map[string]any{
		"lookup": map[string]any{"facts": args("readOnly", true), "arguments": args("count", "long")},
		"change": map[string]any{"arguments": args("count", "long")},
	}
	inventory, _ := json.Marshal(map[string]any{
		"governed":  map[string]any{"upstream": upstream, "tools": tools},
		"governed3": map[string]any{"upstream": upstream, "tools": tools},
	})
	publish("activated", map[string]string{"rules.cedar": codeModeRules, "approved_tools.json": string(inventory), "checks.json": "[]"})

	c := &conn{url: exchangeGateway, version: version}
	tok := bearerCred(token("published", args("app_roles", []string{"support"})))
	unavailable := func(what string, send func() response) {
		before, _ := observed()
		r := send()
		after, _ := observed()
		check(r.Status == http.StatusServiceUnavailable && r.Error != nil && r.Error.Code == -32603 && r.Error.Message == "Upstream credentials unavailable" && after == before,
			"%s: %s was not refused for want of an upstream credential: %v (requests %d -> %d)", version, what, r, before, after)
	}
	handshake := "initialize"
	if version == newerProtocol {
		handshake = "server/discover"
	}
	unavailable(handshake, func() response {
		return c.rpc(tok, handshake, map[string]any{"protocolVersion": olderProtocol, "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "probe", "version": "1"}})
	})
	unavailable("tools/list", func() response { return c.rpc(tok, "tools/list", map[string]any{}) })
	if version == olderProtocol {
		// A notification has no ID for a JSON-RPC error, so it gets the
		// status alone.
		before, _ := observed()
		status := c.notifyStatus(tok, "notifications/initialized")
		after, _ := observed()
		check(status == http.StatusServiceUnavailable && after == before, "%s: notification got %d (requests %d -> %d)", version, status, before, after)
	}
	// The rules permit this call, so it needs an exchanged token.
	unavailable("a permitted tool call", func() response {
		return c.rpc(tok, "tools/call", map[string]any{"name": "lookup", "arguments": args("count", 1)})
	})
	// The rules refuse this call, so it is refused like any other, without
	// an exchange.
	call(c, tok, "change", args("count", 2))

	// A key caller has no token to exchange, so it is refused every request,
	// including Code Mode's tools, which the plug-in answers itself.
	tokenOnly := func(what string, r response, before, after int) {
		check(r.Status == http.StatusForbidden && r.Error != nil && r.Error.Message == "This proxy accepts token callers only" && after == before,
			"%s: key caller's %s on the exchange proxy: %v (requests %d -> %d)", version, what, r, before, after)
	}
	before, _ := observed()
	r := c.rpc(k.support, "tools/list", map[string]any{})
	after, _ := observed()
	tokenOnly("tools/list", r, before, after)
	before, _ = observed()
	r = c.rpc(k.support, "tools/call", map[string]any{"name": "codemode.search", "arguments": map[string]any{"query": "lookup"}})
	after, _ = observed()
	tokenOnly("codemode.search", r, before, after)
	// Through Code Mode on another proxy, a key caller does not find the
	// exchange proxy's tools, which it could not call.
	found := searchNames(connect(k.support, version), k.support, "lookup")
	check(slices.Contains(found, "governed/lookup") && !slices.ContainsFunc(found, func(n string) bool { return strings.HasPrefix(n, "governed3/") }),
		"%s: key caller's search found %v", version, found)
	fmt.Printf("Verified that token exchange fails closed for a %s client.\n", version)
}
