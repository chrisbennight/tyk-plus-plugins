package main

import (
	"fmt"
	"net/http"
)

// exchangeGateway is the proxy with token exchange on. Its token endpoint
// cannot be reached in this environment, so every request it would forward
// must fail closed.
const exchangeGateway = "http://gateway:8080/mcp3/"

// exchangeSuite checks that a proxy with token exchange on forwards nothing
// it has no exchanged token for: token callers get 503 on every method that
// would reach the upstream, key callers are refused, and a call the rules
// refuse is refused as anywhere else, before any exchange.
func exchangeSuite(k keys, version string) {
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
	// A key caller has no token to exchange.
	before, _ := observed()
	r := c.rpc(k.support, "tools/list", map[string]any{})
	after, _ := observed()
	check(r.Status == http.StatusForbidden && r.Error != nil && r.Error.Message == "This proxy accepts token callers only" && after == before,
		"%s: key caller on the exchange proxy: %v (requests %d -> %d)", version, r, before, after)
	// The rules refuse this call, so it is refused like any other, without
	// an exchange.
	call(c, tok, "lookup", args())
	fmt.Printf("Verified that token exchange fails closed for a %s client.\n", version)
}
