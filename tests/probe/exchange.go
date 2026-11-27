package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// exchangeGateway is the proxy with token exchange on. The test upstream is
// also its token endpoint, and accepts only tokens it issued.
const exchangeGateway = "http://gateway:8080/mcp3/"

// unlistedGateway leaves credential stripping off like the exchange proxy,
// but is missing from the exchange settings, as a mistyped proxy ID would
// leave it, so it must refuse to forward rather than pass the caller's
// credential on.
const unlistedGateway = "http://gateway:8080/mcp4/"

// exchanged reports how many token exchanges the test token endpoint
// received, and how many upstream requests carried a token it issued.
func exchanged() (exchanges, withIssuedToken int) {
	res, err := httpClient.Get("http://upstream:8000/requests")
	check(err == nil, "upstream: %v", err)
	defer res.Body.Close()
	var body struct {
		Exchanges       int `json:"exchanges"`
		WithIssuedToken int `json:"withIssuedToken"`
	}
	check(json.NewDecoder(res.Body).Decode(&body) == nil, "upstream reply")
	return body.Exchanges, body.WithIssuedToken
}

// exchangeSuite checks token exchange end to end. A token caller's requests
// reach the upstream with a token the token endpoint issued, never the
// caller's own; when the exchange fails, nothing is forwarded; a call the
// rules refuse is refused before any exchange; and key callers are refused
// every request, even for Code Mode's own tools, and do not find the proxy's
// tools through Code Mode on another proxy.
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

	// The upstream accepts only tokens the token endpoint issued, so every
	// request below that succeeds carried an exchanged token.
	// The token is distinct for each version, so neither finds the other's
	// exchanged token cached.
	tok := bearerCred(token("published", args("app_roles", []string{"support"}, "jti", "exchange-"+version)))
	// Every request each step sends upstream must carry an issued token.
	allIssued := func(what string, step func()) {
		requestsBefore, _ := observed()
		_, issuedBefore := exchanged()
		step()
		requestsAfter, _ := observed()
		_, issuedAfter := exchanged()
		check(requestsAfter > requestsBefore && issuedAfter-issuedBefore == requestsAfter-requestsBefore,
			"%s: %s sent %d requests upstream, %d with an issued token", version, what, requestsAfter-requestsBefore, issuedAfter-issuedBefore)
	}
	exchangesBefore, _ := exchanged()
	var c *conn
	allIssued("the handshake", func() { c = connectAt(exchangeGateway, tok, version) })
	allIssued("tools/list", func() {
		catalog := catalogOf(c, tok)
		check(catalog["lookup"] != nil, "%s: the exchange proxy listed %v", version, catalog)
	})
	allIssued("a permitted call", func() { call(c, tok, "lookup", args("count", 1), "found") })
	exchangesAfter, _ := exchanged()
	// One exchange serves the caller's requests while its token is cached.
	check(exchangesAfter-exchangesBefore == 1, "%s: exchanges %d -> %d", version, exchangesBefore, exchangesAfter)
	// The rules refuse this call, so it is refused like any other, without
	// an exchange. The caller's token is new, so an exchange attempt could
	// not be hidden by the cache.
	fresh := bearerCred(token("published", args("app_roles", []string{"support"}, "jti", "exchange-refused-"+version)))
	call(c, fresh, "change", args("count", 2))
	exchangesRefused, _ := exchanged()
	check(exchangesRefused == exchangesAfter, "%s: a refused call was exchanged: %d -> %d", version, exchangesAfter, exchangesRefused)

	// The token endpoint refuses this caller, so nothing is forwarded.
	refused := bearerCred(token("published", args("sub", "refused", "app_roles", []string{"support"})))
	unavailable := func(what string, send func() response) {
		before, _ := observed()
		exchangesBefore, _ := exchanged()
		r := send()
		after, _ := observed()
		exchangesAfter, _ := exchanged()
		check(r.Status == http.StatusServiceUnavailable && r.Error != nil && r.Error.Code == -32603 && r.Error.Message == "Upstream credentials unavailable" &&
			after == before && exchangesAfter == exchangesBefore+1,
			"%s: %s after a refused exchange: %v (requests %d -> %d, exchanges %d -> %d)", version, what, r, before, after, exchangesBefore, exchangesAfter)
	}
	failed := &conn{url: exchangeGateway, version: version}
	handshake := "initialize"
	if version == newerProtocol {
		handshake = "server/discover"
	}
	unavailable(handshake, func() response {
		return failed.rpc(refused, handshake, map[string]any{"protocolVersion": olderProtocol, "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "probe", "version": "1"}})
	})
	unavailable("tools/list", func() response { return failed.rpc(refused, "tools/list", map[string]any{}) })
	unavailable("a permitted tool call", func() response {
		return failed.rpc(refused, "tools/call", map[string]any{"name": "lookup", "arguments": args("count", 1)})
	})
	if version == olderProtocol {
		// A notification, the event stream and the session teardown carry
		// no ID for a JSON-RPC error, so they get the status alone.
		notification, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}})
		for _, request := range []struct {
			what, method string
			body         []byte
		}{{"notification", http.MethodPost, notification}, {"event stream", http.MethodGet, nil}, {"session teardown", http.MethodDelete, nil}} {
			before, _ := observed()
			exchangesBefore, _ := exchanged()
			status, body := failed.bare(refused, request.method, request.body)
			after, _ := observed()
			exchangesAfter, _ := exchanged()
			check(status == http.StatusServiceUnavailable && strings.TrimSpace(body) == "" && after == before && exchangesAfter == exchangesBefore+1,
				"%s: %s after a refused exchange got %d %q (requests %d -> %d, exchanges %d -> %d)",
				version, request.what, status, body, before, after, exchangesBefore, exchangesAfter)
		}
	}

	// A proxy that leaves stripping off without exchange forwards nothing,
	// for token and key callers alike, and makes no exchange.
	unlisted := &conn{url: unlistedGateway, version: version}
	for name, cred := range map[string]credential{"token": tok, "key": k.support} {
		before, _ := observed()
		exchangesBefore, _ := exchanged()
		r := unlisted.rpc(cred, "tools/list", map[string]any{})
		after, _ := observed()
		exchangesAfter, _ := exchanged()
		check(r.Status == http.StatusServiceUnavailable && r.Error != nil && r.Error.Message == "Upstream credentials unavailable" &&
			after == before && exchangesAfter == exchangesBefore,
			"%s: %s caller on a proxy with stripping off and no exchange: %v (requests %d -> %d, exchanges %d -> %d)",
			version, name, r, before, after, exchangesBefore, exchangesAfter)
	}

	// A key caller has no token to exchange, so it is refused every request,
	// including Code Mode's tools, which the plug-in answers itself.
	tokenOnly := func(what string, send func() response) {
		before, _ := observed()
		r := send()
		after, _ := observed()
		check(r.Status == http.StatusForbidden && r.Error != nil && r.Error.Message == "This proxy accepts token callers only" && after == before,
			"%s: key caller's %s on the exchange proxy: %v (requests %d -> %d)", version, what, r, before, after)
	}
	tokenOnly("tools/list", func() response { return failed.rpc(k.support, "tools/list", map[string]any{}) })
	tokenOnly("codemode.search", func() response {
		return failed.rpc(k.support, "tools/call", map[string]any{"name": "codemode.search", "arguments": map[string]any{"query": "lookup"}})
	})
	// Through Code Mode on another proxy, a key caller does not find the
	// exchange proxy's tools, which it could not call.
	found := searchNames(connect(k.support, version), k.support, "lookup")
	check(slices.Contains(found, "governed/lookup") && !slices.ContainsFunc(found, func(n string) bool { return strings.HasPrefix(n, "governed3/") }),
		"%s: key caller's search found %v", version, found)
	fmt.Printf("Verified token exchange for a %s client.\n", version)
}

// bare sends a request of the older protocol that has no JSON-RPC ID, in a
// session the gateway never forwards, and returns its status and body.
func (c *conn) bare(cred credential, method string, body []byte) (int, string) {
	req, _ := http.NewRequest(method, c.url, bytes.NewReader(body))
	req.Header = c.headers(cred, "", "")
	req.Header.Set("Mcp-Session-Id", "never-forwarded")
	if method == http.MethodGet {
		req.Header.Set("Accept", "text/event-stream")
	}
	res, err := httpClient.Do(req)
	check(err == nil, "%s: %v", method, err)
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	return res.StatusCode, string(data)
}
