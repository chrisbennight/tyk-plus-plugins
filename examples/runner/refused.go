package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// refusedCallers checks that callers the gateway cannot identify cannot
// connect in either protocol version, are refused on each method a client sends
// first (initialize, its notification, server/discover, tools/list and
// tools/call), and that none of their requests reach a server.
func (r *runner) refusedCallers() {
	for _, name := range r.e.expected.RefusedCallers {
		cred, err := r.refusedCredential(name)
		if err != nil {
			r.fail(name, err.Error())
			continue
		}
		// Each proxy authenticates on its own, so every one must refuse.
		for _, server := range r.e.proxies() {
			r.refusedOn(name, cred, server)
		}
	}
}

func (r *runner) refusedOn(name string, cred credential, server string) {
	before, err := observe(server)
	if err != nil {
		r.fail(name, err.Error())
		return
	}
	for _, version := range versions {
		what := fmt.Sprintf("%s is refused when connecting to %s with a %s client", name, server, version)
		if s, err := connect(cred, version, server, nil); err == nil {
			s.Close()
			r.fail(what, "connected")
		} else {
			r.pass(what)
		}
	}
	for _, req := range []struct{ version, method string }{
		{versions[0], "initialize"}, {versions[0], "notifications/initialized"}, {versions[0], "tools/list"}, {versions[0], "tools/call"},
		{versions[1], "server/discover"}, {versions[1], "tools/list"}, {versions[1], "tools/call"},
	} {
		what := fmt.Sprintf("%s is refused on %s %s (%s)", name, server, req.method, req.version)
		if status, err := rawRequest(cred, server, r.e.someTool(server), req.version, req.method); err != nil {
			r.fail(what, err.Error())
		} else if status != http.StatusUnauthorized && status != http.StatusForbidden {
			r.fail(what, fmt.Sprintf("answered %d", status))
		} else {
			r.pass(what)
		}
	}
	after, err := observe(server)
	what := fmt.Sprintf("%s's requests never reach %s", name, server)
	switch {
	case err != nil:
		r.fail(what, err.Error())
	case after.Requests != before.Requests:
		r.fail(what, fmt.Sprintf("the server received %d requests", after.Requests-before.Requests))
	default:
		r.pass(what)
	}
}

// refusedCredential builds a credential that must not identify anyone.
func (r *runner) refusedCredential(name string) (credential, error) {
	d := r.e.deck
	valid := func() map[string]any {
		return map[string]any{"iss": d.Issuer, "aud": d.Audience, "sub": "intruder", "roles": []string{"admin"}, "exp": time.Now().Add(time.Hour).Unix()}
	}
	claims := valid()
	switch name {
	case "no-credential":
		return credential{}, nil
	case "expired-token":
		claims["exp"] = time.Now().Add(-time.Minute).Unix()
	case "other-audience-token":
		claims["aud"] = "another-gateway"
	case "no-subject-token":
		delete(claims, "sub")
	case "malformed-roles-token":
		claims["roles"] = map[string]any{"admin": true}
	case "unpublished-key-token":
		return signed(claims, true)
	case "key-and-token", "unknown-key-and-token":
		// A request carrying a key and a valid token has no single caller,
		// whether or not the key is valid.
		key := credential{"X-API-Key": "not-a-key"}
		if name == "key-and-token" {
			var err error
			if key, err = r.creds.of("deployer"); err != nil {
				return nil, err
			}
		}
		token, err := signed(valid(), false)
		if err != nil {
			return nil, err
		}
		return key.with(token), nil
	case "key-without-metadata":
		key := os.Getenv("EXAMPLE_KEY_WITHOUT_METADATA_KEY")
		if key == "" {
			var err error
			if key, err = createKey(r.e.proxies(), map[string]any{}); err != nil {
				return nil, err
			}
		}
		return credential{"X-API-Key": key}, nil
	default:
		return nil, fmt.Errorf("the runner does not know how to build the refused caller %q", name)
	}
	return signed(claims, false)
}

// rawRequest sends one request without a client library, so a refusal is seen
// exactly as the gateway sends it.
func rawRequest(cred credential, server, tool, version, method string) (int, error) {
	params := map[string]any{}
	if version == versions[1] {
		params["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    version,
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "examples-runner", "version": "1"},
		}
	}
	switch method {
	case "initialize":
		params["protocolVersion"] = version
		params["capabilities"] = map[string]any{}
		params["clientInfo"] = map[string]any{"name": "examples-runner", "version": "1"}
	case "tools/call":
		// An approved tool, so a refusal comes from the caller check rather
		// than from the tool being unknown.
		params["name"] = tool
		params["arguments"] = map[string]any{}
	}
	message := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
	if !strings.HasPrefix(method, "notifications/") {
		message["id"] = 1
	}
	body, _ := json.Marshal(message)
	req, _ := http.NewRequest(http.MethodPost, endpoint(server), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if method != "initialize" {
		req.Header.Set("MCP-Protocol-Version", version)
	}
	if version == versions[1] {
		req.Header.Set("Mcp-Method", method)
		if method == "tools/call" {
			req.Header.Set("Mcp-Name", tool)
		}
	}
	for k, v := range cred {
		req.Header.Set(k, v)
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	res.Body.Close()
	return res.StatusCode, nil
}

// someTool returns an approved tool on server, the first by name.
func (e *examples) someTool(server string) string {
	var names []string
	for name := range e.tools[server].Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}
