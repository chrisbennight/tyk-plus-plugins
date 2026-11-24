package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// refusedCallers checks that callers the gateway cannot identify are refused
// on every MCP method, and that none of their requests reach a server.
func (r *runner) refusedCallers() {
	const server = "directory"
	for _, name := range r.e.expected.RefusedCallers {
		cred, err := r.refusedCredential(name)
		if err != nil {
			r.fail(name, err.Error())
			continue
		}
		before, err := observe(server)
		if err != nil {
			r.fail(name, err.Error())
			continue
		}
		for _, version := range versions {
			what := fmt.Sprintf("%s is refused when connecting with a %s client", name, version)
			if s, err := connect(cred, version, server); err == nil {
				s.Close()
				r.fail(what, "connected")
			} else {
				r.pass(what)
			}
		}
		for _, method := range []string{"tools/list", "tools/call"} {
			what := fmt.Sprintf("%s is refused on %s", name, method)
			if status, err := rawRequest(cred, server, method); err != nil {
				r.fail(what, err.Error())
			} else if status != http.StatusUnauthorized && status != http.StatusForbidden {
				r.fail(what, fmt.Sprintf("answered %d", status))
			} else {
				r.pass(what)
			}
		}
		after, err := observe(server)
		what := name + "'s requests never reach the server"
		switch {
		case err != nil:
			r.fail(what, err.Error())
		case after.Requests != before.Requests:
			r.fail(what, fmt.Sprintf("the server received %d requests", after.Requests-before.Requests))
		default:
			r.pass(what)
		}
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
	case "key-without-metadata":
		key, err := createKey(r.e.proxies(), map[string]any{})
		if err != nil {
			return nil, err
		}
		return credential{"X-API-Key": key}, nil
	default:
		return nil, fmt.Errorf("the runner does not know how to build the refused caller %q", name)
	}
	return signed(claims, false)
}

// rawRequest sends one newer-protocol request without a client library, so a
// refusal is seen exactly as the gateway sends it.
func rawRequest(cred credential, server, method string) (int, error) {
	params := map[string]any{"_meta": map[string]any{
		"io.modelcontextprotocol/protocolVersion":    versions[1],
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "examples-runner", "version": "1"},
	}}
	if method == "tools/call" {
		params["name"] = "search"
		params["arguments"] = map[string]any{"query": "x"}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, _ := http.NewRequest(http.MethodPost, endpoint(server), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", versions[1])
	req.Header.Set("Mcp-Method", method)
	if method == "tools/call" {
		req.Header.Set("Mcp-Name", "search")
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
