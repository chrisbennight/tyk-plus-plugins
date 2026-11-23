package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

const (
	gateway        = "http://gateway:8080/mcp/"
	olderProtocol  = "2025-11-25"
	newerProtocol  = "2026-07-28"
	unsupportedErr = -32022
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// credential holds the headers that identify a caller. Tokens travel as
// bearer credentials and keys in their own header; a caller may send both.
type credential map[string]string

func keyCred(key string) credential     { return credential{"X-API-Key": key} }
func bearerCred(token string) credential { return credential{"Authorization": "Bearer " + token} }
func (c credential) with(other credential) credential {
	merged := credential{}
	for k, v := range c {
		merged[k] = v
	}
	for k, v := range other {
		merged[k] = v
	}
	return merged
}

// response is one JSON-RPC reply, whether it arrived as plain JSON or as an
// event in a streamed response.
type response struct {
	Status int
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// conn is a JSON-RPC client for exact checks. It speaks either protocol
// version, carries the older protocol's session, and reads plain or
// streamed replies.
type conn struct {
	version string // the version actually in use after negotiation
	session string
}

// connect opens a connection that prefers the given version. A newer client
// tries server/discover first and falls back to the older handshake when the
// upstream does not support it, as the MCP specification requires.
func connect(cred credential, version string) *conn {
	c := &conn{version: version}
	if version == newerProtocol {
		r := c.rpc(cred, "server/discover", map[string]any{})
		var discovered struct {
			SupportedVersions []string `json:"supportedVersions"`
		}
		if r.Status == http.StatusOK && r.Error == nil && json.Unmarshal(r.Result, &discovered) == nil &&
			slices.Contains(discovered.SupportedVersions, newerProtocol) {
			return c
		}
		c.version = olderProtocol
	}
	r := c.rpc(cred, "initialize", map[string]any{"protocolVersion": olderProtocol, "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "probe", "version": "1"}})
	check(r.Status == http.StatusOK && r.Error == nil, "initialize failed: %+v", r)
	if c.session != "" {
		c.notify(cred, "notifications/initialized")
	}
	return c
}

func (c *conn) headers(cred credential, method, name string) http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json, text/event-stream")
	h.Set("MCP-Protocol-Version", c.version)
	if c.version == newerProtocol {
		h.Set("Mcp-Method", method)
		if name != "" {
			h.Set("Mcp-Name", name)
		}
	} else if c.session != "" {
		h.Set("Mcp-Session-Id", c.session)
	}
	for k, v := range cred {
		h.Set(k, v)
	}
	return h
}

func (c *conn) params(params map[string]any) map[string]any {
	if c.version != newerProtocol {
		return params
	}
	out := map[string]any{"_meta": map[string]any{
		"io.modelcontextprotocol/protocolVersion":    newerProtocol,
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "probe", "version": "1"},
	}}
	for k, v := range params {
		out[k] = v
	}
	return out
}

func (c *conn) rpc(cred credential, method string, params map[string]any) response {
	name, _ := params["name"].(string)
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": c.params(params)})
	req, _ := http.NewRequest(http.MethodPost, gateway, bytes.NewReader(body))
	req.Header = c.headers(cred, method, name)
	res, err := httpClient.Do(req)
	check(err == nil, "%s: %v", method, err)
	defer res.Body.Close()
	if id := res.Header.Get("Mcp-Session-Id"); id != "" && method == "initialize" {
		c.session = id
	}
	return decode(res)
}

func (c *conn) notify(cred credential, method string) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": c.params(map[string]any{})})
	req, _ := http.NewRequest(http.MethodPost, gateway, bytes.NewReader(body))
	req.Header = c.headers(cred, method, "")
	res, err := httpClient.Do(req)
	check(err == nil, "%s: %v", method, err)
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
}

// decode reads a plain JSON reply or the first message event of a stream.
func decode(res *http.Response) response {
	var r response
	data, err := io.ReadAll(res.Body)
	check(err == nil, "reading reply: %v", err)
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		data = nil
		for scanner.Scan() {
			if line, ok := strings.CutPrefix(scanner.Text(), "data:"); ok {
				data = []byte(strings.TrimSpace(line))
				break
			}
		}
	}
	if len(bytes.TrimSpace(data)) > 0 {
		check(json.Unmarshal(data, &r) == nil, "unreadable reply %d: %s", res.StatusCode, data)
	}
	r.Status = res.StatusCode
	return r
}

func (r response) String() string {
	if r.Error != nil {
		return fmt.Sprintf("HTTP %d error %d %q", r.Status, r.Error.Code, r.Error.Message)
	}
	return fmt.Sprintf("HTTP %d result %s", r.Status, r.Result)
}

func check(ok bool, format string, args ...any) {
	if !ok {
		panic(fmt.Sprintf(format, args...))
	}
}
