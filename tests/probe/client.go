package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	gateway        = "http://gateway:8080/mcp/"
	olderProtocol  = "2025-11-25"
	newerProtocol  = "2026-07-28"
	methodNotFound = -32601
	// tykInvalidDiscovery is the error Tyk returns when an upstream cannot
	// answer server/discover.
	tykInvalidDiscovery = -33006
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// credential holds the headers that identify a caller. Tokens travel as
// bearer credentials and keys in their own header; a caller may send both.
type credential map[string]string

func keyCred(key string) credential      { return credential{"X-API-Key": key} }
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
	// Raw is the whole JSON-RPC message, so refusals can be compared exactly.
	Raw     json.RawMessage `json:"-"`
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data,omitempty"`
	} `json:"error"`
}

// conn is a JSON-RPC client for exact checks. It speaks either protocol
// version, carries the older protocol's session, and reads plain or
// streamed replies.
type conn struct {
	version string // the version actually in use after negotiation
	session string
	lastID  int
	// lastStreamed records whether the last reply arrived as a stream.
	lastStreamed bool
	// discovery records what server/discover did for a newer client: the
	// newer version was offered, only older versions were offered, or the
	// method was not supported at all.
	discovery string
}

const (
	discoveryNewer       = "newer"
	discoveryOlderOnly   = "older-only"
	discoveryUnsupported = "unsupported"
)

// connect opens a connection that prefers the given version. A newer client
// tries server/discover first and falls back to the older handshake when the
// server does not offer the newer version, as the MCP specification requires.
func connect(cred credential, version string) *conn {
	c := &conn{version: version}
	if version == newerProtocol {
		r := c.rpc(cred, "server/discover", map[string]any{})
		if r.Status == http.StatusOK && r.Error == nil {
			var discovered struct {
				SupportedVersions []string `json:"supportedVersions"`
			}
			check(json.Unmarshal(r.Result, &discovered) == nil && len(discovered.SupportedVersions) > 0,
				"server/discover succeeded without listing versions: %v", r)
			if slices.Contains(discovered.SupportedVersions, newerProtocol) {
				c.discovery = discoveryNewer
				return c
			}
			check(slices.Contains(discovered.SupportedVersions, olderProtocol), "server/discover offered neither supported version: %v", discovered.SupportedVersions)
			c.discovery = discoveryOlderOnly
		} else {
			// A server that does not know the newer protocol answers "method not
			// found" or rejects the version outright. Tyk reports an upstream's
			// rejection as its own error saying the discovery response is invalid;
			// clients fall back on either.
			check(r.Error != nil && (r.Error.Code == methodNotFound || r.Error.Code == tykInvalidDiscovery),
				"server/discover failed for another reason: %v", r)
			c.discovery = discoveryUnsupported
		}
		c.version = olderProtocol
	}
	r := c.rpc(cred, "initialize", map[string]any{"protocolVersion": olderProtocol, "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "probe", "version": "1"}})
	var initialized struct {
		ProtocolVersion string                `json:"protocolVersion"`
		ServerInfo      struct{ Name string } `json:"serverInfo"`
	}
	check(r.Status == http.StatusOK && r.Error == nil && json.Unmarshal(r.Result, &initialized) == nil &&
		initialized.ServerInfo.Name == "test-upstream" && initialized.ProtocolVersion == olderProtocol, "initialize failed: %v", r)
	c.notify(cred, "notifications/initialized")
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

// rpc sends one request with a fresh ID. A JSON-RPC reply must echo that ID.
func (c *conn) rpc(cred credential, method string, params map[string]any) response {
	name, _ := params["name"].(string)
	c.lastID++
	id := c.lastID
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": c.params(params)})
	req, _ := http.NewRequest(http.MethodPost, gateway, bytes.NewReader(body))
	req.Header = c.headers(cred, method, name)
	res, err := httpClient.Do(req)
	check(err == nil, "%s: %v", method, err)
	defer res.Body.Close()
	if id := res.Header.Get("Mcp-Session-Id"); id != "" && method == "initialize" {
		c.session = id
	}
	c.lastStreamed = strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream")
	r := decode(res, id)
	// A reply that carries a result or an error must be JSON-RPC and echo the ID.
	if r.JSONRPC != "" || r.Result != nil || r.Error != nil {
		check(r.JSONRPC == "2.0" && string(r.ID) == strconv.Itoa(id), "%s: reply %s does not answer request %d", method, r.Raw, id)
	}
	return r
}

func (c *conn) notify(cred credential, method string) {
	check(c.notifyStatus(cred, method) < 300, "%s was refused", method)
}

// notifyStatus sends a notification and returns the HTTP status.
func (c *conn) notifyStatus(cred credential, method string) int {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": c.params(map[string]any{})})
	req, _ := http.NewRequest(http.MethodPost, gateway, bytes.NewReader(body))
	req.Header = c.headers(cred, method, "")
	res, err := httpClient.Do(req)
	check(err == nil, "%s: %v", method, err)
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res.StatusCode
}

// decode reads a plain JSON reply, or the message in a stream that answers
// the request, skipping any notifications sent before it.
func decode(res *http.Response, id int) response {
	var r response
	data, err := io.ReadAll(res.Body)
	check(err == nil, "reading reply: %v", err)
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		data = nil
		for scanner.Scan() {
			line, ok := strings.CutPrefix(scanner.Text(), "data:")
			if !ok {
				continue
			}
			var message struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal([]byte(line), &message) == nil && string(message.ID) == strconv.Itoa(id) {
				data = []byte(strings.TrimSpace(line))
				break
			}
		}
	}
	if len(bytes.TrimSpace(data)) > 0 {
		check(json.Unmarshal(data, &r) == nil, "unreadable reply %d: %s", res.StatusCode, data)
		r.Raw = data
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
