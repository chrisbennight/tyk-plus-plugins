package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The two protocol versions the gateway supports. A client asking for the
// newer one falls back to the older one when a server offers only that.
var versions = []string{"2025-11-25", "2026-07-28"}

type runner struct {
	e        *examples
	creds    *credentials
	sessions map[string]*mcp.ClientSession
	// refusal is the JSON-RPC error of the first refused tool call. Every
	// refusal must match it, so a caller cannot tell an unapproved or unknown
	// tool from one it may not call.
	refusal *rpcError
	passed  int
	failed  []string
}

func run(e *examples) bool {
	// The policy publishes the committed activation checks, so refuse to vouch
	// for a gateway while they disagree with the expected outcomes.
	if err := e.checksCurrent(); err != nil {
		fail(err)
	}
	creds, err := newCredentials(e)
	if err != nil {
		fail(err)
	}
	r := &runner{e: e, creds: creds, sessions: map[string]*mcp.ClientSession{}}
	defer r.close()
	if err := r.waitForServers(); err != nil {
		fail(err)
	}
	// The expectations describe the changing server at version 0, where a
	// review walk-through may have left it elsewhere.
	if d := e.expected.Drift; d != nil {
		if err := setVersion(d.Server, 0); err != nil {
			fail(fmt.Errorf("setting %s to version 0: %w", d.Server, err))
		}
	}
	for _, c := range e.expected.Calls {
		for _, version := range versions {
			cred, err := creds.of(c.Caller)
			if err != nil {
				fail(err)
			}
			r.check(fmt.Sprintf("%s calls %s.%s %s with a %s client: %s", c.Caller, c.Server, c.Tool, arguments(c.Arguments), version, c.Expect),
				c.Caller, cred, version, c.Server, c.Tool, c.Arguments, c.Expect)
		}
	}
	for _, k := range e.expected.KeyAndToken {
		key, err := creds.of(k.Key)
		if err != nil {
			fail(err)
		}
		token, err := creds.of(k.Token)
		if err != nil {
			fail(err)
		}
		for _, version := range versions {
			r.check(fmt.Sprintf("%s key with %s token calls %s.%s with a %s client: %s", k.Key, k.Token, k.Server, k.Tool, version, k.Expect),
				k.Key+"+"+k.Token, key.with(token), version, k.Server, k.Tool, k.Arguments, k.Expect)
		}
	}
	r.listedTools()
	r.refusedCallers()
	r.drift()

	fmt.Printf("\n%d checks passed, %d failed.\n", r.passed, len(r.failed))
	for _, f := range r.failed {
		fmt.Println("FAILED:", f)
	}
	return len(r.failed) == 0
}

func arguments(args map[string]any) string {
	b, _ := json.Marshal(args)
	return string(b)
}

func (r *runner) pass(what string) {
	r.passed++
	fmt.Println("ok  ", what)
}

func (r *runner) fail(what, why string) {
	r.failed = append(r.failed, what+": "+why)
	fmt.Println("FAIL", what+":", why)
}

// check makes one tool call and confirms both the outcome the client sees and
// whether the call reached the server.
func (r *runner) check(what, caller string, cred credential, version, server, tool string, args map[string]any, expect string) {
	session, err := r.session(caller, cred, version, server)
	if err != nil {
		r.fail(what, "could not connect: "+err.Error())
		return
	}
	r.checkCall(what, session, version, server, tool, args, expect)
}

// checkCall makes one tool call on a session and confirms both the outcome the
// client sees and whether the call reached the server.
func (r *runner) checkCall(what string, session *mcp.ClientSession, version, server, tool string, args map[string]any, expect string) {
	before, err := observe(server)
	if err != nil {
		r.fail(what, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, callErr := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	after, err := observe(server)
	if err != nil {
		r.fail(what, err.Error())
		return
	}
	reached := after.Requests - before.Requests
	switch expect {
	case "permitted":
		switch {
		case callErr != nil:
			r.fail(what, "refused: "+callErr.Error())
		case result.IsError:
			r.fail(what, "the tool reported an error")
		case reached != 1 || after.Tool == nil || *after.Tool != tool:
			r.fail(what, fmt.Sprintf("the server received %d requests instead of one call to %s", reached, tool))
		case !sameJSON(after.Arguments, args):
			r.fail(what, fmt.Sprintf("the server received arguments %s, want %s", arguments(after.Arguments), arguments(args)))
		case after.ProtocolVersion != r.wantVersion(server, version):
			r.fail(what, fmt.Sprintf("the server was reached with protocol %q, want %q", after.ProtocolVersion, r.wantVersion(server, version)))
		default:
			r.pass(what)
		}
	default:
		refusal, isRefusal := refusalOf(callErr)
		switch {
		case callErr == nil:
			r.fail(what, "permitted")
		case !isRefusal:
			r.fail(what, "failed without a JSON-RPC refusal: "+callErr.Error())
		case reached != 0:
			r.fail(what, fmt.Sprintf("refused, but the server received %d requests", reached))
		case r.refusal != nil && *refusal != *r.refusal:
			r.fail(what, fmt.Sprintf("refused with %+v, but other refusals were %+v; every refused call must look the same", *refusal, *r.refusal))
		default:
			if r.refusal == nil {
				r.refusal = refusal
			}
			r.pass(what)
		}
	}
}

// listedTools confirms that each caller's tools/list on each server shows
// exactly the tools expected.json names: the approved tools the caller could
// call with some arguments.
func (r *runner) listedTools() {
	for _, caller := range sortedKeys(r.e.expected.Listed) {
		servers := r.e.expected.Listed[caller]
		cred, err := r.creds.of(caller)
		if err != nil {
			fail(err)
		}
		for _, server := range sortedKeys(servers) {
			want := slices.Sorted(slices.Values(servers[server]))
			for _, version := range versions {
				what := fmt.Sprintf("%s lists the tools on %s with a %s client: %v", caller, server, version, want)
				session, err := r.session(caller, cred, version, server)
				if err != nil {
					r.fail(what, "could not connect: "+err.Error())
					continue
				}
				got, err := toolNames(session)
				switch {
				case err != nil:
					r.fail(what, "listing failed: "+err.Error())
				case !slices.Equal(got, want):
					r.fail(what, fmt.Sprintf("listed %v", got))
				default:
					r.pass(what)
				}
			}
		}
	}
}

// toolNames lists every tool a session is shown, across pages, sorted.
func toolNames(session *mcp.ClientSession) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	names := []string{}
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// wantVersion is the protocol version a client asking for version should end
// up using with server.
func (r *runner) wantVersion(server, version string) string {
	if slices.Contains(r.e.expected.OlderProtocolOnly, server) {
		return versions[0]
	}
	return version
}

// rpcError is a JSON-RPC error, every part of which must be the same for every
// refused tool call.
type rpcError struct {
	Code    int64
	Message string
	// Data is the error's data member as raw JSON, empty when absent.
	Data string
}

// refusalOf extracts the JSON-RPC error from a failed call. The client reports
// it either as a JSON-RPC error or, when the gateway answers with an HTTP error
// status, as a transport error whose text carries the response body. A timeout
// or connection failure carries neither and is not a refusal.
func refusalOf(err error) (*rpcError, bool) {
	if err == nil {
		return nil, false
	}
	var wire *jsonrpc.Error
	if errors.As(err, &wire) {
		return &rpcError{wire.Code, wire.Message, string(wire.Data)}, true
	}
	text := err.Error()
	for i := strings.Index(text, "{"); i >= 0; {
		var body struct {
			JSONRPC string `json:"jsonrpc"`
			Error   *struct {
				Code    int64           `json:"code"`
				Message string          `json:"message"`
				Data    json.RawMessage `json:"data"`
			} `json:"error"`
		}
		// Only a well-formed JSON-RPC error counts: a bare HTTP error body does not.
		if json.NewDecoder(strings.NewReader(text[i:])).Decode(&body) == nil && body.JSONRPC == "2.0" &&
			body.Error != nil && body.Error.Code != 0 && body.Error.Message != "" {
			return &rpcError{body.Error.Code, body.Error.Message, string(body.Error.Data)}, true
		}
		next := strings.Index(text[i+1:], "{")
		if next < 0 {
			break
		}
		i += next + 1
	}
	return nil, false
}

// session returns one client session per caller, protocol version and server.
func (r *runner) session(caller string, cred credential, version, server string) (*mcp.ClientSession, error) {
	id := caller + "|" + version + "|" + server
	if s, ok := r.sessions[id]; ok {
		return s, nil
	}
	s, err := connect(cred, version, server, nil)
	if err != nil {
		return nil, err
	}
	if got, want := s.InitializeResult().ProtocolVersion, r.wantVersion(server, version); got != want {
		s.Close()
		return nil, fmt.Errorf("negotiated protocol %q, want %q", got, want)
	}
	r.sessions[id] = s
	return s, nil
}

func (r *runner) close() {
	for _, s := range r.sessions {
		s.Close()
	}
}

func endpoint(server string) string {
	return strings.TrimSuffix(setting("GATEWAY_URL", "http://gateway:8080"), "/") + "/" + server + "/"
}

// connect opens a client session through the gateway. opts may be nil.
func connect(cred credential, version, server string, opts *mcp.ClientOptions) (*mcp.ClientSession, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "examples-runner", Version: "1"}, opts)
	transport := &mcp.StreamableClientTransport{Endpoint: endpoint(server), HTTPClient: &http.Client{Transport: withHeaders(cred), CheckRedirect: noRedirects}}
	return client.Connect(ctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: version})
}

type withHeaders credential

func (h withHeaders) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	for k, v := range h {
		req.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// observed is what a mock server reports outside MCP.
type observed struct {
	Requests        int            `json:"requests"`
	Tool            *string        `json:"tool"`
	Arguments       map[string]any `json:"arguments"`
	ProtocolVersion string         `json:"protocolVersion"`
}

// sameJSON reports whether two argument maps encode to the same JSON, so a
// number read from expected.json equals the same number the server reports.
func sameJSON(a, b map[string]any) bool {
	x, errX := json.Marshal(a)
	y, errY := json.Marshal(b)
	return errX == nil && errY == nil && bytes.Equal(x, y)
}

func observe(server string) (observed, error) {
	var o observed
	body, err := get(fmt.Sprintf(setting("SERVER_URL", "http://%s:8000"), server) + "/requests")
	if err == nil {
		dec := json.NewDecoder(strings.NewReader(body))
		dec.UseNumber() // compare argument numbers exactly
		err = dec.Decode(&o)
	}
	if err != nil {
		return o, fmt.Errorf("reading what %s received: %w", server, err)
	}
	return o, nil
}

func (r *runner) waitForServers() error {
	var servers []string
	for server := range r.e.tools {
		servers = append(servers, server)
	}
	sort.Strings(servers)
	deadline := time.Now().Add(90 * time.Second)
	for {
		var missing []string
		for _, s := range servers {
			if _, err := observe(s); err != nil {
				missing = append(missing, s)
			}
		}
		if _, err := get(setting("ISSUER_URL", "http://issuer:8000") + "/healthz"); err != nil {
			missing = append(missing, "issuer")
		}
		if len(missing) == 0 && gatewayServes(servers[0]) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the gateway or these services are not ready: %v", missing)
		}
		time.Sleep(time.Second)
	}
}

// gatewayServes reports whether the gateway has loaded the proxy for a server.
// It refuses this request, which carries no credential; a proxy that is not
// loaded yet answers 404 instead.
func gatewayServes(server string) bool {
	res, err := httpClient.Post(endpoint(server), "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return false
	}
	res.Body.Close()
	return res.StatusCode != http.StatusNotFound && res.StatusCode < 500
}
