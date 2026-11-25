package codemode

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// CallHeader carries the identifier of a nested call. It only links the call
// to its run and lets the plug-in refuse Code Mode tools inside a run; it
// grants nothing. The plug-in removes it before a request reaches an
// upstream, and programs cannot set headers.
const CallHeader = "X-Code-Mode-Call"

// OlderProtocol is the MCP version whose servers may keep sessions.
const OlderProtocol = "2025-11-25"

// replyOverhead is the room a reply needs beyond its result.
const replyOverhead = 64 << 10

// Nested describes a nested call the gateway is handling.
type Nested struct {
	Run   string
	Proxy string
}

// Registry records the nested calls in flight, so the plug-in can recognise
// its own requests when they come back through the gateway.
type Registry struct{ calls sync.Map }

// Begin registers a nested call to proxy and returns the header value that
// identifies it. end removes it once the call is answered.
func (g *Registry) Begin(run, proxy string) (value string, end func()) {
	value = randomID()
	g.calls.Store(value, Nested{Run: run, Proxy: proxy})
	return value, func() { g.calls.Delete(value) }
}

// Lookup returns the nested call a header value identifies.
func (g *Registry) Lookup(value string) (Nested, bool) {
	if value == "" {
		return Nested{}, false
	}
	n, ok := g.calls.Load(value)
	if !ok {
		return Nested{}, false
	}
	return n.(Nested), true
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewRunID returns a random run identifier.
func NewRunID() string { return randomID() }

// Origin is the request that started a run. Nested calls repeat its protocol
// and credential.
type Origin struct {
	Proxy string
	// Version is the MCP protocol version the client negotiated.
	Version string
	// Session is the caller's session on Proxy, for the older protocol.
	Session string
	// Meta is the protocol metadata the newer protocol puts in each request.
	Meta json.RawMessage
	// NamedHeaders reports whether requests carry Mcp-Method and Mcp-Name,
	// as the newer protocol's do.
	NamedHeaders bool
	// Credential holds exactly the header that identified the caller.
	Credential http.Header
}

// Gateway sends nested calls to this gateway.
type Gateway struct {
	Base     string
	Paths    map[string]string
	Client   *http.Client
	Registry *Registry
}

// NewClient returns the HTTP client nested calls use. Nested calls carry the
// caller's credential and go only to this gateway, so the client uses no
// proxy from the environment and never follows a redirect; a redirect reaches
// the program as an HTTP error.
func NewClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Session makes one run's nested calls.
type Session struct {
	gateway  *Gateway
	origin   Origin
	run      string
	maxBytes int
	nextID   int
	mu       sync.Mutex
	// sessions holds the session opened on each other proxy, for the older
	// protocol. A proxy whose upstream keeps no sessions has an empty one.
	sessions map[string]*proxySession
}

type proxySession struct {
	once    sync.Once
	id      string
	refused *protocol.Error
	err     error
}

// Session starts the nested calls of one run.
func (g *Gateway) Session(origin Origin, run string, valueBytes int) *Session {
	return &Session{gateway: g, origin: origin, run: run, maxBytes: valueBytes + replyOverhead, sessions: map[string]*proxySession{}}
}

// id returns a request ID unique to this run. Calls on the run's own proxy
// share the caller's session, so the IDs include the run ID and are strings,
// which never collide with the client's own IDs or another run's.
func (s *Session) id() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	return fmt.Sprintf("codemode-%s-%d", s.run, s.nextID)
}

// Call implements Call.
func (s *Session) Call(ctx context.Context, proxy, tool string, args json.RawMessage) (json.RawMessage, *protocol.Error, error) {
	if _, ok := s.gateway.Paths[proxy]; !ok {
		// A proxy without Code Mode answers as a refused call does, so
		// programs cannot tell which proxies exist.
		return nil, &protocol.Error{Code: -32002, Message: "Tool call denied"}, nil
	}
	session, refused, err := s.sessionFor(ctx, proxy)
	if err != nil || refused != nil {
		return nil, refused, err
	}
	params := map[string]json.RawMessage{}
	if len(s.origin.Meta) > 0 {
		params["_meta"] = s.origin.Meta
	}
	params["name"], _ = json.Marshal(tool)
	params["arguments"] = args
	id := s.id()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
	res, err := s.post(ctx, proxy, session, "tools/call", tool, body)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	return readReply(res, id, s.maxBytes)
}

// sessionFor returns the session a call to proxy uses. Calls on the run's
// own proxy use the caller's session. Under the older protocol, a call to
// another proxy uses a session the run opens there as the caller, because a
// server that keeps sessions refuses calls without one.
func (s *Session) sessionFor(ctx context.Context, proxy string) (string, *protocol.Error, error) {
	if proxy == s.origin.Proxy {
		return s.origin.Session, nil, nil
	}
	if s.origin.Version != OlderProtocol {
		return "", nil, nil
	}
	s.mu.Lock()
	ps := s.sessions[proxy]
	if ps == nil {
		ps = &proxySession{}
		s.sessions[proxy] = ps
	}
	s.mu.Unlock()
	ps.once.Do(func() { ps.id, ps.refused, ps.err = s.open(ctx, proxy) })
	return ps.id, ps.refused, ps.err
}

// open starts a session on proxy as the caller. A refusal, such as Tyk's
// when the caller has no access to the proxy, is returned as the refusal of
// every call that needs the session.
func (s *Session) open(ctx context.Context, proxy string) (string, *protocol.Error, error) {
	id := s.id()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "initialize", "params": map[string]any{
		"protocolVersion": s.origin.Version, "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "tyk-code-mode", "version": "1"},
	}})
	res, err := s.post(ctx, proxy, "", "initialize", "", body)
	if err != nil {
		return "", nil, err
	}
	// The session exists once the server names it, so it is returned, and
	// closed with the run, even if the rest of the handshake fails.
	session := res.Header.Get("Mcp-Session-Id")
	_, refused, err := readReply(res, id, replyOverhead)
	res.Body.Close()
	if err != nil || refused != nil {
		return session, refused, err
	}
	note, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	res, err = s.post(ctx, proxy, session, "notifications/initialized", "", note)
	if err != nil {
		return session, nil, err
	}
	io.Copy(io.Discard, io.LimitReader(res.Body, replyOverhead))
	res.Body.Close()
	return session, nil, nil
}

// closeWait bounds closing a run's sessions, all at once.
const closeWait = 5 * time.Second

// Close ends the sessions the run opened, in parallel. A session that cannot
// be closed expires on its server.
func (s *Session) Close() {
	s.mu.Lock()
	opened := map[string]string{}
	for proxy, ps := range s.sessions {
		if ps.id != "" {
			opened[proxy] = ps.id
		}
	}
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), closeWait)
	defer cancel()
	var wg sync.WaitGroup
	for proxy, id := range opened {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := s.request(ctx, http.MethodDelete, proxy, id, "", "", nil)
			if err != nil {
				return
			}
			if res, err := s.do(req, proxy); err == nil {
				io.Copy(io.Discard, io.LimitReader(res.Body, replyOverhead))
				res.Body.Close()
			}
		}()
	}
	wg.Wait()
}

func (s *Session) post(ctx context.Context, proxy, session, method, name string, body []byte) (*http.Response, error) {
	req, err := s.request(ctx, http.MethodPost, proxy, session, method, name, body)
	if err != nil {
		return nil, err
	}
	return s.do(req, proxy)
}

// request builds a nested request. Every header is set here, from the
// run's origin; nothing a program supplies becomes a header.
func (s *Session) request(ctx context.Context, verb, proxy, session, method, name string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, verb, s.gateway.Base+s.gateway.Paths[proxy], bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if s.origin.Version != "" {
		req.Header.Set("MCP-Protocol-Version", s.origin.Version)
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	if s.origin.NamedHeaders && method != "" {
		req.Header.Set("Mcp-Method", method)
		if name != "" {
			req.Header.Set("Mcp-Name", name)
		}
	}
	for header, values := range s.origin.Credential {
		for _, v := range values {
			req.Header.Add(header, v)
		}
	}
	return req, nil
}

// do sends a nested request. Its identifier stays registered until the
// gateway has answered, by which time the plug-in has handled the request.
func (s *Session) do(req *http.Request, proxy string) (*http.Response, error) {
	value, end := s.gateway.Registry.Begin(s.run, proxy)
	defer end()
	req.Header.Set(CallHeader, value)
	return s.gateway.Client.Do(req)
}

// readReply reads the JSON-RPC reply to request id, plain or streamed, from
// at most limit bytes. A stream is read only up to the event that answers.
func readReply(res *http.Response, id string, limit int) (json.RawMessage, *protocol.Error, error) {
	body := io.LimitReader(res.Body, int64(limit)+1)
	var data []byte
	var err error
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		data, err = streamedReply(body, id, limit)
	} else if data, err = io.ReadAll(body); err == nil && len(data) > limit {
		err = ErrTooLarge
	}
	if err != nil {
		return nil, nil, err
	}
	var reply struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &reply) == nil {
		switch {
		case reply.Error != nil:
			return nil, &protocol.Error{Code: reply.Error.Code, Message: reply.Error.Message}, nil
		case reply.Result != nil && string(reply.ID) == jsonID(id):
			return reply.Result, nil, nil
		}
	}
	// Tyk's own refusals, such as a missing access right, are not JSON-RPC.
	var gateway struct {
		Error string `json:"error"`
	}
	message := strings.TrimSpace(string(data))
	if json.Unmarshal(data, &gateway) == nil && gateway.Error != "" {
		message = gateway.Error
	}
	if res.StatusCode >= 300 {
		return nil, &protocol.Error{Code: -32000, Message: fmt.Sprintf("HTTP %d: %s", res.StatusCode, message)}, nil
	}
	return nil, nil, errors.New("the gateway's reply was not a JSON-RPC reply to the call")
}

// streamedReply reads a stream event by event and returns the data of the
// event that answers request id, or nil if the stream ends without one. An
// event's data may span several lines, which are joined as the event-stream
// format requires.
func streamedReply(r io.Reader, id string, limit int) ([]byte, error) {
	want := jsonID(id)
	reader := bufio.NewReader(r)
	var lines []string
	read := 0
	for {
		line, err := reader.ReadString('\n')
		if read += len(line); read > limit {
			return nil, ErrTooLarge
		}
		switch line = strings.TrimRight(line, "\r\n"); {
		case line == "" && len(lines) > 0:
			data := strings.Join(lines, "\n")
			lines = lines[:0]
			var message struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal([]byte(data), &message) == nil && string(message.ID) == want {
				return []byte(data), nil
			}
		case strings.HasPrefix(line, "data:"):
			lines = append(lines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// jsonID is a request ID as it appears in a JSON-RPC message.
func jsonID(id string) string {
	data, _ := json.Marshal(id)
	return string(data)
}
