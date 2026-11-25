package codemode

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGateway records nested requests and answers like an MCP proxy.
type fakeGateway struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
	registry *Registry
	// seen records the nested call each request's header identified while
	// the gateway handled it.
	seen   []Nested
	answer func(w http.ResponseWriter, r *http.Request, body map[string]any)
}

func (g *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	var body map[string]any
	json.Unmarshal(data, &body)
	n, _ := g.registry.Lookup(r.Header.Get(CallHeader))
	g.mu.Lock()
	g.requests = append(g.requests, r)
	g.bodies = append(g.bodies, string(data))
	g.seen = append(g.seen, n)
	g.mu.Unlock()
	g.answer(w, r, body)
}

func newGateway(t *testing.T, answer func(http.ResponseWriter, *http.Request, map[string]any)) (*Gateway, *fakeGateway) {
	registry := &Registry{}
	fake := &fakeGateway{registry: registry, answer: answer}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return &Gateway{Base: server.URL, Paths: map[string]string{"a": "/a/", "b": "/b/"}, Client: NewClient(), Registry: registry}, fake
}

func reply(w http.ResponseWriter, body map[string]any, result any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": body["id"], "result": result})
}

func TestNestedCallCarriesOnlyTheOrigin(t *testing.T) {
	gateway, fake := newGateway(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		reply(w, body, map[string]any{"content": []any{}})
	})
	origin := Origin{Proxy: "a", Version: "2026-07-28", Meta: json.RawMessage(`{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`),
		NamedHeaders: true, Credential: http.Header{"Authorization": {"Bearer t"}}}
	s := gateway.Session(origin, "run-1", 1<<20)
	result, refused, err := s.Call(context.Background(), "b", "lookup", json.RawMessage(`{"count":7}`))
	if err != nil || refused != nil || string(result) != `{"content":[]}` {
		t.Fatalf("result %s, refused %+v, err %v", result, refused, err)
	}
	r := fake.requests[0]
	if r.URL.Path != "/b/" || r.Header.Get("Authorization") != "Bearer t" || r.Header.Get("X-Api-Key") != "" ||
		r.Header.Get("Mcp-Method") != "tools/call" || r.Header.Get("Mcp-Name") != "lookup" || r.Header.Get("MCP-Protocol-Version") != "2026-07-28" {
		t.Fatalf("request %s with headers %v", r.URL.Path, r.Header)
	}
	if fake.seen[0] != (Nested{Run: "run-1", Proxy: "b"}) {
		t.Fatalf("the gateway saw nested call %+v", fake.seen[0])
	}
	if _, ok := gateway.Registry.Lookup(r.Header.Get(CallHeader)); ok {
		t.Fatal("the nested call stayed registered after its reply")
	}
	if !strings.Contains(fake.bodies[0], `"_meta"`) || !strings.Contains(fake.bodies[0], `"arguments":{"count":7}`) {
		t.Fatalf("body %s", fake.bodies[0])
	}
}

func TestNestedCallOpensSessionsOnOtherProxies(t *testing.T) {
	var mu sync.Mutex
	sessions := map[string]string{}
	gateway, fake := newGateway(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		switch {
		case r.Method == http.MethodDelete:
			mu.Lock()
			delete(sessions, r.Header.Get("Mcp-Session-Id"))
			mu.Unlock()
		case body["method"] == "initialize":
			mu.Lock()
			sessions["s-"+r.URL.Path] = r.URL.Path
			mu.Unlock()
			w.Header().Set("Mcp-Session-Id", "s-"+r.URL.Path)
			reply(w, body, map[string]any{"protocolVersion": OlderProtocol})
		case body["method"] == "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			mu.Lock()
			_, open := sessions[r.Header.Get("Mcp-Session-Id")]
			mu.Unlock()
			if !open && r.Header.Get("Mcp-Session-Id") != "caller" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": body["id"], "error": map[string]any{"code": -32600, "message": "no session"}})
				return
			}
			reply(w, body, map[string]any{"session": r.Header.Get("Mcp-Session-Id")})
		}
	})
	origin := Origin{Proxy: "a", Version: OlderProtocol, Session: "caller", Credential: http.Header{"X-Api-Key": {"k"}}}
	s := gateway.Session(origin, "run-1", 1<<20)
	var wg sync.WaitGroup
	results := make([]string, 3)
	for i, proxy := range []string{"a", "b", "b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, refused, err := s.Call(context.Background(), proxy, "lookup", json.RawMessage(`{}`))
			if err != nil || refused != nil {
				t.Errorf("call to %s: %+v %v", proxy, refused, err)
			}
			results[i] = string(result)
		}()
	}
	wg.Wait()
	s.Close()
	if results[0] != `{"session":"caller"}` || results[1] != `{"session":"s-/b/"}` || results[2] != results[1] {
		t.Fatalf("results %v", results)
	}
	initializes := 0
	for _, body := range fake.bodies {
		if strings.Contains(body, `"initialize"`) {
			initializes++
		}
	}
	if initializes != 1 || len(sessions) != 0 {
		t.Fatalf("%d sessions opened, %v left open", initializes, sessions)
	}
	for _, r := range fake.requests {
		if r.Header.Get("X-Api-Key") != "k" || r.Header.Get("Authorization") != "" {
			t.Fatalf("request without the caller's key alone: %v", r.Header)
		}
	}
}

func TestNestedCallReplies(t *testing.T) {
	for _, c := range []struct {
		name    string
		answer  func(http.ResponseWriter, *http.Request, map[string]any)
		result  string
		refused string
		err     error
	}{
		{name: "streamed", answer: func(w http.ResponseWriter, r *http.Request, body map[string]any) {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n")
			data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": body["id"], "result": map[string]any{"ok": true}})
			io.WriteString(w, "event: message\ndata: "+string(data)+"\n\n")
		}, result: `{"ok":true}`},
		{name: "refused", answer: func(w http.ResponseWriter, r *http.Request, body map[string]any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": body["id"], "error": map[string]any{"code": -32002, "message": "Tool call denied"}})
		}, refused: "Tool call denied"},
		{name: "gateway refusal", answer: func(w http.ResponseWriter, r *http.Request, body map[string]any) {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"error": "Access to this API has been disallowed"}`)
		}, refused: "HTTP 403: Access to this API has been disallowed"},
		{name: "too large", answer: func(w http.ResponseWriter, r *http.Request, body map[string]any) {
			reply(w, body, map[string]any{"text": strings.Repeat("x", 200<<10)})
		}, err: ErrTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			gateway, _ := newGateway(t, c.answer)
			s := gateway.Session(Origin{Proxy: "a", Version: "2026-07-28"}, "r", 1024)
			result, refused, err := s.Call(context.Background(), "a", "t", json.RawMessage(`{}`))
			switch {
			case c.err != nil:
				if !errors.Is(err, c.err) {
					t.Fatalf("err %v, want %v", err, c.err)
				}
			case c.refused != "":
				if refused == nil || refused.Message != c.refused {
					t.Fatalf("refused %+v, want %q (err %v)", refused, c.refused, err)
				}
			default:
				if err != nil || string(result) != c.result {
					t.Fatalf("result %s, err %v", result, err)
				}
			}
		})
	}
}

func TestNestedCallToUnknownProxy(t *testing.T) {
	gateway, fake := newGateway(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {})
	s := gateway.Session(Origin{Proxy: "a"}, "r", 1024)
	_, refused, err := s.Call(context.Background(), "elsewhere", "t", nil)
	if err != nil || refused == nil || refused.Message != "Tool call denied" || len(fake.requests) != 0 {
		t.Fatalf("refused %+v, err %v, %d requests", refused, err, len(fake.requests))
	}
}

func TestLoad(t *testing.T) {
	env := func(pairs ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i < len(pairs); i += 2 {
			m[pairs[i]] = pairs[i+1]
		}
		return func(k string) string { return m[k] }
	}
	tyk := Tyk{ListenPort: 8080, WriteTimeout: 120 * time.Second}
	if s, err := Load(env(), tyk); s != nil || err != nil {
		t.Fatalf("unconfigured: %+v %v", s, err)
	}
	s, err := Load(env("CODEMODE_SANDBOX_ADDRESS", "sandbox:7443", "CODEMODE_PROXIES", "governed=/mcp/, second=/mcp2/",
		"CODEMODE_MAX_RUN_MS", "200000", "CODEMODE_BACKENDS", "gvisor,podman"), tyk)
	if s == nil || err == nil {
		t.Fatal("bad settings were accepted")
	}
	for _, want := range []string{"write_timeout", `unknown backend "podman"`, "CODEMODE_TLS_CERT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("problems %q do not mention %q", err, want)
		}
	}
	if s.Proxies["second"] != "/mcp2/" || s.Gateway != "http://127.0.0.1:8080" || s.Max.RunMillis != 200000 {
		t.Errorf("settings %+v", s)
	}
	if _, err := Load(env("CODEMODE_SANDBOX_ADDRESS", "s:1", "CODEMODE_PROXIES", "bad path"), tyk); err == nil || !strings.Contains(err.Error(), "CODEMODE_PROXIES") {
		t.Errorf("a malformed proxy list was accepted: %v", err)
	}
}
