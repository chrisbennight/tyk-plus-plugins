package codemode

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// testTLS returns a server and client configuration sharing one authority.
func testTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, DNSNames: []string{"sandbox.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	parsed, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	server = &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13}
	client = &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "sandbox.test", MinVersion: tls.VersionTLS13}
	return server, client
}

// fakeHost is a sandbox host whose behavior each test scripts.
type fakeHost struct {
	backend string
	// script runs one run after the start message.
	script func(t *testing.T, r *protocol.Reader, send func(protocol.Message), start protocol.Message)
	starts atomic.Int32
}

func (h *fakeHost) serve(t *testing.T, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			var mu sync.Mutex
			send := func(m protocol.Message) {
				mu.Lock()
				defer mu.Unlock()
				protocol.Write(c, m)
			}
			send(protocol.Message{Type: protocol.TypeHello, Backend: h.backend})
			r := protocol.NewReader(c, 8<<20)
			var start protocol.Message
			if r.Read(&start) != nil || start.Type != protocol.TypeStart {
				return
			}
			h.starts.Add(1)
			h.script(t, r, send, start)
		}()
	}
}

func startHost(t *testing.T, h *fakeHost) (*Runner, Limits) {
	t.Helper()
	serverTLS, clientTLS := testTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go h.serve(t, ln)
	runner := NewRunner(&Settings{Address: ln.Addr().String(), TLS: clientTLS, Backends: map[string]bool{protocol.BackendGVisor: true}, Runs: 2})
	limits := DefaultLimits
	limits.RunMillis = 5000
	return runner, limits
}

// callAndFinish asks for the given calls in parallel, then finishes with the
// replies it received, in call order.
func callAndFinish(calls ...protocol.Message) func(*testing.T, *protocol.Reader, func(protocol.Message), protocol.Message) {
	return func(t *testing.T, r *protocol.Reader, send func(protocol.Message), _ protocol.Message) {
		for _, c := range calls {
			c.Type = protocol.TypeCall
			send(c)
		}
		replies := map[int64]protocol.Message{}
		for len(replies) < len(calls) {
			var m protocol.Message
			if r.Read(&m) != nil {
				return
			}
			replies[m.ID] = m
		}
		var out []any
		for _, c := range calls {
			m := replies[c.ID]
			if m.Type == protocol.TypeResult {
				out = append(out, json.RawMessage(m.Result))
			} else {
				out = append(out, map[string]any{"error": m.Error})
			}
		}
		result, _ := json.Marshal(out)
		send(protocol.Message{Type: protocol.TypeDone, Result: result, Console: []string{"done"}})
	}
}

func TestRunRelaysCallsInParallel(t *testing.T) {
	host := &fakeHost{backend: protocol.BackendGVisor, script: callAndFinish(
		protocol.Message{ID: 1, Proxy: "a", Tool: "lookup", Arguments: json.RawMessage(`{"n":1}`)},
		protocol.Message{ID: 2, Proxy: "b", Tool: "lookup", Arguments: json.RawMessage(`{"n":2}`)},
		protocol.Message{ID: 3, Proxy: "a", Tool: "secret"},
	)}
	runner, limits := startHost(t, host)
	var inFlight, most atomic.Int32
	call := func(ctx context.Context, proxy, tool string, args json.RawMessage) (json.RawMessage, *protocol.Error, error) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		if tool == "secret" {
			return nil, &protocol.Error{Code: -32002, Message: "Tool call denied"}, nil
		}
		return json.RawMessage(`{"proxy":"` + proxy + `","args":` + string(args) + `}`), nil, nil
	}
	var records []CallRecord
	var mu sync.Mutex
	out := runner.Run(context.Background(), Request{Source: "x", Limits: limits, Call: call, OnCall: func(c CallRecord) {
		mu.Lock()
		records = append(records, c)
		mu.Unlock()
	}})
	if out.Failure != nil {
		t.Fatalf("run failed: %+v", out.Failure)
	}
	want := `[{"proxy":"a","args":{"n":1}},{"proxy":"b","args":{"n":2}},{"error":{"code":-32002,"message":"Tool call denied"}}]`
	if string(out.Result) != want {
		t.Fatalf("result %s, want %s", out.Result, want)
	}
	if most.Load() < 2 {
		t.Errorf("calls did not run in parallel")
	}
	if out.Backend != protocol.BackendGVisor || out.Calls != 3 || out.Refused != 1 || len(records) != 3 {
		t.Errorf("outcome %+v, records %+v", out, records)
	}
}

func TestRunLimitsCallsAtOnce(t *testing.T) {
	var calls []protocol.Message
	for i := range 6 {
		calls = append(calls, protocol.Message{ID: int64(i + 1), Proxy: "a", Tool: "lookup"})
	}
	host := &fakeHost{backend: protocol.BackendGVisor, script: callAndFinish(calls...)}
	runner, limits := startHost(t, host)
	limits.CallsAtOnce = 2
	var inFlight, most atomic.Int32
	call := func(ctx context.Context, proxy, tool string, args json.RawMessage) (json.RawMessage, *protocol.Error, error) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		return json.RawMessage(`{}`), nil, nil
	}
	if out := runner.Run(context.Background(), Request{Source: "x", Limits: limits, Call: call}); out.Failure != nil {
		t.Fatalf("run failed: %+v", out.Failure)
	}
	if most.Load() != 2 {
		t.Errorf("%d calls ran at once, want 2", most.Load())
	}
}

func TestRunLimits(t *testing.T) {
	ok := func(ctx context.Context, proxy, tool string, args json.RawMessage) (json.RawMessage, *protocol.Error, error) {
		return json.RawMessage(`{}`), nil, nil
	}
	for _, c := range []struct {
		name   string
		script func(*testing.T, *protocol.Reader, func(protocol.Message), protocol.Message)
		limits func(*Limits)
		call   Call
		req    func(*Request)
		kind   string
		says   string
	}{
		{name: "calls per run", limits: func(l *Limits) { l.Calls = 2 },
			script: callAndFinish(protocol.Message{ID: 1, Proxy: "a", Tool: "t"}, protocol.Message{ID: 2, Proxy: "a", Tool: "t"}, protocol.Message{ID: 3, Proxy: "a", Tool: "t"}),
			kind:   protocol.KindLimit, says: "calls per run limit"},
		{name: "tool result size", limits: func(l *Limits) { l.ValueBytes = 10 },
			script: callAndFinish(protocol.Message{ID: 1, Proxy: "a", Tool: "t"}),
			call: func(ctx context.Context, proxy, tool string, args json.RawMessage) (json.RawMessage, *protocol.Error, error) {
				return json.RawMessage(`{"text":"far too long"}`), nil, nil
			},
			kind: protocol.KindLimit, says: "value size limit"},
		{name: "final result size", limits: func(l *Limits) { l.ValueBytes = 4 },
			script: func(t *testing.T, r *protocol.Reader, send func(protocol.Message), _ protocol.Message) {
				send(protocol.Message{Type: protocol.TypeDone, Result: json.RawMessage(`"toolong"`)})
			},
			kind: protocol.KindLimit, says: "value size limit"},
		{name: "console", limits: func(l *Limits) { l.ConsoleBytes = 4 },
			script: func(t *testing.T, r *protocol.Reader, send func(protocol.Message), _ protocol.Message) {
				send(protocol.Message{Type: protocol.TypeDone, Result: json.RawMessage(`1`), Console: []string{"hello"}})
			},
			kind: protocol.KindLimit, says: "console limit"},
		{name: "program size", limits: func(l *Limits) { l.ProgramBytes = 3 }, req: func(r *Request) { r.Source = "four" },
			kind: protocol.KindLimit, says: "program size limit"},
		{name: "input size", limits: func(l *Limits) { l.ValueBytes = 3 }, req: func(r *Request) { r.Input = json.RawMessage(`"four"`) },
			kind: protocol.KindLimit, says: "value size limit"},
		{name: "run time backstop", limits: func(l *Limits) { l.RunMillis = 1 },
			script: func(t *testing.T, r *protocol.Reader, send func(protocol.Message), _ protocol.Message) {
				time.Sleep(15 * time.Second)
			},
			kind: protocol.KindLimit, says: "run time limit"},
		{name: "host failure passed on",
			script: func(t *testing.T, r *protocol.Reader, send func(protocol.Message), _ protocol.Message) {
				send(protocol.Failed(protocol.KindLimit, "the run exceeded its memory limit"))
			},
			kind: protocol.KindLimit, says: "memory limit"},
		{name: "host closes without result",
			script: func(t *testing.T, r *protocol.Reader, send func(protocol.Message), _ protocol.Message) {},
			kind:   protocol.KindUnavailable},
		{name: "unexpected message",
			script: func(t *testing.T, r *protocol.Reader, send func(protocol.Message), _ protocol.Message) {
				send(protocol.Message{Type: protocol.TypeHello})
			},
			kind: protocol.KindProtocol},
	} {
		t.Run(c.name, func(t *testing.T) {
			script := c.script
			if script == nil {
				script = func(*testing.T, *protocol.Reader, func(protocol.Message), protocol.Message) {}
			}
			host := &fakeHost{backend: protocol.BackendGVisor, script: script}
			runner, limits := startHost(t, host)
			if c.limits != nil {
				c.limits(&limits)
			}
			call := c.call
			if call == nil {
				call = ok
			}
			req := Request{Source: "x", Limits: limits, Call: call}
			if c.req != nil {
				c.req(&req)
			}
			out := runner.Run(context.Background(), req)
			if out.Failure == nil || out.Failure.Kind != c.kind || !strings.Contains(out.Failure.Message, c.says) {
				t.Fatalf("failure %+v, want kind %s naming %q", out.Failure, c.kind, c.says)
			}
		})
	}
}

func TestRunTimePerCall(t *testing.T) {
	host := &fakeHost{backend: protocol.BackendGVisor, script: callAndFinish(protocol.Message{ID: 1, Proxy: "a", Tool: "slow"})}
	runner, limits := startHost(t, host)
	limits.CallMillis = 50
	call := func(ctx context.Context, proxy, tool string, args json.RawMessage) (json.RawMessage, *protocol.Error, error) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	out := runner.Run(context.Background(), Request{Source: "x", Limits: limits, Call: call})
	if out.Failure != nil || !strings.Contains(string(out.Result), "time per call limit") || out.Unknown != 1 {
		t.Fatalf("outcome %+v %s", out, out.Result)
	}
}

func TestRunStopsWhenTheClientLeaves(t *testing.T) {
	ended := make(chan struct{})
	host := &fakeHost{backend: protocol.BackendGVisor, script: func(t *testing.T, r *protocol.Reader, send func(protocol.Message), _ protocol.Message) {
		send(protocol.Message{Type: protocol.TypeCall, ID: 1, Proxy: "a", Tool: "slow"})
		var m protocol.Message
		for r.Read(&m) == nil {
		}
		close(ended)
	}}
	runner, limits := startHost(t, host)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var later atomic.Int32
	call := func(callCtx context.Context, proxy, tool string, args json.RawMessage) (json.RawMessage, *protocol.Error, error) {
		if later.Add(1) > 1 {
			t.Error("a call started after the client left")
		}
		close(started)
		<-callCtx.Done()
		return nil, nil, callCtx.Err()
	}
	go func() {
		<-started
		cancel()
	}()
	out := runner.Run(ctx, Request{Source: "x", Limits: limits, Call: call})
	if out.Failure == nil || out.Failure.Kind != KindCancelled || out.Unknown != 1 {
		t.Fatalf("outcome %+v", out)
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the sandbox connection stayed open")
	}
}

func TestRunRefusesBackend(t *testing.T) {
	host := &fakeHost{backend: protocol.BackendRunc, script: func(*testing.T, *protocol.Reader, func(protocol.Message), protocol.Message) {}}
	runner, limits := startHost(t, host)
	out := runner.Run(context.Background(), Request{Source: "x", Limits: limits})
	if out.Failure == nil || out.Failure.Kind != protocol.KindUnavailable || !strings.Contains(out.Failure.Message, `"runc"`) {
		t.Fatalf("failure %+v", out.Failure)
	}
	if host.starts.Load() != 0 {
		t.Error("the program was sent to a backend the gateway does not accept")
	}
}

func TestRunBusy(t *testing.T) {
	release := make(chan struct{})
	host := &fakeHost{backend: protocol.BackendGVisor, script: func(t *testing.T, r *protocol.Reader, send func(protocol.Message), _ protocol.Message) {
		<-release
		send(protocol.Message{Type: protocol.TypeDone, Result: json.RawMessage(`1`)})
	}}
	runner, limits := startHost(t, host)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runner.Run(context.Background(), Request{Source: "x", Limits: limits})
		}()
	}
	for host.starts.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	out := runner.Run(context.Background(), Request{Source: "x", Limits: limits})
	close(release)
	wg.Wait()
	if out.Failure == nil || out.Failure.Kind != protocol.KindBusy {
		t.Fatalf("failure %+v", out.Failure)
	}
}

func TestRunRefusesCodeModeTools(t *testing.T) {
	host := &fakeHost{backend: protocol.BackendGVisor, script: callAndFinish(protocol.Message{ID: 1, Proxy: "a", Tool: "codemode.execute"})}
	runner, limits := startHost(t, host)
	call := func(ctx context.Context, proxy, tool string, args json.RawMessage) (json.RawMessage, *protocol.Error, error) {
		t.Error("a Code Mode tool was called from a program")
		return nil, nil, nil
	}
	out := runner.Run(context.Background(), Request{Source: "x", Limits: limits, Call: call})
	if out.Failure != nil || !strings.Contains(string(out.Result), "error") || out.Refused != 1 {
		t.Fatalf("outcome %+v %s", out, out.Result)
	}
}

func TestLimitsWithin(t *testing.T) {
	max := DefaultLimits
	got := Limits{CallsAtOnce: 100, CallMillis: 10, Limits: protocol.Limits{RunMillis: 1000, Calls: 1000}}.Within(max)
	if got.CallsAtOnce != max.CallsAtOnce || got.CallMillis != 10 || got.RunMillis != 1000 || got.Calls != max.Calls || got.ValueBytes != max.ValueBytes {
		t.Fatalf("limits %+v", got)
	}
}
