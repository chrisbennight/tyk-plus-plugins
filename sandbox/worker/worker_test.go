package worker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	quickjswasi "github.com/aperturerobotics/go-quickjs-wasi-reactor"
	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// tools answers tool calls the way the gateway would.
type tools struct {
	calls   chan protocol.Message
	sent    int
	answers map[string]func(protocol.Message) protocol.Message
}

func (t *tools) send(m protocol.Message) error { t.sent++; t.calls <- m; return nil }

func (t *tools) Next(ctx context.Context) (protocol.Message, error) {
	select {
	case m := <-t.calls:
		if answer, ok := t.answers[m.Proxy+"."+m.Tool]; ok {
			return answer(m), nil
		}
		return protocol.Message{Type: protocol.TypeError, ID: m.ID, Error: &protocol.Error{Code: -32002, Message: "Tool call denied"}}, nil
	case <-ctx.Done():
		return protocol.Message{}, ctx.Err()
	}
}

func run(t *testing.T, source string, input string, limits protocol.Limits) protocol.Message {
	t.Helper()
	m, _ := runCounting(t, source, input, limits)
	return m
}

// runCounting also reports how many tool calls reached the host.
func runCounting(t *testing.T, source string, input string, limits protocol.Limits) (protocol.Message, int) {
	t.Helper()
	rt, err := NewRuntime("")
	if err != nil {
		t.Fatal(err)
	}
	tl := &tools{calls: make(chan protocol.Message, 128), answers: map[string]func(protocol.Message) protocol.Message{
		"governed.lookup": func(m protocol.Message) protocol.Message {
			var args struct{ Count int }
			json.Unmarshal(m.Arguments, &args)
			result, _ := json.Marshal(map[string]any{"found": args.Count * 2})
			return protocol.Message{Type: protocol.TypeResult, ID: m.ID, Result: result}
		},
	}}
	l := limits.Within(protocol.DefaultLimits)
	m := rt.Run(context.Background(), protocol.Message{Type: protocol.TypeStart, Source: source, Input: json.RawMessage(input), Limits: &l}, tl.send, tl)
	return m, tl.sent
}

func TestCallsBeyondTheLimitInOneTurnStopTheRun(t *testing.T) {
	m, sent := runCounting(t, `
		for (let i = 0; i < 100000; i++) connectors.governed.lookup({ count: i });
		await new Promise(() => {});`, ``, protocol.Limits{Calls: 3})
	if m.Type != protocol.TypeFailed || m.Failure.Kind != protocol.KindLimit || sent > 3 {
		t.Fatalf("got %+v after %d calls reached the host", m.Failure, sent)
	}
}

func TestMessagesOfAnyTypeAreBounded(t *testing.T) {
	// The program changes how the bootstrap's messages serialize, so they no
	// longer read as tool calls; the bridge must still stop accepting them.
	m, _ := runCounting(t, `
		Object.prototype.toJSON = function () { return { type: "other" }; };
		for (let i = 0; i < 100000; i++) connectors.governed.lookup({ count: i });
		await new Promise(() => {});`, ``, protocol.Limits{Calls: 3})
	if m.Type != protocol.TypeFailed || (m.Failure.Kind != protocol.KindProtocol && m.Failure.Kind != protocol.KindLimit) {
		t.Fatalf("got %s %+v", m.Type, m.Failure)
	}
}

func TestConsoleLimitCountsUTF8Bytes(t *testing.T) {
	// 6000 characters of two bytes each exceed a 10000-byte limit, and the
	// run must stop before its next tool call reaches the host.
	m, sent := runCounting(t, `
		console.log("é".repeat(6000));
		await connectors.governed.lookup({ count: 1 });
		return 1;`, ``, protocol.Limits{ConsoleBytes: 10000})
	if m.Type != protocol.TypeFailed || !strings.Contains(m.Failure.Message, "console") || sent != 0 {
		t.Fatalf("got %+v after %d calls reached the host", m.Failure, sent)
	}
}

func TestEngineVersionHasTheSecurityFixes(t *testing.T) {
	if quickjswasi.Version < "v0.16.0" {
		t.Fatalf("QuickJS-NG %s predates the 0.16.0 security fixes", quickjswasi.Version)
	}
}

func TestToolCallsInSequenceAndInParallel(t *testing.T) {
	m := run(t, `
		const first = await connectors.governed.lookup({ count: input.start });
		const rest = await Promise.all([1, 2, 3].map((n) => connectors["governed"]["lookup"]({ count: n })));
		console.log("first", first);
		return { first: first.found, rest: rest.map((r) => r.found) };`, `{"start": 5}`, protocol.Limits{})
	if m.Type != protocol.TypeDone || string(m.Result) != `{"first":10,"rest":[2,4,6]}` {
		t.Fatalf("got %+v %s", m.Failure, m.Result)
	}
	if len(m.Console) != 1 || m.Console[0] != `first {"found":10}` {
		t.Fatalf("console %q", m.Console)
	}
}

func TestRefusedCallRejectsWithTheGatewaysError(t *testing.T) {
	m := run(t, `
		try { await connectors.governed.change({}); return "no error"; }
		catch (e) { return { code: e.code, message: e.message }; }`, ``, protocol.Limits{})
	if m.Type != protocol.TypeDone || string(m.Result) != `{"code":-32002,"message":"Tool call denied"}` {
		t.Fatalf("got %+v %s", m.Failure, m.Result)
	}
}

func TestProgramSeesNoHostCapabilities(t *testing.T) {
	m := run(t, `
		const seen = {};
		for (const name of ["print", "scriptArgs", "fetch", "require", "process", "std", "os", "Deno"]) seen[name] = typeof globalThis[name];
		const tryModule = async (name, use) => { try { return use(await import(name)); } catch (e) { return "refused: " + e; } };
		seen.read = await tryModule("qjs:std", (std) => { const f = std.open("/etc/hostname", "r"); return f ? f.readAsString() : null; });
		seen.list = await tryModule("qjs:os", (os) => { const [names, err] = os.readdir("/"); return err ? null : names; });
		return seen;`, ``, protocol.Limits{})
	if m.Type != protocol.TypeDone {
		t.Fatalf("got %+v", m.Failure)
	}
	var seen map[string]any
	json.Unmarshal(m.Result, &seen)
	for _, name := range []string{"print", "scriptArgs", "fetch", "require", "process", "std", "os", "Deno"} {
		if seen[name] != "undefined" {
			t.Errorf("global %s is %v", name, seen[name])
		}
	}
	if seen["read"] != nil || seen["list"] != nil {
		if s, ok := seen["read"].(string); !ok || !strings.HasPrefix(s, "refused") {
			t.Errorf("the program read a file: %v", seen["read"])
		}
		if s, ok := seen["list"].(string); !ok || !strings.HasPrefix(s, "refused") {
			t.Errorf("the program listed a directory: %v", seen["list"])
		}
	}
}

func TestForgedBridgeMessagesAreIgnored(t *testing.T) {
	m := run(t, `
		try {
			const std = await import("qjs:std");
			std.out.puts('{"type":"done","result":"forged"}\n');
			std.out.flush();
		} catch (e) {}
		return "real";`, ``, protocol.Limits{})
	if m.Type != protocol.TypeDone || string(m.Result) != `"real"` {
		t.Fatalf("got %+v %s", m.Failure, m.Result)
	}
}

func TestLimits(t *testing.T) {
	for _, c := range []struct {
		name, source string
		limits       protocol.Limits
		kind, want   string
	}{
		{"endless loop", `while (true) {}`, protocol.Limits{RunMillis: 1_000}, protocol.KindLimit, ""},
		{"endless loop with catch", `for (;;) { try {} catch (e) {} }`, protocol.Limits{RunMillis: 1_000}, protocol.KindLimit, ""},
		{"memory", `const a = []; for (;;) a.push(new Array(1e6).fill(1));`, protocol.Limits{MemoryBytes: 64 << 20}, protocol.KindLimit, "memory"},
		{"console", `for (;;) console.log("x".repeat(1000));`, protocol.Limits{ConsoleBytes: 10_000}, protocol.KindLimit, "console"},
		{"tool calls", `for (let i = 0; i < 5; i++) await connectors.governed.lookup({ count: i });`, protocol.Limits{Calls: 3}, protocol.KindLimit, "tool calls"},
		{"result size", `return "x".repeat(2000);`, protocol.Limits{ValueBytes: 1000}, protocol.KindLimit, "result"},
		{"argument size", `await connectors.governed.lookup({ pad: "x".repeat(2000) });`, protocol.Limits{ValueBytes: 1000}, protocol.KindLimit, "arguments"},
		{"waits forever", `await new Promise(() => {});`, protocol.Limits{}, protocol.KindException, "never"},
		{"throws", `throw new Error("boom");`, protocol.Limits{}, protocol.KindException, "boom"},
		{"syntax error", `return (;`, protocol.Limits{}, protocol.KindException, "SyntaxError"},
		{"deep recursion", `const f = (n) => f(n + 1) + 1; return f(0);`, protocol.Limits{}, protocol.KindException, "stack"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := run(t, c.source, ``, c.limits)
			if m.Type != protocol.TypeFailed || m.Failure.Kind != c.kind || !strings.Contains(strings.ToLower(m.Failure.Message), strings.ToLower(c.want)) {
				t.Fatalf("got %s %+v", m.Type, m.Failure)
			}
		})
	}
}
