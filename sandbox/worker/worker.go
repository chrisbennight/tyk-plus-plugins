// Package worker runs one Code Mode program in QuickJS compiled to
// WebAssembly. The engine has no file system, environment, network or
// process access; the program's only way out is a tool call, which the worker
// forwards to its host and answers with the host's reply.
package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	quickjswasi "github.com/aperturerobotics/go-quickjs-wasi-reactor"
	quickjs "github.com/aperturerobotics/go-quickjs-wasi-reactor/wazero-quickjs"
	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed bootstrap.js
var bootstrap string

// checksPerSecond approximates how many QuickJS interrupt checks one second of
// busy JavaScript passes, so the interrupt budget caps processor use at about
// the run time even when the program never waits.
const checksPerSecond = 1_500

// engineStartLimit bounds starting the engine, before the program's own run
// time begins.
const engineStartLimit = 30 * time.Second

// pageSize is the WebAssembly page size.
const pageSize = 64 << 10

// Runtime builds wazero runtimes that share a compilation cache, so a worker
// started from an image with a prepared cache does not compile the engine.
type Runtime struct {
	cache wazero.CompilationCache
}

// NewRuntime uses the compilation cache in dir, or an in-memory cache when dir
// is empty.
func NewRuntime(dir string) (*Runtime, error) {
	if dir == "" {
		return &Runtime{cache: wazero.NewCompilationCache()}, nil
	}
	cache, err := wazero.NewCompilationCacheWithDir(dir)
	if err != nil {
		return nil, err
	}
	return &Runtime{cache: cache}, nil
}

// Precompile compiles the engine into the cache.
func (rt *Runtime) Precompile(ctx context.Context) error {
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCompilationCache(rt.cache))
	defer r.Close(ctx)
	_, err := quickjs.CompileQuickJS(ctx, r)
	return err
}

// Replies delivers the host's answers to tool calls.
type Replies interface {
	// Next blocks until a reply arrives or ctx ends.
	Next(ctx context.Context) (protocol.Message, error)
}

// Run executes start.Source with start.Input under start.Limits. send receives
// each tool call; the returned message is the run's done or failed message.
func (rt *Runtime) Run(ctx context.Context, start protocol.Message, send func(protocol.Message) error, replies Replies) protocol.Message {
	if start.Limits == nil || !start.Limits.Valid() {
		return protocol.Failed(protocol.KindProtocol, "the start message has no valid limits")
	}
	limits := *start.Limits
	// Starting the engine does not count against the program's run time.
	setup, cancelSetup := context.WithTimeout(ctx, engineStartLimit)
	defer cancelSetup()

	pages := uint32(limits.MemoryBytes / pageSize)
	r := wazero.NewRuntimeWithConfig(setup, wazero.NewRuntimeConfig().
		WithCompilationCache(rt.cache).
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(pages))
	defer r.Close(context.Background())
	if _, err := wasi_snapshot_preview1.Instantiate(setup, r); err != nil {
		return protocol.Failed(protocol.KindUnavailable, "starting the engine: %v", err)
	}
	compiled, err := quickjs.CompileQuickJS(setup, r)
	if err != nil {
		return protocol.Failed(protocol.KindUnavailable, "compiling the engine: %v", err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return protocol.Failed(protocol.KindUnavailable, "creating a nonce: %v", err)
	}
	// One message per allowed call, each with at most ValueBytes of arguments
	// (already JSON, so not escaped again), plus the final message.
	queueBudget := limits.Calls*(limits.ValueBytes+4096) + limits.MaxResultLine()
	b := &bridge{nonce: hex.EncodeToString(nonce), max: limits.MaxResultLine(), budget: queueBudget,
		messages: limits.Calls + 1, valueBytes: limits.ValueBytes}
	stderr := &capped{max: 16 << 10}
	// No stdin, file system, environment or arguments: the engine's standard
	// library finds nothing to open.
	config := wazero.NewModuleConfig().WithStdout(b).WithStderr(stderr)
	q, err := quickjs.NewQuickJSWithModule(setup, r, compiled, config)
	if err != nil {
		return protocol.Failed(protocol.KindUnavailable, "instantiating the engine: %v", err)
	}
	defer q.Close(context.Background())
	if err := q.Init(setup, nil); err != nil {
		return protocol.Failed(protocol.KindUnavailable, "initializing the engine: %v", err)
	}
	if err := setMemoryLimit(setup, r, limits.MemoryBytes); err != nil {
		return protocol.Failed(protocol.KindUnavailable, "setting the memory limit: %v", err)
	}
	budget := limits.RunMillis * checksPerSecond / 1000
	if err := q.SetInterruptBudget(setup, max(budget, 1)); err != nil {
		return protocol.Failed(protocol.KindUnavailable, "setting the interrupt budget: %v", err)
	}

	script := strings.NewReplacer("NONCE", strconv.Quote(b.nonce), "CONSOLE_LIMIT", strconv.Itoa(limits.ConsoleBytes)).Replace(bootstrap)
	if err := q.EvalWithFilename(setup, script, "bootstrap.js", false); err != nil {
		return protocol.Failed(protocol.KindUnavailable, "installing the bootstrap: %v %s", err, stderr)
	}
	ctx, cancel := context.WithTimeout(ctx, timeMillis(limits.RunMillis))
	defer cancel()
	// A limit the bootstrap detects ends the run at once, even while the
	// program is still busy, by closing the engine through this context.
	ctx, halt := context.WithCancel(ctx)
	defer halt()
	b.setHalt(halt)

	input := start.Input
	if len(input) == 0 {
		input = json.RawMessage("null")
	}
	program := "__start(async function (input) {\n" + start.Source + "\n}, JSON.parse(" + jsonString(input) + "));"
	if err := q.EvalWithFilename(ctx, program, "program.js", false); err != nil {
		return protocol.Failed(protocol.KindException, "%s", strings.TrimSpace(stderr.String()))
	}

	pending := map[int64]bool{}
	calls := 0
	for {
		result, err := q.LoopOnce(ctx)
		messages := b.take()
		if f := b.failure(); f != nil {
			return *f
		}
		// A final message halts the engine, so look for it before treating
		// the halt as an error.
		for _, m := range messages {
			if m.Type == protocol.TypeDone || m.Type == protocol.TypeFailed {
				err, result = nil, 0
			}
		}
		if err != nil || result == quickjs.LoopError {
			for _, m := range messages {
				if m.Type == protocol.TypeFailed {
					return classify(m)
				}
			}
			return stopped(ctx, q, stderr, err)
		}
		for _, m := range messages {
			switch m.Type {
			case protocol.TypeCall:
				calls++
				if calls > limits.Calls {
					return protocol.Failed(protocol.KindLimit, "the run made more than %d tool calls", limits.Calls)
				}
				pending[m.ID] = true
				if err := send(m); err != nil {
					return protocol.Failed(protocol.KindProtocol, "sending a tool call: %v", err)
				}
			case protocol.TypeDone:
				if len(m.Result) > limits.ValueBytes {
					return protocol.Failed(protocol.KindLimit, "the result exceeds %d bytes", limits.ValueBytes)
				}
				if n := protocol.ConsoleBytes(m.Console); n > limits.ConsoleBytes {
					return protocol.Failed(protocol.KindLimit, "console output exceeds %d bytes", limits.ConsoleBytes)
				}
				return m
			case protocol.TypeFailed:
				return classify(m)
			}
		}
		if result == 0 {
			continue
		}
		if len(pending) == 0 && result == quickjs.LoopIdle {
			return protocol.Failed(protocol.KindException, "the program stopped without returning: it is waiting for something that can never happen")
		}
		// Wait for a reply, or only until the program's next timer is due.
		wait, stop := ctx, context.CancelFunc(func() {})
		if result > 0 {
			wait, stop = context.WithTimeout(ctx, time.Duration(result.NextTimerMs())*time.Millisecond)
		}
		if len(pending) == 0 {
			<-wait.Done()
			stop()
			if ctx.Err() != nil {
				return stopped(ctx, q, stderr, ctx.Err())
			}
			continue
		}
		reply, err := replies.Next(wait)
		stop()
		if err != nil {
			if ctx.Err() == nil && wait.Err() != nil {
				continue
			}
			return stopped(ctx, q, stderr, err)
		}
		if !pending[reply.ID] {
			return protocol.Failed(protocol.KindProtocol, "a reply answers no pending tool call")
		}
		delete(pending, reply.ID)
		var settle string
		switch {
		case reply.Type == protocol.TypeResult && json.Valid(reply.Result):
			settle = fmt.Sprintf("__settle(%d, true, JSON.parse(%s));", reply.ID, jsonString(reply.Result))
		case reply.Type == protocol.TypeError && reply.Error != nil:
			detail, _ := json.Marshal(reply.Error)
			settle = fmt.Sprintf("__settle(%d, false, JSON.parse(%s));", reply.ID, jsonString(detail))
		default:
			return protocol.Failed(protocol.KindProtocol, "a reply is neither a JSON result nor an error")
		}
		if err := q.EvalWithFilename(ctx, settle, "host.js", false); err != nil {
			return stopped(ctx, q, stderr, err)
		}
	}
}

// classify reports a program that ran out of JavaScript heap as reaching its
// memory limit rather than as an ordinary exception.
func classify(m protocol.Message) protocol.Message {
	if m.Failure != nil && m.Failure.Kind == protocol.KindException && strings.Contains(m.Failure.Message, "out of memory") {
		return protocol.Failed(protocol.KindLimit, "the run exceeded its memory limit")
	}
	return m
}

// stopped explains why the engine stopped: the run's time ran out, the
// interrupt budget was spent, memory ran out, or the program threw.
func stopped(ctx context.Context, q *quickjs.QuickJS, stderr *capped, err error) protocol.Message {
	if ctx.Err() != nil {
		return protocol.Failed(protocol.KindLimit, "the run exceeded its run time")
	}
	if left, berr := q.InterruptBudget(context.Background()); berr == nil && left == 0 {
		return protocol.Failed(protocol.KindLimit, "the run exceeded its processor budget")
	}
	detail := strings.TrimSpace(stderr.String())
	if strings.Contains(detail, "out of memory") {
		return protocol.Failed(protocol.KindLimit, "the run exceeded its memory limit")
	}
	if detail == "" && err != nil {
		detail = err.Error()
	}
	return protocol.Failed(protocol.KindException, "%s", detail)
}

// setMemoryLimit sets QuickJS's own heap limit below the WebAssembly memory
// cap, so most programs that allocate too much get a JavaScript error rather
// than a failed allocation inside the engine.
func setMemoryLimit(ctx context.Context, r wazero.Runtime, limit int64) error {
	mod := r.Module(quickjswasi.QuickJSWASMFilename)
	if mod == nil {
		return errors.New("engine module not found")
	}
	getContext := mod.ExportedFunction(quickjswasi.ExportQJSGetContext)
	getRuntime := mod.ExportedFunction(quickjswasi.ExportJSGetRuntime)
	setLimit := mod.ExportedFunction(quickjswasi.ExportJSSetMemoryLimit)
	if getContext == nil || getRuntime == nil || setLimit == nil {
		return errors.New("engine memory exports not found")
	}
	jsContext, err := getContext.Call(ctx)
	if err != nil {
		return err
	}
	jsRuntime, err := getRuntime.Call(ctx, jsContext[0])
	if err != nil {
		return err
	}
	heap := limit - 16<<20
	if heap < 8<<20 {
		heap = limit / 2
	}
	_, err = setLimit.Call(ctx, jsRuntime[0], uint64(heap))
	return err
}

// jsonString quotes JSON text as a JavaScript string literal, so values reach
// the program through JSON.parse with JSON's own semantics.
func jsonString(text []byte) string {
	quoted, _ := json.Marshal(string(text))
	return string(quoted)
}

func timeMillis(ms int64) time.Duration { return time.Duration(ms) * time.Millisecond }

// bridge receives what the bootstrap prints. Lines without the run's nonce
// are ignored, so a program that reaches the engine's standard output some
// other way cannot pose as the bootstrap. A program can still shape what the
// bootstrap prints, so the bridge bounds what it holds by bytes alone: every
// line, finished or not, is limited to max, everything queued together to
// budget, and the number of messages to messages. The first final message
// stops the engine and the bridge accepts nothing after it.
type bridge struct {
	nonce      string
	max        int
	budget     int
	messages   int
	valueBytes int
	mu         sync.Mutex
	partial    []byte
	queued     int
	queue      []protocol.Message
	failed     *protocol.Message
	finished   bool
	halt       context.CancelFunc
}

func (b *bridge) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.finished || b.failed != nil {
		return len(p), nil
	}
	b.partial = append(b.partial, p...)
	for b.failed == nil && !b.finished {
		i := bytes.IndexByte(b.partial, '\n')
		if i < 0 {
			if len(b.partial) > b.max {
				b.fail(protocol.Failed(protocol.KindLimit, "a message from the program exceeds %d bytes", b.max))
			}
			return len(p), nil
		}
		line := b.partial[:i]
		b.partial = b.partial[i+1:]
		if len(line) > b.max {
			b.fail(protocol.Failed(protocol.KindLimit, "a message from the program exceeds %d bytes", b.max))
			break
		}
		rest, ok := bytes.CutPrefix(line, []byte(b.nonce))
		if !ok {
			continue
		}
		b.queued += len(rest)
		b.messages--
		if b.messages < 0 {
			b.fail(protocol.Failed(protocol.KindLimit, "the run sent more messages than its tool-call limit allows"))
			break
		}
		if b.queued > b.budget {
			b.fail(protocol.Failed(protocol.KindLimit, "the run sent more than %d bytes of messages", b.budget))
			break
		}
		var m protocol.Message
		if err := protocol.Decode(rest, &m); err != nil {
			b.fail(protocol.Failed(protocol.KindProtocol, "the bootstrap sent an unreadable message: %v", err))
			break
		}
		switch m.Type {
		case protocol.TypeCall:
			if len(m.Arguments) > b.valueBytes {
				b.fail(protocol.Failed(protocol.KindLimit, "tool call arguments exceed %d bytes", b.valueBytes))
				continue
			}
			b.queue = append(b.queue, m)
		case protocol.TypeDone, protocol.TypeFailed:
			b.queue = append(b.queue, m)
			b.finished = true
			b.partial = nil
			if b.halt != nil {
				b.halt()
			}
		default:
			b.fail(protocol.Failed(protocol.KindProtocol, "the bootstrap sent a %q message", m.Type))
		}
	}
	return len(p), nil
}

// fail records the first failure, drops queued messages and stops the engine.
// The caller holds b.mu.
func (b *bridge) fail(f protocol.Message) {
	if b.failed == nil {
		b.failed = &f
	}
	b.queue = nil
	if b.halt != nil {
		b.halt()
	}
}

func (b *bridge) setHalt(halt context.CancelFunc) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.halt = halt
}

func (b *bridge) failure() *protocol.Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failed
}

func (b *bridge) take() []protocol.Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	q := b.queue
	b.queue = nil
	return q
}

// capped keeps the first max bytes written to it.
type capped struct {
	mu  sync.Mutex
	max int
	buf bytes.Buffer
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (c *capped) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}
