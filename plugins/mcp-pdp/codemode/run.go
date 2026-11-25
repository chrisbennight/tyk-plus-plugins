package codemode

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// KindCancelled reports a run that ended because its client went away. It is
// local to the gateway and never sent by a sandbox host.
const KindCancelled = "cancelled"

// writeWait bounds each write to the sandbox host, so one that stops reading
// cannot hold a run past its limits.
const writeWait = 10 * time.Second

// ErrTooLarge reports a tool result larger than the run's value limit.
var ErrTooLarge = errors.New("tool result too large")

// Call sends one tool call through the gateway. It returns the call's result,
// or the error a direct caller would get. A non-nil err means the call did
// not complete, so whether the tool acted is unknown.
type Call func(ctx context.Context, proxy, tool string, args json.RawMessage) (result json.RawMessage, refused *protocol.Error, err error)

// Request is one run.
type Request struct {
	Source string
	Input  json.RawMessage
	Limits Limits
	Call   Call
	// OnCall reports each finished call, for the audit log.
	OnCall func(CallRecord)
}

// CallRecord describes one tool call a run made.
type CallRecord struct {
	ID          int64
	Proxy, Tool string
	// Outcome is "result", "refused", "failed" or "unknown".
	Outcome string
}

// Outcome is how a run ended.
type Outcome struct {
	Result  json.RawMessage
	Console []string
	// Failure is set when the run ended without a result.
	Failure *protocol.Failure
	// Backend is the sandbox backend that ran the program, once known.
	Backend string
	// Calls counts the tool calls the program made, by outcome.
	Calls, Refused, Failed, Unknown int
}

// Runner starts runs on a sandbox host.
type Runner struct {
	address  string
	tls      *tls.Config
	backends map[string]bool
	slots    chan struct{}
}

// NewRunner builds a runner from settings.
func NewRunner(s *Settings) *Runner {
	return &Runner{address: s.Address, tls: s.TLS, backends: s.Backends, slots: make(chan struct{}, s.Runs)}
}

func failed(kind, format string, args ...any) *protocol.Failure {
	return &protocol.Failure{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

// Run runs a program to completion. Cancelling ctx, as when the client
// disconnects, stops new calls and ends the run.
func (r *Runner) Run(ctx context.Context, req Request) (out Outcome) {
	limits := req.Limits
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		out.Failure = failed(protocol.KindBusy, "this gateway is running %d Code Mode runs, its limit; try again shortly", cap(r.slots))
		return out
	}
	if len(req.Source) > limits.ProgramBytes {
		out.Failure = failed(protocol.KindLimit, "the program exceeds the program size limit of %d bytes", limits.ProgramBytes)
		return out
	}
	if len(req.Input) > limits.ValueBytes {
		out.Failure = failed(protocol.KindLimit, "the input exceeds the value size limit of %d bytes", limits.ValueBytes)
		return out
	}
	// The sandbox host enforces the run time; this backstop covers a host
	// that stops responding.
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(limits.RunMillis)*time.Millisecond+startAllowance)
	defer cancel()
	dialer := tls.Dialer{Config: r.tls}
	conn, err := dialer.DialContext(runCtx, "tcp", r.address)
	if err != nil {
		out.Failure = r.ended(ctx, runCtx, failed(protocol.KindUnavailable, "the sandbox host is unreachable"))
		return out
	}
	defer conn.Close()
	// Ending the run, for any reason, closes the connection, which unblocks
	// every read and write and makes the sandbox host destroy the sandbox.
	stop := context.AfterFunc(runCtx, func() { conn.Close() })
	defer stop()

	reader := protocol.NewReader(conn, limits.MaxResultLine())
	var writeMu sync.Mutex
	send := func(m protocol.Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(writeWait))
		return protocol.Write(conn, m)
	}

	var hello protocol.Message
	if err := reader.Read(&hello); err != nil {
		out.Failure = r.ended(ctx, runCtx, failed(protocol.KindUnavailable, "the sandbox host did not answer"))
		return out
	}
	switch {
	case hello.Type == protocol.TypeFailed && hello.Failure != nil:
		out.Failure = hostFailure(hello.Failure)
		return out
	case hello.Type != protocol.TypeHello:
		out.Failure = failed(protocol.KindProtocol, "the sandbox host sent %q instead of hello", hello.Type)
		return out
	case !r.backends[hello.Backend]:
		out.Failure = failed(protocol.KindUnavailable, "the sandbox host runs backend %q, which this gateway does not accept", hello.Backend)
		return out
	}
	out.Backend = hello.Backend
	sandboxLimits := limits.Limits
	if err := send(protocol.Message{Type: protocol.TypeStart, Source: req.Source, Input: req.Input, Limits: &sandboxLimits}); err != nil {
		out.Failure = r.ended(ctx, runCtx, failed(protocol.KindUnavailable, "the sandbox host stopped responding"))
		return out
	}

	// Calls run in their own goroutines, at most CallsAtOnce at a time, and
	// end when the run does.
	callCtx, stopCalls := context.WithCancel(runCtx)
	var calls sync.WaitGroup
	var statsMu sync.Mutex
	defer func() {
		stopCalls()
		calls.Wait()
	}()
	slots := make(chan struct{}, limits.CallsAtOnce)
	// A failure found while handling a call ends the run.
	fatal := make(chan *protocol.Failure, 1)
	record := func(c CallRecord) {
		statsMu.Lock()
		switch c.Outcome {
		case "refused":
			out.Refused++
		case "failed":
			out.Failed++
		case "unknown":
			out.Unknown++
		}
		statsMu.Unlock()
		if req.OnCall != nil {
			req.OnCall(c)
		}
	}
	seen := map[int64]bool{}
	messages := make(chan protocol.Message)
	readErr := make(chan error, 1)
	go func() {
		for {
			var m protocol.Message
			if err := reader.Read(&m); err != nil {
				readErr <- err
				return
			}
			select {
			case messages <- m:
			case <-callCtx.Done():
				return
			}
		}
	}()
	for {
		var m protocol.Message
		select {
		case m = <-messages:
		case err := <-readErr:
			if errors.Is(err, protocol.ErrLineTooLong) {
				out.Failure = failed(protocol.KindLimit, "the sandbox host sent a message larger than the run's limits allow")
			} else {
				out.Failure = r.ended(ctx, runCtx, failed(protocol.KindUnavailable, "the sandbox host closed the run without a result"))
			}
			return out
		case f := <-fatal:
			out.Failure = f
			return out
		case <-runCtx.Done():
			out.Failure = r.ended(ctx, runCtx, nil)
			return out
		}
		switch m.Type {
		case protocol.TypeCall:
			if m.ID <= 0 || seen[m.ID] {
				out.Failure = failed(protocol.KindProtocol, "the sandbox host sent a tool call with a missing or repeated identifier")
				return out
			}
			seen[m.ID] = true
			statsMu.Lock()
			out.Calls++
			over := out.Calls > limits.Calls
			statsMu.Unlock()
			if over {
				out.Failure = failed(protocol.KindLimit, "the run made more than %d tool calls, the calls per run limit", limits.Calls)
				return out
			}
			if len(m.Arguments) > limits.ValueBytes {
				out.Failure = failed(protocol.KindLimit, "tool call arguments exceed the value size limit of %d bytes", limits.ValueBytes)
				return out
			}
			calls.Add(1)
			go func(m protocol.Message) {
				defer calls.Done()
				select {
				case slots <- struct{}{}:
					defer func() { <-slots }()
				case <-callCtx.Done():
					return
				}
				reply, outcome, f := r.call(callCtx, req.Call, m, limits)
				record(CallRecord{ID: m.ID, Proxy: m.Proxy, Tool: m.Tool, Outcome: outcome})
				if f != nil {
					select {
					case fatal <- f:
					default:
					}
					return
				}
				if callCtx.Err() != nil {
					return
				}
				if err := send(reply); err != nil {
					select {
					case fatal <- failed(protocol.KindUnavailable, "the sandbox host stopped responding"):
					default:
					}
				}
			}(m)
		case protocol.TypeDone:
			if len(m.Result) > limits.ValueBytes || !json.Valid(m.Result) {
				out.Failure = failed(protocol.KindLimit, "the result must be JSON within the value size limit of %d bytes", limits.ValueBytes)
				return out
			}
			if protocol.ConsoleBytes(m.Console) > limits.ConsoleBytes {
				out.Failure = failed(protocol.KindLimit, "console output exceeds the console limit of %d bytes", limits.ConsoleBytes)
				return out
			}
			out.Result, out.Console = m.Result, m.Console
			return out
		case protocol.TypeFailed:
			if m.Failure == nil {
				m.Failure = failed(protocol.KindException, "the program failed")
			}
			out.Failure = m.Failure
			return out
		default:
			out.Failure = failed(protocol.KindProtocol, "the sandbox host sent a %q message during a run", m.Type)
			return out
		}
	}
}

// call makes one tool call and builds the reply for the program. A failure
// it returns ends the run.
func (r *Runner) call(ctx context.Context, call Call, m protocol.Message, limits Limits) (protocol.Message, string, *protocol.Failure) {
	reply := protocol.Message{Type: protocol.TypeError, ID: m.ID}
	if strings.HasPrefix(m.Tool, ToolPrefix) {
		// Programs cannot run programs; the refusal reads as any other.
		reply.Error = &protocol.Error{Code: -32002, Message: "Tool call denied"}
		return reply, "refused", nil
	}
	if !validToolName(m.Tool) || len(m.Proxy) == 0 || len(m.Proxy) > 256 {
		reply.Error = &protocol.Error{Code: -32602, Message: "the tool call names no valid proxy and tool"}
		return reply, "refused", nil
	}
	args := m.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	timed, cancel := context.WithTimeout(ctx, time.Duration(limits.CallMillis)*time.Millisecond)
	defer cancel()
	result, refused, err := call(timed, m.Proxy, m.Tool, args)
	switch {
	case errors.Is(err, ErrTooLarge):
		return reply, "result", failed(protocol.KindLimit, "tool call %s on %s returned more than the value size limit of %d bytes", m.Tool, m.Proxy, limits.ValueBytes)
	case err != nil && ctx.Err() != nil:
		// The run ended while the call was in flight.
		return reply, "unknown", nil
	case err != nil && timed.Err() != nil:
		reply.Error = &protocol.Error{Code: -32001, Message: fmt.Sprintf("the tool call exceeded the time per call limit of %d ms; whether it took effect is unknown", limits.CallMillis)}
		return reply, "unknown", nil
	case err != nil:
		reply.Error = &protocol.Error{Code: -32603, Message: "the tool call did not complete; whether it took effect is unknown"}
		return reply, "unknown", nil
	case refused != nil:
		reply.Error = refused
		if len(reply.Error.Message) > limits.ValueBytes {
			reply.Error.Message = reply.Error.Message[:limits.ValueBytes]
		}
		return reply, "refused", nil
	case len(result) > limits.ValueBytes:
		return reply, "result", failed(protocol.KindLimit, "tool call %s on %s returned more than the value size limit of %d bytes", m.Tool, m.Proxy, limits.ValueBytes)
	}
	reply.Type, reply.Result = protocol.TypeResult, result
	if isErrorResult(result) {
		return reply, "failed", nil
	}
	return reply, "result", nil
}

// isErrorResult reports a tool result the tool itself marked as an error.
func isErrorResult(result json.RawMessage) bool {
	var r struct {
		IsError bool `json:"isError"`
	}
	return json.Unmarshal(result, &r) == nil && r.IsError
}

// validToolName accepts names that are not empty, not too long and free of
// control characters.
func validToolName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// ended explains a run that stopped because its context ended, or returns
// fallback when it did not.
func (r *Runner) ended(client, run context.Context, fallback *protocol.Failure) *protocol.Failure {
	switch {
	case client.Err() != nil:
		return failed(KindCancelled, "the client disconnected; the run was stopped")
	case run.Err() != nil:
		return failed(protocol.KindLimit, "the run exceeded the run time limit")
	}
	if fallback == nil {
		return failed(protocol.KindUnavailable, "the run ended")
	}
	return fallback
}

// hostFailure passes on a failure a sandbox host reported before the run
// started, keeping only kinds a host may report.
func hostFailure(f *protocol.Failure) *protocol.Failure {
	switch f.Kind {
	case protocol.KindBusy, protocol.KindUnavailable, protocol.KindLimit, protocol.KindProtocol:
		return f
	}
	return failed(protocol.KindUnavailable, "%s", f.Message)
}
