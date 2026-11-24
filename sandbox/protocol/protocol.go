// Package protocol defines the messages exchanged between the gateway
// plug-in, the sandbox service, the launcher helper and the worker that runs a
// program. Every hop carries one JSON object per line, and every reader bounds
// the size of a line before decoding it.
package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Backends a sandbox service can report. Gateways accept only the backends
// they are configured to accept.
const (
	BackendGVisor = "gvisor"
	BackendRunc   = "runc"
)

// Failure kinds reported in a Failed message.
const (
	// KindLimit means a run reached one of its limits; the message names it.
	KindLimit = "limit"
	// KindException means the program threw, rejected, or never finished.
	KindException = "exception"
	// KindBusy means the sandbox service is at capacity.
	KindBusy = "busy"
	// KindUnavailable means no sandbox could be started.
	KindUnavailable = "unavailable"
	// KindProtocol means a peer sent a message that breaks this protocol.
	KindProtocol = "protocol"
)

// Limits bound one run. A zero field means the default.
type Limits struct {
	// RunMillis bounds the whole run, including time spent waiting on tools.
	RunMillis int64 `json:"run_ms,omitempty"`
	// MemoryBytes bounds the program's WebAssembly memory.
	MemoryBytes int64 `json:"memory_bytes,omitempty"`
	// Calls bounds the tool calls a run may make.
	Calls int `json:"calls,omitempty"`
	// ProgramBytes bounds the program source.
	ProgramBytes int `json:"program_bytes,omitempty"`
	// ConsoleBytes bounds the console output a run may capture.
	ConsoleBytes int `json:"console_bytes,omitempty"`
	// ValueBytes bounds the input, each tool call's arguments and result, and
	// the final result.
	ValueBytes int `json:"value_bytes,omitempty"`
}

// DefaultLimits are the limits a run gets when neither the operator nor the
// caller sets them.
var DefaultLimits = Limits{
	RunMillis:    30_000,
	MemoryBytes:  128 << 20,
	Calls:        64,
	ProgramBytes: 256 << 10,
	ConsoleBytes: 256 << 10,
	ValueBytes:   1 << 20,
}

// Within returns the requested limits with every unset field taken from max
// and every field above max lowered to it, so a caller can lower a limit but
// never raise one.
func (l Limits) Within(max Limits) Limits {
	low64 := func(v, m int64) int64 {
		if v <= 0 || v > m {
			return m
		}
		return v
	}
	low := func(v, m int) int {
		if v <= 0 || v > m {
			return m
		}
		return v
	}
	return Limits{
		RunMillis:    low64(l.RunMillis, max.RunMillis),
		MemoryBytes:  low64(l.MemoryBytes, max.MemoryBytes),
		Calls:        low(l.Calls, max.Calls),
		ProgramBytes: low(l.ProgramBytes, max.ProgramBytes),
		ConsoleBytes: low(l.ConsoleBytes, max.ConsoleBytes),
		ValueBytes:   low(l.ValueBytes, max.ValueBytes),
	}
}

// Valid reports whether every limit is positive.
func (l Limits) Valid() bool {
	return l.RunMillis > 0 && l.MemoryBytes > 0 && l.Calls > 0 && l.ProgramBytes > 0 && l.ConsoleBytes > 0 && l.ValueBytes > 0
}

// MaxLine is the longest line any message of a run can need under limits l:
// the program and input together, or a final result with its console output,
// plus room for the surrounding fields. JSON escaping can turn one byte into
// six (a control character becomes \u00XX), so the bound allows for that.
func (l Limits) MaxLine() int {
	return 6*(l.ProgramBytes+l.ValueBytes+l.ConsoleBytes) + 64<<10
}

// MaxResultLine is the longest message a program can need to send: a final
// result with its console output, escaped, plus room for the surrounding
// fields. Tool calls are smaller, since their arguments are bounded by
// ValueBytes alone.
func (l Limits) MaxResultLine() int {
	return 6*(l.ValueBytes+l.ConsoleBytes) + 64<<10
}

// Error is a refused or failed tool call, as a direct caller would see it.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Failure explains why a run ended without a result.
type Failure struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// Message is the union of every message in the protocol; Type selects which
// fields are meaningful.
type Message struct {
	Type string `json:"type"`

	// hello and health: the backend that runs sandboxes.
	Backend string `json:"backend,omitempty"`

	// start
	Source string          `json:"source,omitempty"`
	Input  json.RawMessage `json:"input,omitempty"`
	Limits *Limits         `json:"limits,omitempty"`

	// call, result and error
	ID        int64           `json:"id,omitempty"`
	Proxy     string          `json:"proxy,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *Error          `json:"error,omitempty"`

	// done
	Console []string `json:"console,omitempty"`

	// failed
	Failure *Failure `json:"failure,omitempty"`

	// health
	Health *Health `json:"health,omitempty"`
}

// Message types.
const (
	TypeHello  = "hello"
	TypeHealth = "health"
	TypeStart  = "start"
	TypeCall   = "call"
	TypeResult = "result"
	TypeError  = "error"
	TypeDone   = "done"
	TypeFailed = "failed"
)

// SelfTestChecks are the isolation checks a host's startup self-test must
// report as blocked before the host takes runs.
var SelfTestChecks = []string{"network", "host file", "write", "processes"}

// Health reports whether a sandbox host can take runs.
type Health struct {
	Backend string `json:"backend"`
	Ready   bool   `json:"ready"`
	Problem string `json:"problem,omitempty"`
	// SelfTest maps each startup isolation check to its outcome.
	SelfTest map[string]string `json:"self_test,omitempty"`
	// Active counts runs the launcher is tracking; Containers counts the
	// containers the runtime itself reports.
	Active     int `json:"active"`
	Containers int `json:"containers"`
}

// Failed builds a failure message.
func Failed(kind, format string, args ...any) Message {
	return Message{Type: TypeFailed, Failure: &Failure{Kind: kind, Message: fmt.Sprintf(format, args...)}}
}

// ErrLineTooLong reports a line longer than the reader's bound.
var ErrLineTooLong = errors.New("message exceeds the size limit")

// Reader reads newline-terminated JSON messages of bounded size.
type Reader struct {
	r   *bufio.Reader
	max int
}

// NewReader reads lines of at most max bytes from r.
func NewReader(r io.Reader, max int) *Reader {
	return &Reader{r: bufio.NewReaderSize(r, 64<<10), max: max}
}

// SetMax changes the bound for later lines.
func (r *Reader) SetMax(max int) { r.max = max }

// Line returns the next line without its newline.
func (r *Reader) Line() ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.r.ReadSlice('\n')
		if len(line)+len(chunk) > r.max+1 {
			return nil, ErrLineTooLong
		}
		line = append(line, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if err == io.EOF && len(line) > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		return bytes.TrimSuffix(line, []byte("\n")), nil
	}
}

// Read decodes the next line into m, rejecting unknown fields.
func (r *Reader) Read(m *Message) error {
	line, err := r.Line()
	if err != nil {
		return err
	}
	return Decode(line, m)
}

// Decode decodes one message, rejecting unknown fields and trailing data.
func Decode(line []byte, m *Message) error {
	*m = Message{}
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(m); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing data after message")
	}
	return nil
}

// Write encodes m as one line.
func Write(w io.Writer, m Message) error {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(m); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// ConsoleBytes is the size of console output as the limit counts it: each
// line's UTF-8 bytes plus one for its line break.
func ConsoleBytes(lines []string) int {
	n := 0
	for _, l := range lines {
		n += len(l) + 1
	}
	return n
}
