package drift

import (
	"bufio"
	"bytes"
	"io"
)

// EventRewriter applies a transform to the data of each event in a
// server-sent event stream. An event's data may span several data lines; the
// rewritten data is written as one line, because a JSON-RPC message has no
// line breaks once encoded. Other fields and comments pass unchanged.
type EventRewriter struct {
	source    *bufio.Reader
	body      io.Closer
	transform func([]byte) []byte
	pending   []byte
	done      bool
}

// NewEventRewriter wraps a streamed body.
func NewEventRewriter(body io.ReadCloser, transform func([]byte) []byte) *EventRewriter {
	return &EventRewriter{source: bufio.NewReader(body), body: body, transform: transform}
}

func (r *EventRewriter) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if r.done {
			return 0, io.EOF
		}
		event, err := r.readEvent()
		if err != nil && err != io.EOF {
			return 0, err
		}
		r.done = err == io.EOF
		r.pending = event
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// readEvent reads lines up to and including the blank line that ends an
// event, and returns the event with its data transformed.
func (r *EventRewriter) readEvent() ([]byte, error) {
	var other [][]byte
	var data [][]byte
	var terminator []byte
	for {
		line, err := r.source.ReadBytes('\n')
		if len(line) > 0 {
			content := bytes.TrimRight(line, "\r\n")
			switch {
			case len(content) == 0:
				terminator = line
			case bytes.HasPrefix(content, []byte("data:")):
				value := bytes.TrimPrefix(content, []byte("data:"))
				data = append(data, bytes.TrimPrefix(value, []byte(" ")))
			default:
				other = append(other, line)
			}
		}
		if terminator != nil || err != nil {
			var out bytes.Buffer
			for _, line := range other {
				out.Write(line)
			}
			if data != nil {
				out.WriteString("data: ")
				out.Write(r.transform(bytes.Join(data, []byte("\n"))))
				out.WriteString("\n")
			}
			if terminator != nil {
				out.Write(terminator)
			} else if data != nil {
				out.WriteString("\n")
			}
			return out.Bytes(), err
		}
	}
}

// Close closes the wrapped body.
func (r *EventRewriter) Close() error { return r.body.Close() }
