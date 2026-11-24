package drift

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// EventRewriter applies a transform to the data of each event in a
// server-sent event stream. Lines are read as the event-stream format defines
// them: ended by CRLF, LF or CR, after an optional leading byte order mark.
// Data spanning several lines is joined before the transform, and each line
// of its result is written as its own data line. Other fields and comments
// pass unchanged. An event larger than the limit cannot be checked, so it is
// replaced with an error and the stream ends.
type EventRewriter struct {
	source    *bufio.Reader
	body      io.Closer
	transform func([]byte) []byte
	limit     int
	pending   []byte
	started   bool
	done      bool
}

// NewEventRewriter wraps a streamed body. limit bounds the bytes of one event.
func NewEventRewriter(body io.ReadCloser, limit int, transform func([]byte) []byte) *EventRewriter {
	return &EventRewriter{source: bufio.NewReader(body), body: body, transform: transform, limit: limit}
}

var errEventTooLarge = errors.New("event too large")

func (r *EventRewriter) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if r.done {
			return 0, io.EOF
		}
		event, err := r.readEvent()
		if errors.Is(err, errEventTooLarge) {
			event, err = dataLines(CheckFailed(nil)), io.EOF
			event = append(event, '\n')
		}
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

// readLine returns one line without its ending. size counts the bytes read
// for the current event, so a line without an end cannot grow without limit.
func (r *EventRewriter) readLine(size *int) ([]byte, error) {
	var line []byte
	for {
		b, err := r.source.ReadByte()
		if err != nil {
			if len(line) > 0 && err == io.EOF {
				return line, nil
			}
			return line, err
		}
		*size++
		if *size > r.limit {
			return nil, errEventTooLarge
		}
		switch b {
		case '\n':
			return line, nil
		case '\r':
			if next, err := r.source.Peek(1); err == nil && next[0] == '\n' {
				r.source.ReadByte()
			}
			return line, nil
		}
		line = append(line, b)
	}
}

// readEvent reads lines up to and including the blank line that ends an
// event, and returns the event with its data transformed.
func (r *EventRewriter) readEvent() ([]byte, error) {
	var out bytes.Buffer
	var data [][]byte
	size := 0
	for {
		line, err := r.readLine(&size)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if !r.started {
			r.started = true
			line = bytes.TrimPrefix(line, []byte("\xef\xbb\xbf"))
		}
		ended := err == io.EOF
		if err == nil && len(line) == 0 {
			if data != nil {
				out.Write(dataLines(r.transform(bytes.Join(data, []byte("\n")))))
			}
			out.WriteString("\n")
			return out.Bytes(), nil
		}
		if len(line) > 0 {
			field, value, _ := bytes.Cut(line, []byte(":"))
			if len(field) > 0 && string(field) == "data" {
				data = append(data, bytes.TrimPrefix(value, []byte(" ")))
			} else {
				out.Write(line)
				out.WriteString("\n")
			}
		}
		if ended {
			if data != nil {
				out.Write(dataLines(r.transform(bytes.Join(data, []byte("\n")))))
				out.WriteString("\n")
			}
			return out.Bytes(), io.EOF
		}
	}
}

// dataLines writes a message as data lines, one per line of the message.
func dataLines(message []byte) []byte {
	var out bytes.Buffer
	normalized := bytes.ReplaceAll(bytes.ReplaceAll(message, []byte("\r\n"), []byte("\n")), []byte("\r"), []byte("\n"))
	for _, line := range bytes.Split(normalized, []byte("\n")) {
		out.WriteString("data: ")
		out.Write(line)
		out.WriteString("\n")
	}
	return out.Bytes()
}

// Close closes the wrapped body.
func (r *EventRewriter) Close() error { return r.body.Close() }
