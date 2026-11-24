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
// of its result is written as its own data line. An event larger than the
// limit cannot be checked, so it is replaced with an error and the stream
// ends.
type EventRewriter struct {
	source    *bufio.Reader
	body      io.Closer
	transform func([]byte) []byte
	failure   []byte
	limit     int
	pending   []byte
	started   bool
	afterCR   bool
	done      bool
}

// NewEventRewriter wraps a streamed body. limit bounds the bytes of one event,
// and failure is the message sent in place of an event that exceeds it; nil
// sends an error without a request ID.
func NewEventRewriter(body io.ReadCloser, limit int, failure []byte, transform func([]byte) []byte) *EventRewriter {
	if failure == nil {
		failure = CheckFailed(nil)
	}
	return &EventRewriter{source: bufio.NewReader(body), body: body, transform: transform, failure: failure, limit: limit}
}

var errEventTooLarge = errors.New("event too large")

func (r *EventRewriter) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if r.done {
			return 0, io.EOF
		}
		event, err := r.readEvent()
		if errors.Is(err, errEventTooLarge) {
			event, err = dataLines(r.failure), io.EOF
			event = append(event, '\n')
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
		r.done = r.done || err == io.EOF
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
		if r.afterCR {
			r.afterCR = false
			if b == '\n' {
				continue
			}
		}
		*size++
		if *size > r.limit {
			return nil, errEventTooLarge
		}
		switch b {
		case '\n':
			return line, nil
		case '\r':
			// A following LF belongs to this line ending; it is skipped when
			// it arrives rather than waited for, so a CR-ended event is not
			// held back.
			r.afterCR = true
			return line, nil
		}
		line = append(line, b)
	}
}

// readEvent reads lines up to and including the blank line that ends an
// event, and returns the event with its data transformed. Only the fields the
// event-stream format defines are passed on, and comments; clients ignore any
// other field, so dropping it changes nothing for them and no line the
// rewriter did not recognize reaches a client. A comment outside an event is
// passed on at once, so keepalives are not held back.
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
		if err == io.EOF {
			// Clients discard an event the stream ended before completing,
			// so its data is neither checked nor passed on.
			return out.Bytes(), io.EOF
		}
		if len(line) == 0 {
			if data != nil {
				out.Write(dataLines(r.transform(bytes.Join(data, []byte("\n")))))
			}
			out.WriteString("\n")
			return out.Bytes(), nil
		}
		field, value, _ := bytes.Cut(line, []byte(":"))
		switch string(field) {
		case "data":
			data = append(data, bytes.TrimPrefix(value, []byte(" ")))
		case "":
			out.Write(line)
			out.WriteString("\n")
			if data == nil && out.Len() == len(line)+1 {
				return out.Bytes(), nil
			}
		case "event", "id", "retry":
			out.Write(line)
			out.WriteString("\n")
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

// End makes the event being transformed the last one passed on.
func (r *EventRewriter) End() { r.done = true }

// Close closes the wrapped body.
func (r *EventRewriter) Close() error { return r.body.Close() }

// UntilReview passes a stream through unchanged until reviewed reports that
// its proxy has come under drift review, then ends it. A client discards the
// event it was receiving and lists again, through the check, so a stream
// opened before review started cannot deliver an unchecked list after.
func UntilReview(body io.ReadCloser, reviewed func() bool) io.ReadCloser {
	return &untilReview{body: body, reviewed: reviewed}
}

type untilReview struct {
	body     io.ReadCloser
	reviewed func() bool
}

func (u *untilReview) Read(p []byte) (int, error) {
	if u.reviewed() {
		return 0, io.EOF
	}
	n, err := u.body.Read(p)
	// A read may block across the change, so what it returns is checked too.
	if u.reviewed() {
		return 0, io.EOF
	}
	return n, err
}

func (u *untilReview) Close() error { return u.body.Close() }
