package protocol

import (
	"errors"
	"strings"
	"testing"
)

func TestWithinLowersButNeverRaises(t *testing.T) {
	max := DefaultLimits
	got := Limits{RunMillis: 5_000, Calls: 1_000, MemoryBytes: -1}.Within(max)
	if got.RunMillis != 5_000 {
		t.Errorf("a lower run time was not kept: %d", got.RunMillis)
	}
	if got.Calls != max.Calls {
		t.Errorf("a higher call limit was not lowered: %d", got.Calls)
	}
	if got.MemoryBytes != max.MemoryBytes || got.ValueBytes != max.ValueBytes {
		t.Errorf("unset or invalid limits did not take the maximum: %+v", got)
	}
	if !got.Valid() {
		t.Errorf("limits within valid maximums are invalid: %+v", got)
	}
}

func TestReaderBoundsLines(t *testing.T) {
	long := strings.Repeat("x", 200)
	r := NewReader(strings.NewReader(`{"type":"hello"}`+"\n"+long+"\n"), 100)
	var m Message
	if err := r.Read(&m); err != nil || m.Type != TypeHello {
		t.Fatalf("short line: %v %+v", err, m)
	}
	if _, err := r.Line(); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("long line: %v", err)
	}
}

func TestDecodeRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	var m Message
	if err := Decode([]byte(`{"type":"start","path":"/etc"}`), &m); err == nil {
		t.Error("an unknown field was accepted")
	}
	if err := Decode([]byte(`{"type":"start"} {"type":"start"}`), &m); err == nil {
		t.Error("trailing data was accepted")
	}
}
