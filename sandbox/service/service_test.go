package service

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/launcher"
	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// exchange connects to a service, sends start, and returns the hello and the
// service's answer.
func exchange(t *testing.T, s *Service, start protocol.Message) (protocol.Message, protocol.Message) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go s.Handle(server)
	r := protocol.NewReader(client, 1<<20)
	var hello, answer protocol.Message
	if err := r.Read(&hello); err != nil {
		t.Fatal(err)
	}
	if err := protocol.Write(client, start); err != nil {
		t.Fatal(err)
	}
	if err := r.Read(&answer); err != nil {
		t.Fatal(err)
	}
	return hello, answer
}

func testService(h *protocol.Health) (*Service, *int) {
	launched := 0
	s := &Service{config: Config{Capacity: 1, Max: protocol.DefaultLimits},
		health: func() (*protocol.Health, error) { return h, nil },
		launch: func(int64) (*launcher.Run, error) { launched++; return nil, errors.New("not in this test") },
	}
	return s, &launched
}

func TestFailedSelfTestRefusesEveryRun(t *testing.T) {
	s, launched := testService(&protocol.Health{Backend: "gvisor", Ready: false, Problem: "the self-test sandbox was not isolated: network"})
	hello, answer := exchange(t, s, protocol.Message{Type: protocol.TypeStart, Source: "return 1;"})
	if hello.Backend != "gvisor" {
		t.Errorf("hello did not report the backend: %+v", hello)
	}
	if answer.Type != protocol.TypeFailed || answer.Failure.Kind != protocol.KindUnavailable || !strings.Contains(answer.Failure.Message, "not isolated: network") {
		t.Errorf("got %+v", answer.Failure)
	}
	if *launched != 0 {
		t.Error("a sandbox was requested from a host that failed its self-test")
	}
}

func TestBusyAtCapacity(t *testing.T) {
	s, launched := testService(&protocol.Health{Backend: "gvisor", Ready: true})
	s.active.Store(1)
	_, answer := exchange(t, s, protocol.Message{Type: protocol.TypeStart, Source: "return 1;"})
	if answer.Type != protocol.TypeFailed || answer.Failure.Kind != protocol.KindBusy || *launched != 0 {
		t.Errorf("got %+v, launched %d", answer.Failure, *launched)
	}
}

func TestOversizedProgramAndBadInputAreRefused(t *testing.T) {
	s, launched := testService(&protocol.Health{Backend: "gvisor", Ready: true})
	small := protocol.Limits{ProgramBytes: 10}
	_, answer := exchange(t, s, protocol.Message{Type: protocol.TypeStart, Source: strings.Repeat("x", 11), Limits: &small})
	if answer.Type != protocol.TypeFailed || answer.Failure.Kind != protocol.KindLimit || !strings.Contains(answer.Failure.Message, "10 bytes") {
		t.Errorf("oversized program: %+v", answer.Failure)
	}
	// Input that is not JSON never reaches a sandbox.
	client, server := net.Pipe()
	go s.Handle(server)
	r := protocol.NewReader(client, 1<<20)
	var hello protocol.Message
	r.Read(&hello)
	client.Write([]byte(`{"type":"start","source":"return 1;","input":{"unclosed":}` + "\n"))
	if err := r.Read(&answer); err != nil || answer.Type != protocol.TypeFailed {
		t.Errorf("invalid input: %v %+v", err, answer)
	}
	client.Close()
	if *launched != 0 {
		t.Error("a refused run requested a sandbox")
	}
}

func TestHealthQuery(t *testing.T) {
	s, _ := testService(&protocol.Health{Backend: "runc", Ready: true, Active: 2})
	_, answer := exchange(t, s, protocol.Message{Type: protocol.TypeHealth})
	if answer.Type != protocol.TypeHealth || answer.Health.Backend != "runc" || answer.Health.Active != 2 {
		t.Errorf("got %+v", answer)
	}
}
