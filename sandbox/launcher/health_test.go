package launcher

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// fakeLauncher answers each connection's health request with reply, or
// never answers when reply is nil.
func fakeLauncher(t *testing.T, reply *Reply) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "launcher.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadBytes('\n')
				if err != nil {
					return
				}
				if req, err := DecodeRequest(line); err != nil || req.Op != OpHealth {
					return
				}
				if reply == nil {
					// Silent until the client gives up and closes.
					io.Copy(io.Discard, c)
					return
				}
				data, _ := json.Marshal(reply)
				c.Write(append(data, '\n'))
			}()
		}
	}()
	return socket
}

func TestHealthcheck(t *testing.T) {
	ready := &Reply{Health: &protocol.Health{Backend: protocol.BackendGVisor, Ready: true}}
	failed := &Reply{Health: &protocol.Health{Backend: protocol.BackendGVisor, Problem: "the self-test sandbox was not isolated: network"}}
	// The runtime's output can carry newlines into the problem.
	multiline := &Reply{Health: &protocol.Health{Backend: protocol.BackendGVisor, Problem: "the self-test sandbox failed: exit status 1:\nline one\n  line two"}}
	refused := &Reply{Error: "refused: not the sandbox service"}
	cases := []struct {
		name   string
		socket string
		want   string // empty when healthy
	}{
		{"ready", fakeLauncher(t, ready), ""},
		{"failed self-test", fakeLauncher(t, failed), "not isolated: network"},
		{"multi-line problem", fakeLauncher(t, multiline), "exit status 1: line one line two"},
		{"refused", fakeLauncher(t, refused), "not the sandbox service"},
		{"no launcher", filepath.Join(t.TempDir(), "missing.sock"), "did not answer"},
		{"silent launcher", fakeLauncher(t, nil), "did not answer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			err := Healthcheck(c.socket, 500*time.Millisecond)
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("the check took %v", elapsed)
			}
			if c.want == "" {
				if err != nil {
					t.Fatalf("want healthy, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error containing %q, got %v", c.want, err)
			}
		})
	}
}
