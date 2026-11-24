// Command sandbox-worker runs inside a sandbox. Started without arguments it
// reads one start message from standard input, runs the program, exchanges
// tool calls over standard input and output, and writes the final message.
// "selftest PATH DIR" reports whether the sandbox isolates the network and
// processes, hides PATH and keeps DIR read-only; "precompile DIR" prepares the engine cache at build
// time.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
	"github.com/chrisbennight/tyk-plus-plugins/sandbox/worker"
)

// cacheDir holds the engine compiled when the image was built.
const cacheDir = "/cache"

// replies reads the host's replies on one goroutine, so a reply is never lost
// when the worker stops waiting for one early.
type replies struct{ ch chan read }

type read struct {
	m   protocol.Message
	err error
}

// newReplies buffers up to capacity replies, one per allowed tool call, so the
// worker keeps reading replies while it is still sending calls.
func newReplies(r *protocol.Reader, capacity int) replies {
	ch := make(chan read, capacity)
	go func() {
		for {
			var m protocol.Message
			err := r.Read(&m)
			ch <- read{m, err}
			if err != nil {
				return
			}
		}
	}()
	return replies{ch}
}

func (r replies) Next(ctx context.Context) (protocol.Message, error) {
	select {
	case got := <-r.ch:
		return got.m, got.err
	case <-ctx.Done():
		return protocol.Message{}, ctx.Err()
	}
}

func main() {
	if len(os.Args) == 4 && os.Args[1] == "selftest" {
		json.NewEncoder(os.Stdout).Encode(worker.SelfTest(os.Args[2], os.Args[3]))
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "precompile" {
		rt, err := worker.NewRuntime(os.Args[2])
		if err == nil {
			err = rt.Precompile(context.Background())
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "precompile:", err)
			os.Exit(1)
		}
		return
	}
	in := protocol.NewReader(os.Stdin, 64<<20)
	var start protocol.Message
	if err := in.Read(&start); err != nil || start.Type != protocol.TypeStart || start.Limits == nil {
		protocol.Write(os.Stdout, protocol.Failed(protocol.KindProtocol, "the first message must be a start message"))
		os.Exit(1)
	}
	in.SetMax(start.Limits.MaxLine())
	rt, err := worker.NewRuntime(cacheDir)
	if err != nil {
		// A missing or unreadable cache only costs compile time.
		rt, _ = worker.NewRuntime("")
	}
	final := rt.Run(context.Background(), start, func(m protocol.Message) error { return protocol.Write(os.Stdout, m) }, newReplies(in, start.Limits.Calls+1))
	protocol.Write(os.Stdout, final)
}
