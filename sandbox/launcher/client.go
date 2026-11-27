package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// Run is a started sandbox. Closing Conn tells the launcher to destroy it.
type Run struct {
	ID string
	// Backend is the runtime that started this sandbox.
	Backend string
	Conn    *net.UnixConn
	Stdin   *os.File
	Stdout  *os.File
}

// Close ends the run.
func (r *Run) Close() {
	r.Stdin.Close()
	r.Stdout.Close()
	r.Conn.Close()
}

// startWait bounds how long the launcher may take to start a sandbox.
const startWait = 30 * time.Second

// Unavailable reports that the launcher could not start a sandbox.
type Unavailable struct{ Reason string }

func (u Unavailable) Error() string { return u.Reason }

// Busy reports that the launcher is running as many sandboxes as it allows.
type Busy struct{ Reason string }

func (b Busy) Error() string { return b.Reason }

// Start asks the launcher at socket for a sandbox that may run for runMillis,
// giving up when ctx ends or the launcher does not answer in time.
func Start(ctx context.Context, socket string, runMillis int64) (*Run, error) {
	c, err := dial(socket)
	if err != nil {
		return nil, Unavailable{"the launcher is unreachable: " + err.Error()}
	}
	// Starting a sandbox must answer promptly; the connection then stays open
	// without a deadline for the run's lifetime.
	deadline := time.Now().Add(startWait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	if err := send(c, Request{Op: OpStart, RunMillis: runMillis}); err != nil {
		c.Close()
		return nil, err
	}
	buf := make([]byte, 4096)
	oob := make([]byte, syscall.CmsgSpace(2*4))
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		c.Close()
		return nil, Unavailable{"reading the launcher's reply: " + err.Error()}
	}
	var reply Reply
	if err := json.Unmarshal(buf[:n], &reply); err != nil || reply.Error != "" || reply.Run == "" {
		c.Close()
		if strings.HasPrefix(reply.Error, "busy:") {
			return nil, Busy{reply.Error}
		}
		if reply.Error != "" {
			return nil, Unavailable{reply.Error}
		}
		return nil, Unavailable{"the launcher sent an unreadable reply"}
	}
	c.SetDeadline(time.Time{})
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		c.Close()
		return nil, errors.New("the launcher sent no pipes")
	}
	fds, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 2 {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		c.Close()
		return nil, errors.New("the launcher sent the wrong pipes")
	}
	return &Run{ID: reply.Run, Backend: reply.Backend, Conn: c, Stdin: os.NewFile(uintptr(fds[0]), "sandbox-stdin"), Stdout: os.NewFile(uintptr(fds[1]), "sandbox-stdout")}, nil
}

// QueryHealth asks the launcher at socket for its health, waiting at most
// wait for the answer.
func QueryHealth(socket string, wait time.Duration) (*protocol.Health, error) {
	c, err := dial(socket)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(wait))
	if err := send(c, Request{Op: OpHealth}); err != nil {
		return nil, err
	}
	var reply Reply
	if err := json.NewDecoder(c).Decode(&reply); err != nil {
		return nil, err
	}
	if reply.Health == nil {
		return nil, fmt.Errorf("%s", strings.TrimSpace(reply.Error))
	}
	return reply.Health, nil
}

// Healthcheck returns nil when the launcher at socket answers within wait
// and can start sandboxes, and otherwise says why not. It is for container
// health checks; the images have no shell.
func Healthcheck(socket string, wait time.Duration) error {
	h, err := QueryHealth(socket, wait)
	if err != nil {
		return fmt.Errorf("the launcher did not answer: %w", err)
	}
	if !h.Ready {
		return fmt.Errorf("the launcher refuses every run: %s", h.Problem)
	}
	return nil
}

func dial(socket string) (*net.UnixConn, error) {
	c, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}
	return c.(*net.UnixConn), nil
}

func send(c *net.UnixConn, r Request) error {
	data, _ := json.Marshal(r)
	_, err := c.Write(append(data, '\n'))
	return err
}
