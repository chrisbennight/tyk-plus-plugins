package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/launcher"
	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

const serviceUID = 12345

// TestHealthcheckChild runs the health check in a child process, since
// switching user changes the whole process.
func TestHealthcheckChild(t *testing.T) {
	if os.Getenv("HEALTHCHECK_CHILD") != "1" {
		t.Skip("run by TestHealthcheckConnectsAsTheServiceUser")
	}
	if err := healthcheck(); err != nil {
		t.Fatal(err)
	}
}

// TestHealthcheckConnectsAsTheServiceUser starts the check as root, as a
// container health check does, and shows the launcher's socket sees the
// service's user, so the launcher can keep refusing every other user.
func TestHealthcheckConnectsAsTheServiceUser(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("switching user needs root")
	}
	// A directory the service's user can reach, as the shared socket volume is.
	dir, err := os.MkdirTemp("", "launcher-health")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "launcher.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(socket, 0o666); err != nil {
		t.Fatal(err)
	}
	peers := make(chan *syscall.Ucred, 1)
	go func() {
		c, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		defer c.Close()
		raw, _ := c.SyscallConn()
		var cred *syscall.Ucred
		raw.Control(func(fd uintptr) { cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) })
		peers <- cred
		reply := launcher.Reply{Error: "refused: not the sandbox service"}
		if cred != nil && cred.Uid == serviceUID {
			reply = launcher.Reply{Health: &protocol.Health{Backend: protocol.BackendGVisor, Ready: true}}
		}
		bufio.NewReader(c).ReadBytes('\n')
		data, _ := json.Marshal(reply)
		c.Write(append(data, '\n'))
	}()

	cmd := exec.Command(os.Args[0], "-test.run=^TestHealthcheckChild$", "-test.v")
	cmd.Env = append(os.Environ(), "HEALTHCHECK_CHILD=1", "SANDBOX_LAUNCHER_SOCKET="+socket, "SANDBOX_SERVICE_UID=12345")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the health check failed: %v\n%s", err, out)
	}
	cred := <-peers
	if cred == nil || cred.Uid != serviceUID || cred.Gid != serviceUID {
		t.Fatalf("the launcher saw %+v, want user and group %d", cred, serviceUID)
	}
}

func TestBecomeUserKeepsTheCurrentUser(t *testing.T) {
	if err := becomeUser(uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
}
