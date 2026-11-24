// Package launcher is the sandbox host's only privileged component. It starts
// one sandbox per run from a fixed worker image, hands the run's input and
// output pipes to the sandbox service, and destroys the sandbox when the run
// ends. It accepts only typed requests from the sandbox service's user and
// builds every runtime command from fixed values and checked numbers.
package launcher

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// Fixed locations inside the launcher's container.
const (
	// RootFS holds the worker image every sandbox runs read-only.
	RootFS = "/opt/sandbox/rootfs"
	// stateDir is a tmpfs holding per-run bundles and runtime state.
	stateDir = "/run/sandbox"
	// canary is a file the self-test sandbox must not be able to read.
	canary = stateDir + "/canary"
	// grace covers starting the sandbox and lets the sandbox service report a
	// run's time limit before the launcher destroys the sandbox itself.
	grace = 15 * time.Second
	// sandboxUser is the unprivileged user programs run as.
	sandboxUser = 65534
	// cleanupWait bounds killing and deleting one sandbox.
	cleanupWait = 30 * time.Second
)

// Config is the launcher's operator configuration.
type Config struct {
	Backend      string
	ServiceUID   uint32
	MaxRunMillis int64
	// MemoryBytes is the memory limit for each sandbox where the runtime
	// enforces one; the gVisor backend runs without per-sandbox cgroups.
	MemoryBytes int64
	// MaxRuns bounds the sandboxes the launcher runs at once, whatever the
	// sandbox service asks for.
	MaxRuns int
	Socket  string
}

// Request is the only message the launcher accepts.
type Request struct {
	Op        string `json:"op"`
	RunMillis int64  `json:"run_ms,omitempty"`
}

// Request operations.
const (
	OpStart  = "start"
	OpHealth = "health"
)

// Reply answers a request. A started run's pipes travel with the reply.
type Reply struct {
	Run    string           `json:"run,omitempty"`
	Error  string           `json:"error,omitempty"`
	Health *protocol.Health `json:"health,omitempty"`
}

// Validate checks a request against the operator's maximum run time.
func (r Request) Validate(maxRunMillis int64) error {
	switch r.Op {
	case OpHealth:
		if r.RunMillis != 0 {
			return errors.New("health takes no run time")
		}
	case OpStart:
		if r.RunMillis <= 0 || r.RunMillis > maxRunMillis {
			return fmt.Errorf("run time must be between 1 and %d ms", maxRunMillis)
		}
	default:
		return fmt.Errorf("unknown operation %q", r.Op)
	}
	return nil
}

// DecodeRequest parses one request, rejecting unknown fields.
func DecodeRequest(line []byte) (Request, error) {
	var r Request
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return Request{}, err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return Request{}, errors.New("trailing data after request")
	}
	return r, nil
}

// RuntimeCommand returns the runtime binary and arguments that run bundle id.
// Only fixed values and the generated id appear in it.
func RuntimeCommand(backend, op, id string) (string, []string) {
	if backend == protocol.BackendGVisor {
		// Without --privileged, Docker's cgroup files are read-only, so gVisor
		// runs without per-sandbox cgroups; the container's own limits apply.
		args := []string{"--root=" + stateDir + "/runsc", "--network=none", "--platform=systrap", "--ignore-cgroups"}
		switch op {
		case "run":
			return "runsc", append(args, "run", "--bundle", bundleDir(id), id)
		case "kill":
			return "runsc", append(args, "kill", id, "KILL")
		case "delete":
			return "runsc", append(args, "delete", "--force", id)
		default:
			return "runsc", append(args, "list", "-quiet")
		}
	}
	args := []string{"--root=" + stateDir + "/runc"}
	switch op {
	case "run":
		return "runc", append(args, "run", "--bundle", bundleDir(id), id)
	case "kill":
		return "runc", append(args, "kill", id, "KILL")
	case "delete":
		return "runc", append(args, "delete", "--force", id)
	default:
		return "runc", append(args, "list", "-q")
	}
}

func bundleDir(id string) string { return filepath.Join(stateDir, "bundles", id) }

// Spec is the container definition for one sandbox: the worker image
// read-only, an unprivileged user without capabilities, no network, its own
// process, IPC, host-name and mount namespaces, and resource limits.
func Spec(args []string, memoryBytes int64) map[string]any {
	none := []string{}
	return map[string]any{
		"ociVersion": "1.0.2",
		"process": map[string]any{
			"terminal": false,
			"user":     map[string]any{"uid": sandboxUser, "gid": sandboxUser},
			"args":     args,
			"env":      []string{},
			"cwd":      "/",
			"capabilities": map[string]any{
				"bounding": none, "effective": none, "permitted": none, "inheritable": none, "ambient": none,
			},
			"noNewPrivileges": true,
			"rlimits":         []map[string]any{{"type": "RLIMIT_NOFILE", "hard": 64, "soft": 64}},
		},
		"root":     map[string]any{"path": RootFS, "readonly": true},
		"hostname": "sandbox",
		"mounts": []map[string]any{
			{"destination": "/proc", "type": "proc", "source": "proc", "options": []string{"nosuid", "noexec", "nodev"}},
			{"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "noexec", "mode=755", "size=64k"}},
		},
		"linux": map[string]any{
			"namespaces": []map[string]any{{"type": "pid"}, {"type": "network"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}},
			"resources":  map[string]any{"memory": map[string]any{"limit": memoryBytes}, "pids": map[string]any{"limit": 64}},
		},
	}
}

// Launcher serves typed requests on a Unix socket.
type Launcher struct {
	config   Config
	mu       sync.Mutex
	active   map[string]bool
	selfTest map[string]string
	problem  string
}

// New prepares the state directory and runs the startup self-test. A failed
// self-test leaves the launcher refusing every run.
func New(ctx context.Context, config Config) *Launcher {
	l := &Launcher{config: config, active: map[string]bool{}}
	if err := os.MkdirAll(filepath.Join(stateDir, "bundles"), 0o700); err != nil {
		l.problem = "preparing the state directory: " + err.Error()
		return l
	}
	if config.Backend == protocol.BackendRunc {
		if err := delegateCgroups(); err != nil {
			l.problem = "delegating cgroups: " + err.Error()
			return l
		}
	}
	l.selfTest, l.problem = l.runSelfTest(ctx)
	if l.problem != "" {
		slog.Error("Sandbox self-test failed; refusing every run", "problem", l.problem, "results", l.selfTest)
	} else {
		slog.Info("Sandbox self-test passed", "backend", config.Backend, "results", l.selfTest)
	}
	return l
}

// SelfTestProblem explains which isolation checks a self-test failed, or
// returns "" when every check was blocked.
func SelfTestProblem(results map[string]string) string {
	var allowed []string
	for _, check := range protocol.SelfTestChecks {
		if outcome, ok := results[check]; !ok {
			allowed = append(allowed, check+" (not reported)")
		} else if outcome != "blocked" {
			allowed = append(allowed, check)
		}
	}
	if len(allowed) > 0 {
		return "the self-test sandbox was not isolated: " + strings.Join(allowed, ", ")
	}
	return ""
}

func (l *Launcher) runSelfTest(ctx context.Context) (map[string]string, string) {
	// Readable by everyone, so only its absence from the sandbox blocks it.
	if err := os.WriteFile(canary, []byte("must not be visible from a sandbox"), 0o644); err != nil {
		return nil, "writing the canary file: " + err.Error()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	id := newID()
	cmd, err := l.prepare(id, []string{"/worker", "selftest", canary, "/scratch"})
	if err != nil {
		return nil, err.Error()
	}
	defer l.destroy(id)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Start(); err != nil {
		return nil, "starting the self-test sandbox: " + err.Error()
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		return nil, "the self-test sandbox did not finish"
	}
	if err != nil {
		return nil, fmt.Sprintf("the self-test sandbox failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	var results map[string]string
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		return nil, "reading the self-test results: " + err.Error()
	}
	return results, SelfTestProblem(results)
}

// prepare writes the bundle for run id and returns the runtime command.
func (l *Launcher) prepare(id string, args []string) (*exec.Cmd, error) {
	dir := bundleDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	spec, _ := json.Marshal(Spec(args, l.config.MemoryBytes))
	if err := os.WriteFile(filepath.Join(dir, "config.json"), spec, 0o600); err != nil {
		return nil, err
	}
	name, argv := RuntimeCommand(l.config.Backend, "run", id)
	return exec.Command(name, argv...), nil
}

// destroy kills and deletes run id's sandbox and removes its bundle, and
// reports whether the sandbox is gone. Killing an already stopped sandbox fails
// harmlessly. A sandbox that could not be deleted keeps its bundle, is logged,
// and still shows in the health report's container count.
func (l *Launcher) destroy(id string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupWait)
	defer cancel()
	name, argv := RuntimeCommand(l.config.Backend, "kill", id)
	_ = exec.CommandContext(ctx, name, argv...).Run()
	name, argv = RuntimeCommand(l.config.Backend, "delete", id)
	if out, err := exec.CommandContext(ctx, name, argv...).CombinedOutput(); err != nil && l.listed(id) {
		slog.Error("Deleting a sandbox failed; its slot stays in use", "run", id, "error", err, "output", strings.TrimSpace(string(out)))
		return false
	}
	if err := os.RemoveAll(bundleDir(id)); err != nil {
		slog.Warn("Removing a sandbox bundle failed", "run", id, "error", err)
	}
	return true
}

// listed reports whether the runtime still lists run id, or cannot say.
func (l *Launcher) listed(id string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupWait)
	defer cancel()
	name, argv := RuntimeCommand(l.config.Backend, "list", "")
	out, err := exec.CommandContext(ctx, name, argv...).Output()
	if err != nil {
		return true
	}
	for _, listed := range strings.Fields(string(out)) {
		if listed == id {
			return true
		}
	}
	return false
}

// containers counts the containers the runtime reports.
func (l *Launcher) containers() int {
	name, argv := RuntimeCommand(l.config.Backend, "list", "")
	out, err := exec.Command(name, argv...).Output()
	if err != nil {
		return -1
	}
	return len(strings.Fields(string(out)))
}

func (l *Launcher) health() *protocol.Health {
	l.mu.Lock()
	active := len(l.active)
	l.mu.Unlock()
	return &protocol.Health{Backend: l.config.Backend, Ready: l.problem == "", Problem: l.problem,
		SelfTest: l.selfTest, Active: active, Containers: l.containers()}
}

// Serve accepts connections until ln closes.
func (l *Launcher) Serve(ln *net.UnixListener) error {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go l.handle(c)
	}
}

func (l *Launcher) handle(c *net.UnixConn) {
	defer c.Close()
	reply := func(r Reply) { data, _ := json.Marshal(r); c.Write(append(data, '\n')) }
	uid, err := peerUID(c)
	if err != nil || uid != l.config.ServiceUID {
		slog.Warn("Refused a launcher connection", "uid", uid, "error", err)
		reply(Reply{Error: "refused: not the sandbox service"})
		return
	}
	line, err := bufio.NewReader(io.LimitReader(c, 4096)).ReadBytes('\n')
	if err != nil {
		reply(Reply{Error: "refused: unreadable request"})
		return
	}
	req, err := DecodeRequest(line)
	if err == nil {
		err = req.Validate(l.config.MaxRunMillis)
	}
	if err != nil {
		reply(Reply{Error: "refused: " + err.Error()})
		return
	}
	if req.Op == OpHealth {
		reply(Reply{Health: l.health()})
		return
	}
	if l.problem != "" {
		reply(Reply{Error: "unavailable: " + l.problem})
		return
	}
	l.start(c, time.Duration(req.RunMillis)*time.Millisecond)
}

// start runs one sandbox for the connection's lifetime.
func (l *Launcher) start(c *net.UnixConn, limit time.Duration) {
	id := newID()
	l.mu.Lock()
	if len(l.active) >= l.config.MaxRuns {
		l.mu.Unlock()
		data, _ := json.Marshal(Reply{Error: fmt.Sprintf("unavailable: already running %d sandboxes", l.config.MaxRuns)})
		c.Write(append(data, '\n'))
		return
	}
	// Reserve the slot before starting, so concurrent requests cannot exceed
	// it. The slot is released only once the sandbox is confirmed gone.
	l.active[id] = true
	l.mu.Unlock()
	defer func() {
		if l.destroy(id) {
			l.mu.Lock()
			delete(l.active, id)
			l.mu.Unlock()
		}
	}()
	cmd, err := l.prepare(id, []string{"/worker"})
	if err != nil {
		data, _ := json.Marshal(Reply{Error: "unavailable: " + err.Error()})
		c.Write(append(data, '\n'))
		return
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return
	}
	var stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, &stderr
	if err := cmd.Start(); err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		data, _ := json.Marshal(Reply{Error: "unavailable: starting the sandbox: " + err.Error()})
		c.Write(append(data, '\n'))
		return
	}
	inR.Close()
	outW.Close()
	data, _ := json.Marshal(Reply{Run: id})
	_, _, err = c.WriteMsgUnix(append(data, '\n'), syscall.UnixRights(int(inW.Fd()), int(outR.Fd())), nil)
	inW.Close()
	outR.Close()
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	closed := make(chan struct{})
	go func() { io.Copy(io.Discard, c); close(closed) }()
	timer := time.NewTimer(limit + grace)
	defer timer.Stop()
	reason := "finished"
	select {
	case err := <-exited:
		if err != nil {
			reason = "exited: " + err.Error()
		}
	case <-timer.C:
		reason = "time limit"
	case <-closed:
		reason = "connection closed"
	}
	slog.Info("Sandbox ended", "run", id, "reason", reason)
}

func newID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "run-" + hex.EncodeToString(b)
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}

// delegateCgroups moves the launcher out of its container's root cgroup so
// the root can delegate memory, CPU and process controllers to sandboxes.
func delegateCgroups() error {
	if err := os.MkdirAll("/sys/fs/cgroup/launcher", 0o755); err != nil {
		return err
	}
	procs, err := os.ReadFile("/sys/fs/cgroup/cgroup.procs")
	if err != nil {
		return err
	}
	for _, pid := range strings.Fields(string(procs)) {
		// A process may exit between reading and moving it.
		_ = os.WriteFile("/sys/fs/cgroup/launcher/cgroup.procs", []byte(pid), 0o644)
	}
	return os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0o644)
}
