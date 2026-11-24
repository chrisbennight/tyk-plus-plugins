// Package service is the network-facing, unprivileged half of the sandbox
// host. Each mutual-TLS connection from a gateway is one run: the service asks
// the launcher for a fresh sandbox, passes the program in, and relays tool
// calls and their replies, checking every message against the protocol and the
// run's limits.
package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/launcher"
	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// Config is the sandbox service's operator configuration.
type Config struct {
	Listen         string
	CertFile       string
	KeyFile        string
	ClientCAFile   string
	LauncherSocket string
	// Capacity bounds the runs this host takes at once.
	Capacity int
	// Max is the highest limit a run may have; callers can only lower them.
	Max protocol.Limits
}

// startAllowance covers starting a sandbox and its engine, which does not
// count against a run's own time.
const startAllowance = 10 * time.Second

// firstMessageWait bounds how long a gateway may take to send its first
// message after connecting.
const firstMessageWait = 30 * time.Second

// TLSConfig requires TLS 1.3 and a client certificate signed by the
// configured authority.
func TLSConfig(cfg Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading the server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("reading the client authority: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the client authority file holds no certificate")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13}, nil
}

// Service handles runs.
type Service struct {
	config Config
	active atomic.Int64
	// launch starts a sandbox; tests replace it.
	launch func(runMillis int64) (*launcher.Run, error)
	health func() (*protocol.Health, error)

	// cached is the launcher's last health report, reused briefly so that
	// starting a run does not ask the runtime to list its containers.
	mu       sync.Mutex
	cached   *protocol.Health
	cachedAt time.Time
}

// healthCacheTime bounds how stale a reused health report may be.
const healthCacheTime = 5 * time.Second

// launcherHealth returns the launcher's health, fresh when asked for or when
// the cached report is old or not ready.
func (s *Service) launcherHealth(fresh bool) (*protocol.Health, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !fresh && s.cached != nil && s.cached.Ready && time.Since(s.cachedAt) < healthCacheTime {
		return s.cached, nil
	}
	h, err := s.health()
	if err != nil {
		return nil, err
	}
	s.cached, s.cachedAt = h, time.Now()
	return h, nil
}

// New returns a service that uses the launcher at cfg.LauncherSocket.
func New(cfg Config) *Service {
	return &Service{config: cfg,
		launch: func(ms int64) (*launcher.Run, error) { return launcher.Start(cfg.LauncherSocket, ms) },
		health: func() (*protocol.Health, error) { return launcher.QueryHealth(cfg.LauncherSocket) },
	}
}

// Serve accepts connections until ln closes.
func (s *Service) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.Handle(c)
	}
}

// lockedWriter lets several goroutines write whole messages to one peer.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) write(m protocol.Message) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return protocol.Write(l.w, m)
}

// Handle serves one connection, which is one run or one health query.
func (s *Service) Handle(c net.Conn) {
	defer c.Close()
	client := &lockedWriter{w: c}
	if t, ok := c.(*tls.Conn); ok {
		c.SetDeadline(time.Now().Add(firstMessageWait))
		if err := t.Handshake(); err != nil {
			slog.Warn("Refused a connection", "remote", c.RemoteAddr().String(), "error", err)
			return
		}
	}
	h, err := s.launcherHealth(false)
	if err != nil {
		client.write(protocol.Failed(protocol.KindUnavailable, "the launcher is unreachable: %v", err))
		return
	}
	if err := client.write(protocol.Message{Type: protocol.TypeHello, Backend: h.Backend}); err != nil {
		return
	}
	c.SetDeadline(time.Now().Add(firstMessageWait))
	reader := protocol.NewReader(c, s.config.Max.MaxLine())
	var first protocol.Message
	if err := reader.Read(&first); err != nil {
		client.write(protocol.Failed(protocol.KindProtocol, "unreadable first message: %v", err))
		return
	}
	c.SetDeadline(time.Time{})
	switch first.Type {
	case protocol.TypeHealth:
		if h, err = s.launcherHealth(true); err != nil {
			client.write(protocol.Failed(protocol.KindUnavailable, "the launcher is unreachable: %v", err))
			return
		}
		client.write(protocol.Message{Type: protocol.TypeHealth, Health: h})
		return
	case protocol.TypeStart:
	default:
		client.write(protocol.Failed(protocol.KindProtocol, "the first message must be start or health"))
		return
	}
	requested := protocol.Limits{}
	if first.Limits != nil {
		requested = *first.Limits
	}
	limits := requested.Within(s.config.Max)
	if len(first.Source) > limits.ProgramBytes {
		client.write(protocol.Failed(protocol.KindLimit, "the program exceeds %d bytes", limits.ProgramBytes))
		return
	}
	if len(first.Input) > limits.ValueBytes || (len(first.Input) > 0 && !json.Valid(first.Input)) {
		client.write(protocol.Failed(protocol.KindLimit, "the input must be JSON of at most %d bytes", limits.ValueBytes))
		return
	}
	if !h.Ready {
		client.write(protocol.Failed(protocol.KindUnavailable, "the sandbox host is not ready: %s", h.Problem))
		return
	}
	if n := s.active.Add(1); n > int64(s.config.Capacity) {
		s.active.Add(-1)
		client.write(protocol.Failed(protocol.KindBusy, "the sandbox host is running %d runs, its capacity", s.config.Capacity))
		return
	}
	defer s.active.Add(-1)
	final := s.run(c, reader, client, protocol.Message{Type: protocol.TypeStart, Source: first.Source, Input: first.Input, Limits: &limits})
	client.write(final)
}

// run relays one run between the gateway and its sandbox and returns the
// message that ends it.
func (s *Service) run(c net.Conn, fromClient *protocol.Reader, client *lockedWriter, start protocol.Message) protocol.Message {
	limits := *start.Limits
	run, err := s.launch(limits.RunMillis)
	if err != nil {
		return protocol.Failed(protocol.KindUnavailable, "no sandbox: %v", err)
	}
	defer run.Close()
	worker := &lockedWriter{w: run.Stdin}
	if err := worker.write(start); err != nil {
		return protocol.Failed(protocol.KindUnavailable, "starting the program: %v", err)
	}

	// The worker enforces the run time from when its engine is ready; this is
	// a backstop in case the sandbox stops responding.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(limits.RunMillis)*time.Millisecond+startAllowance)
	defer cancel()
	end := make(chan protocol.Message, 2)
	finish := func(m protocol.Message) {
		select {
		case end <- m:
		default:
		}
	}
	var mu sync.Mutex
	outstanding := map[int64]bool{}
	calls := 0

	go func() {
		r := protocol.NewReader(run.Stdout, limits.MaxLine())
		for {
			var m protocol.Message
			if err := r.Read(&m); err != nil {
				finish(protocol.Failed(protocol.KindException, "the sandbox ended without a result: %v", err))
				return
			}
			switch m.Type {
			case protocol.TypeCall:
				if problem := checkCall(m, limits); problem != "" {
					finish(protocol.Failed(protocol.KindProtocol, "%s", problem))
					return
				}
				mu.Lock()
				calls++
				dup := outstanding[m.ID]
				outstanding[m.ID] = true
				over := calls > limits.Calls
				mu.Unlock()
				if over {
					finish(protocol.Failed(protocol.KindLimit, "the run made more than %d tool calls", limits.Calls))
					return
				}
				if dup {
					finish(protocol.Failed(protocol.KindProtocol, "the program reused tool call %d", m.ID))
					return
				}
				if err := client.write(protocol.Message{Type: protocol.TypeCall, ID: m.ID, Proxy: m.Proxy, Tool: m.Tool, Arguments: m.Arguments}); err != nil {
					finish(protocol.Failed(protocol.KindProtocol, "the gateway connection failed: %v", err))
					return
				}
			case protocol.TypeDone:
				if len(m.Result) > limits.ValueBytes || !json.Valid(m.Result) {
					finish(protocol.Failed(protocol.KindLimit, "the result must be JSON of at most %d bytes", limits.ValueBytes))
					return
				}
				finish(protocol.Message{Type: protocol.TypeDone, Result: m.Result, Console: m.Console})
				return
			case protocol.TypeFailed:
				if m.Failure == nil {
					m = protocol.Failed(protocol.KindException, "the program failed")
				}
				finish(protocol.Message{Type: protocol.TypeFailed, Failure: m.Failure})
				return
			default:
				finish(protocol.Failed(protocol.KindProtocol, "the sandbox sent a %q message", m.Type))
				return
			}
		}
	}()

	go func() {
		for {
			var m protocol.Message
			if err := fromClient.Read(&m); err != nil {
				finish(protocol.Failed(protocol.KindProtocol, "the gateway connection ended: %v", err))
				return
			}
			if m.Type != protocol.TypeResult && m.Type != protocol.TypeError {
				finish(protocol.Failed(protocol.KindProtocol, "the gateway sent a %q message during a run", m.Type))
				return
			}
			mu.Lock()
			known := outstanding[m.ID]
			delete(outstanding, m.ID)
			mu.Unlock()
			if !known {
				finish(protocol.Failed(protocol.KindProtocol, "the gateway answered unknown tool call %d", m.ID))
				return
			}
			reply := protocol.Message{Type: m.Type, ID: m.ID}
			if m.Type == protocol.TypeResult {
				if len(m.Result) > limits.ValueBytes || !json.Valid(m.Result) {
					finish(protocol.Failed(protocol.KindLimit, "tool call %d returned more than %d bytes", m.ID, limits.ValueBytes))
					return
				}
				reply.Result = m.Result
			} else {
				if m.Error == nil {
					finish(protocol.Failed(protocol.KindProtocol, "an error reply has no error"))
					return
				}
				reply.Error = m.Error
			}
			if err := worker.write(reply); err != nil {
				finish(protocol.Failed(protocol.KindException, "the sandbox stopped: %v", err))
				return
			}
		}
	}()

	select {
	case m := <-end:
		return m
	case <-ctx.Done():
		return protocol.Failed(protocol.KindLimit, "the run exceeded its run time")
	}
}

func checkCall(m protocol.Message, limits protocol.Limits) string {
	switch {
	case m.ID <= 0:
		return "a tool call has no identifier"
	case m.Proxy == "" || m.Tool == "" || len(m.Proxy) > 256 || len(m.Tool) > 256:
		return "a tool call has no valid proxy or tool name"
	case len(m.Arguments) > limits.ValueBytes:
		return fmt.Sprintf("tool call arguments exceed %d bytes", limits.ValueBytes)
	case len(m.Arguments) > 0 && !json.Valid(m.Arguments):
		return "tool call arguments are not JSON"
	}
	return ""
}
