// Command sandbox-launcher is the sandbox host's root helper. It listens on a
// Unix socket that only the sandbox service's user may use and starts one
// sandbox per run.
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/launcher"
	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

func main() {
	config := launcher.Config{
		Backend:      env("SANDBOX_BACKEND", protocol.BackendGVisor),
		Socket:       env("SANDBOX_LAUNCHER_SOCKET", "/run/sandbox-launcher/launcher.sock"),
		ServiceUID:   uint32(number("SANDBOX_SERVICE_UID", 10001)),
		MaxRunMillis: number("SANDBOX_MAX_RUN_MS", 120_000),
		MemoryBytes:  number("SANDBOX_MEMORY_BYTES", 512<<20),
		MaxRuns:      int(number("SANDBOX_MAX_RUNS", 16)),
	}
	switch {
	case config.Backend == protocol.BackendRunc && !launcher.RuncBuilt:
		slog.Error("SANDBOX_BACKEND is runc, but this launcher was built without it; runc is only in development builds", "value", config.Backend)
		os.Exit(1)
	case config.Backend != protocol.BackendGVisor && config.Backend != protocol.BackendRunc:
		slog.Error("SANDBOX_BACKEND must be gvisor, or runc in a development build", "value", config.Backend)
		os.Exit(1)
	}
	l := launcher.New(context.Background(), config)
	os.Remove(config.Socket)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.Socket, Net: "unix"})
	if err != nil {
		slog.Error("Listening", "error", err)
		os.Exit(1)
	}
	// Any local user may connect; the launcher checks each peer's user itself.
	if err := os.Chmod(config.Socket, 0o666); err != nil {
		slog.Error("Opening the socket", "error", err)
		os.Exit(1)
	}
	slog.Info("Sandbox launcher listening", "socket", config.Socket, "backend", config.Backend)
	slog.Error("Stopped", "error", l.Serve(ln))
	os.Exit(1)
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func number(name string, fallback int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		slog.Error("Invalid setting", "name", name, "value", v)
		os.Exit(1)
	}
	return n
}
