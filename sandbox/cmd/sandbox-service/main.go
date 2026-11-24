// Command sandbox-service accepts Code Mode runs from gateways over mutual TLS
// and runs each one in a fresh sandbox from the launcher.
package main

import (
	"crypto/tls"
	"log/slog"
	"os"
	"strconv"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
	"github.com/chrisbennight/tyk-plus-plugins/sandbox/service"
)

func main() {
	d := protocol.DefaultLimits
	config := service.Config{
		Listen:         env("SANDBOX_LISTEN", ":8443"),
		CertFile:       env("SANDBOX_TLS_CERT", "/etc/sandbox/tls/server.pem"),
		KeyFile:        env("SANDBOX_TLS_KEY", "/etc/sandbox/tls/server-key.pem"),
		ClientCAFile:   env("SANDBOX_CLIENT_CA", "/etc/sandbox/tls/client-ca.pem"),
		LauncherSocket: env("SANDBOX_LAUNCHER_SOCKET", "/run/sandbox-launcher/launcher.sock"),
		Capacity:       int(number("SANDBOX_CAPACITY", 8)),
		Max: protocol.Limits{
			RunMillis:    number("SANDBOX_MAX_RUN_MS", d.RunMillis),
			MemoryBytes:  number("SANDBOX_MAX_MEMORY_BYTES", d.MemoryBytes),
			Calls:        int(number("SANDBOX_MAX_CALLS", int64(d.Calls))),
			ProgramBytes: int(number("SANDBOX_MAX_PROGRAM_BYTES", int64(d.ProgramBytes))),
			ConsoleBytes: int(number("SANDBOX_MAX_CONSOLE_BYTES", int64(d.ConsoleBytes))),
			ValueBytes:   int(number("SANDBOX_MAX_VALUE_BYTES", int64(d.ValueBytes))),
		},
	}
	tlsConfig, err := service.TLSConfig(config)
	if err != nil {
		slog.Error("TLS", "error", err)
		os.Exit(1)
	}
	ln, err := tls.Listen("tcp", config.Listen, tlsConfig)
	if err != nil {
		slog.Error("Listening", "error", err)
		os.Exit(1)
	}
	slog.Info("Sandbox service listening", "address", config.Listen, "capacity", config.Capacity)
	slog.Error("Stopped", "error", service.New(config).Serve(ln))
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
