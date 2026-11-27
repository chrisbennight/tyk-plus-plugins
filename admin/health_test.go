package main

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestProbeAddress(t *testing.T) {
	for listen, want := range map[string]string{":8000": "127.0.0.1:8000", "0.0.0.0:8000": "127.0.0.1:8000",
		"[::]:8000": "[::1]:8000", "10.0.0.5:8000": "10.0.0.5:8000"} {
		if got, err := probeAddress(listen); err != nil || got != want {
			t.Errorf("probeAddress(%q) = %q, %v; want %q", listen, got, err, want)
		}
	}
}

func TestHealthcheck(t *testing.T) {
	// The identity provider is unreachable; the dashboard is still healthy.
	cfg := config{store: t.TempDir(), pending: t.TempDir(), issuer: "https://127.0.0.1:1", discoveryURL: "https://127.0.0.1:1",
		clientID: "drift-review", clientSecret: "unused", reviewerGroup: "reviewers", groupsClaim: "groups"}
	public, _ := url.Parse("https://gateway.example/extensions/admin")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: newServer(cfg, newAuth(cfg, public)).routes()}
	go srv.Serve(ln)
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// ADMIN_LISTEN's default form, with no host, is probed on loopback.
	if err := healthcheck(":"+port, 2*time.Second); err != nil {
		t.Fatalf("healthy dashboard reported unhealthy: %v", err)
	}
	if err := healthcheck("0.0.0.0:"+port, 2*time.Second); err != nil {
		t.Fatalf("unspecified address: %v", err)
	}

	srv.Close()
	if err := healthcheck(":"+port, time.Second); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("stopped dashboard: %v", err)
	}
	if err := healthcheck("8000", time.Second); err == nil || !strings.Contains(err.Error(), "ADMIN_LISTEN") {
		t.Fatalf("invalid listen address: %v", err)
	}
}
