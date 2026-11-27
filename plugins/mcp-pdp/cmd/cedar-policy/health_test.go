package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

// gateway serves Tyk's readiness endpoint with the given status code and
// returns a configuration file pointing the probe at it, as tyk.conf does
// with a control API port.
func gateway(t *testing.T, code int, hosts chan<- string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hosts != nil {
			hosts <- r.Host
		}
		if r.URL.Path != "/ready" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	conf := filepath.Join(t.TempDir(), "tyk.conf")
	data := `{"listen_port": 1, "control_api_port": ` + port + `}`
	if err := os.WriteFile(conf, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return conf
}

func statusFile(t *testing.T, status policy.Status) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "status.json")
	data, _ := json.Marshal(status)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func noEnv(string) (string, bool) { return "", false }

func env(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) { v, ok := values[name]; return v, ok }
}

func TestHealth(t *testing.T) {
	enforced := policy.Status{Enforcing: "sha256:good", Active: "sha256:good", Outcome: "activated"}
	// A rejected new set leaves the previous one enforced.
	rejectedKept := policy.Status{Enforcing: "sha256:good", Active: "sha256:bad", Outcome: "rejected"}
	// After a restart onto a rejected set nothing is enforced.
	rejectedNone := policy.Status{Active: "sha256:bad", Outcome: "rejected"}
	cases := []struct {
		name   string
		code   int
		status *policy.Status
		want   string // empty when healthy
	}{
		{"ready and enforcing", 200, &enforced, ""},
		{"rejected set with the previous one enforced", 200, &rejectedKept, ""},
		{"no status file named", 200, nil, ""},
		{"not ready", 503, &enforced, "not ready"},
		{"no policy set enforced", 200, &rejectedNone, "enforces no policy set"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := []string{"-conf", gateway(t, c.code, nil)}
			if c.status != nil {
				args = append(args, "-status", statusFile(t, *c.status))
			}
			var out bytes.Buffer
			err := runHealth(args, noEnv, &out)
			if c.want == "" {
				if err != nil || !strings.HasPrefix(out.String(), "healthy") {
					t.Fatalf("want healthy, got %v (%q)", err, out.String())
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestHealthStatusFileFromEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	err := runHealth([]string{"-conf", gateway(t, 200, nil)}, env(map[string]string{"CEDAR_STATUS_FILE": path}), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "has not written its policy status") {
		t.Fatalf("want a missing status error, got %v", err)
	}
}

func TestHealthGatewayDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	conf := filepath.Join(t.TempDir(), "tyk.conf")
	os.WriteFile(conf, []byte(`{"control_api_port": `+port+`}`), 0o644)
	start := time.Now()
	err = runHealth([]string{"-conf", conf, "-timeout", "1s"}, noEnv, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("want an unreachable error, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the probe took %v", time.Since(start))
	}
}

func TestHealthControlAPIHostname(t *testing.T) {
	hosts := make(chan string, 1)
	conf := gateway(t, 200, hosts)
	if err := runHealth([]string{"-conf", conf}, env(map[string]string{"TYK_GW_CONTROLAPIHOSTNAME": "control.internal"}), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if host := <-hosts; host != "control.internal" {
		t.Fatalf("the probe sent Host %q", host)
	}
}

func TestHealthHelp(t *testing.T) {
	var out bytes.Buffer
	if err := runHealth([]string{"-h"}, noEnv, &out); err != nil || !strings.Contains(out.String(), "cedar-policy health") {
		t.Fatalf("help: %v %q", err, out.String())
	}
}

func TestReadyURL(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "tyk.conf")
	os.WriteFile(conf, []byte(`{"listen_port": 8080, "control_api_port": 9696}`), 0o644)
	cases := []struct {
		name string
		conf string
		env  map[string]string
		want string
	}{
		{"control port", conf, nil, "http://127.0.0.1:9696/ready"},
		{"control port from the environment", conf, map[string]string{"TYK_GW_CONTROLAPIPORT": "9000"}, "http://127.0.0.1:9000/ready"},
		{"listen port without a control port", "", map[string]string{"TYK_GW_OMITCONFIGFILE": "true", "TYK_GW_LISTENPORT": "8081"}, "http://127.0.0.1:8081/ready"},
		{"Tyk's default port", "", map[string]string{"TYK_GW_OMITCONFIGFILE": "true"}, "http://127.0.0.1:8080/ready"},
		{"unspecified listen address", conf, map[string]string{"TYK_GW_LISTENADDRESS": "0.0.0.0"}, "http://127.0.0.1:9696/ready"},
		{"specific listen address", conf, map[string]string{"TYK_GW_LISTENADDRESS": "::1"}, "http://[::1]:9696/ready"},
		{"TLS", conf, map[string]string{"TYK_GW_HTTPSERVEROPTIONS_USESSL": "true"}, "https://127.0.0.1:9696/ready"},
		{"renamed endpoint", conf, map[string]string{"TYK_GW_READINESSCHECKENDPOINTNAME": "readyz"}, "http://127.0.0.1:9696/readyz"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := readTykConfig(c.conf, env(c.env))
			if err != nil {
				t.Fatal(err)
			}
			if got := readyURL(cfg); got != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
	if _, err := readTykConfig(conf, env(map[string]string{"TYK_GW_CONTROLAPIPORT": "nine"})); err == nil {
		t.Fatal("an invalid port was accepted")
	}
}
