// Package codemode runs Code Mode programs for the gateway plug-in. A program
// runs on a separate sandbox host, reached over mutual TLS, and every tool
// call it makes is sent back through the gateway as the caller who started
// the run, so the gateway decides it exactly as it would a direct call.
package codemode

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// ExecuteTool is the tool that runs a program.
const ExecuteTool = "codemode.execute"

// ToolPrefix starts the name of every Code Mode tool. Programs cannot call
// these tools.
const ToolPrefix = "codemode."

// startAllowance is the time a sandbox host may take to start a run, beyond
// the run time itself. It matches the sandbox service's own allowance.
const startAllowance = 10 * time.Second

// responseMargin leaves room, within Tyk's write_timeout, to write the result
// after a run that used its whole allowance.
const responseMargin = 5 * time.Second

// Limits bound one run. The sandbox host enforces the run time, memory, calls
// per run and sizes; the plug-in checks sizes and calls per run too, and
// alone enforces calls at once and the time per call.
type Limits struct {
	protocol.Limits
	// CallsAtOnce bounds the tool calls in flight at once; further calls wait.
	CallsAtOnce int `json:"calls_at_once,omitempty"`
	// CallMillis bounds each tool call.
	CallMillis int64 `json:"call_ms,omitempty"`
}

// DefaultLimits are the operator maximums when no setting changes them.
var DefaultLimits = Limits{Limits: protocol.DefaultLimits, CallsAtOnce: 6, CallMillis: 30_000}

// Within returns the requested limits with every unset field taken from max
// and every field above max lowered to it.
func (l Limits) Within(max Limits) Limits {
	out := Limits{Limits: l.Limits.Within(max.Limits), CallsAtOnce: l.CallsAtOnce, CallMillis: l.CallMillis}
	if out.CallsAtOnce <= 0 || out.CallsAtOnce > max.CallsAtOnce {
		out.CallsAtOnce = max.CallsAtOnce
	}
	if out.CallMillis <= 0 || out.CallMillis > max.CallMillis {
		out.CallMillis = max.CallMillis
	}
	return out
}

// Settings configure Code Mode on one gateway.
type Settings struct {
	// Address is the sandbox host, or the load balancer in front of several,
	// as host:port.
	Address string
	TLS     *tls.Config
	// Backends lists the sandbox backends this gateway accepts.
	Backends map[string]bool
	// Proxies maps each proxy where Code Mode is on to its listen path.
	// Programs may call tools on any of these proxies.
	Proxies map[string]string
	// Gateway is the base URL nested calls are sent to: this gateway itself.
	Gateway string
	// Max holds the operator maximums; callers may only lower them.
	Max Limits
	// Runs bounds the runs this gateway takes at once.
	Runs int
}

// Tyk holds the gateway settings Code Mode depends on.
type Tyk struct {
	// ListenAddress is the address Tyk listens on; empty means every
	// address, so nested calls use the loopback address.
	ListenAddress string
	ListenPort    int
	UseTLS        bool
	WriteTimeout  time.Duration
}

// Load reads the settings from the environment. It returns nil settings and
// no error when Code Mode is not configured, and an error when it is
// configured but unusable, so the gateway can report Code Mode unavailable.
func Load(getenv func(string) string, tyk Tyk) (*Settings, error) {
	address := getenv("CODEMODE_SANDBOX_ADDRESS")
	proxies := getenv("CODEMODE_PROXIES")
	if address == "" && proxies == "" {
		return nil, nil
	}
	s := &Settings{Address: address, Backends: map[string]bool{}, Max: DefaultLimits, Runs: 8}
	var problems []string
	fail := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	if address == "" {
		fail("CODEMODE_SANDBOX_ADDRESS is not set")
	}
	var err error
	if s.Proxies, err = parseProxies(proxies); err != nil {
		fail("CODEMODE_PROXIES: %v", err)
	}
	backends := getenv("CODEMODE_BACKENDS")
	if backends == "" {
		backends = protocol.BackendGVisor
	}
	for _, b := range strings.Split(backends, ",") {
		switch b = strings.TrimSpace(b); b {
		case protocol.BackendGVisor, protocol.BackendRunc:
			s.Backends[b] = true
		default:
			fail("CODEMODE_BACKENDS: unknown backend %q", b)
		}
	}
	s.Gateway = getenv("CODEMODE_GATEWAY_URL")
	if s.Gateway == "" {
		scheme := "http"
		if tyk.UseTLS {
			scheme = "https"
		}
		host := tyk.ListenAddress
		if host == "" {
			host = "127.0.0.1"
		}
		s.Gateway = fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, strconv.Itoa(tyk.ListenPort)))
	}
	s.Gateway = strings.TrimSuffix(s.Gateway, "/")
	number := func(name string, target *int64) {
		if value := getenv(name); value != "" {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n <= 0 {
				fail("%s must be a positive whole number, not %q", name, value)
				return
			}
			*target = n
		}
	}
	small := func(name string, target *int) {
		v := int64(*target)
		number(name, &v)
		*target = int(v)
	}
	number("CODEMODE_MAX_RUN_MS", &s.Max.RunMillis)
	number("CODEMODE_MAX_MEMORY_BYTES", &s.Max.MemoryBytes)
	number("CODEMODE_MAX_CALL_MS", &s.Max.CallMillis)
	small("CODEMODE_MAX_CALLS", &s.Max.Calls)
	small("CODEMODE_MAX_CALLS_AT_ONCE", &s.Max.CallsAtOnce)
	small("CODEMODE_MAX_PROGRAM_BYTES", &s.Max.ProgramBytes)
	small("CODEMODE_MAX_CONSOLE_BYTES", &s.Max.ConsoleBytes)
	small("CODEMODE_MAX_VALUE_BYTES", &s.Max.ValueBytes)
	small("CODEMODE_MAX_RUNS", &s.Runs)
	// The whole run, the sandbox's start and writing the result must fit in
	// the time Tyk allows for a response, or results would be cut off.
	if need := time.Duration(s.Max.RunMillis)*time.Millisecond + startAllowance + responseMargin; tyk.WriteTimeout > 0 && need > tyk.WriteTimeout {
		fail("the run time limit of %s, plus %s to start a sandbox and %s to reply, exceeds Tyk's write_timeout of %s",
			time.Duration(s.Max.RunMillis)*time.Millisecond, startAllowance, responseMargin, tyk.WriteTimeout)
	}
	if s.TLS, err = clientTLS(getenv); err != nil {
		fail("%v", err)
	}
	if len(problems) > 0 {
		return s, errors.New(strings.Join(problems, "; "))
	}
	return s, nil
}

var proxyID = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// parseProxies reads "id=/path/,id2=/path2/".
func parseProxies(value string) (map[string]string, error) {
	proxies := map[string]string{}
	for _, entry := range strings.Split(value, ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		id, path, ok := strings.Cut(entry, "=")
		if !ok || !proxyID.MatchString(id) || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\\ ") {
			return nil, fmt.Errorf("entry %q is not proxy-id=/listen/path/", entry)
		}
		if _, dup := proxies[id]; dup {
			return nil, fmt.Errorf("proxy %q is listed twice", id)
		}
		proxies[id] = path
	}
	if len(proxies) == 0 {
		return nil, errors.New("no proxies are listed")
	}
	return proxies, nil
}

// clientTLS builds the mutual-TLS client configuration from the certificate,
// key and certificate authority files.
func clientTLS(getenv func(string) string) (*tls.Config, error) {
	certFile, keyFile, caFile := getenv("CODEMODE_TLS_CERT"), getenv("CODEMODE_TLS_KEY"), getenv("CODEMODE_TLS_CA")
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, errors.New("CODEMODE_TLS_CERT, CODEMODE_TLS_KEY and CODEMODE_TLS_CA must all be set")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading the client certificate: %w", err)
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading the certificate authority: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("the certificate authority file holds no certificates")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   getenv("CODEMODE_SANDBOX_SERVER_NAME"),
		MinVersion:   tls.VersionTLS13,
		// Resumed sessions skip most of the handshake on later runs.
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
	}, nil
}
