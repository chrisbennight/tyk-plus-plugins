// Command sandbox-probe tests a running sandbox host from outside, as a
// gateway would: over mutual TLS, one connection per run. "certs DIR" writes a
// throwaway certificate authority and certificates for the test stack.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func check(ok bool, format string, args ...any) {
	if !ok {
		panic(fmt.Sprintf(format, args...))
	}
}

func main() {
	defer func() {
		if failure := recover(); failure != nil {
			fmt.Fprintln(os.Stderr, "FAILED:", failure)
			os.Exit(1)
		}
	}()
	if len(os.Args) == 3 && os.Args[1] == "certs" {
		certs(os.Args[2])
		return
	}
	probe()
}

// certs writes a server certificate, a client authority, a client certificate
// it signed, and a client certificate from an unrelated authority.
func certs(dir string) {
	issue := func(name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, isCA bool, usage x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
		if !isCA {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		}
		parent, signer := tmpl, key
		if ca != nil {
			parent, signer = ca, caKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
		check(err == nil, "issuing %s: %v", name, err)
		cert, _ := x509.ParseCertificate(der)
		return cert, key
	}
	write := func(name string, cert *x509.Certificate, key *ecdsa.PrivateKey) {
		os.WriteFile(filepath.Join(dir, name+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644)
		if key != nil {
			der, _ := x509.MarshalECPrivateKey(key)
			os.WriteFile(filepath.Join(dir, name+"-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o644)
		}
	}
	ca, caKey := issue("test-ca", nil, nil, true, 0)
	write("client-ca", ca, nil)
	server, serverKey := issue("sandbox", ca, caKey, false, x509.ExtKeyUsageServerAuth)
	write("server", server, serverKey)
	client, clientKey := issue("gateway", ca, caKey, false, x509.ExtKeyUsageClientAuth)
	write("client", client, clientKey)
	rogueCA, rogueKey := issue("rogue-ca", nil, nil, true, 0)
	rogue, rogueClientKey := issue("gateway", rogueCA, rogueKey, false, x509.ExtKeyUsageClientAuth)
	write("rogue", rogue, rogueClientKey)
	fmt.Println("Wrote test certificates to", dir)
}

var (
	addr    = env("SANDBOX_ADDR", "sandbox:8443")
	certDir = env("SANDBOX_CERTS", "/certs")
	socket  = env("SANDBOX_LAUNCHER_SOCKET", "/run/sandbox-launcher/launcher.sock")
)

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func tlsConfig(clientName string) *tls.Config {
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(certDir, "client-ca.pem"))
	check(err == nil && pool.AppendCertsFromPEM(caPEM), "reading the authority: %v", err)
	config := &tls.Config{RootCAs: pool, ServerName: "sandbox", MinVersion: tls.VersionTLS13}
	if clientName != "" {
		cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, clientName+".pem"), filepath.Join(certDir, clientName+"-key.pem"))
		check(err == nil, "loading %s: %v", clientName, err)
		config.Certificates = []tls.Certificate{cert}
	}
	return config
}

type message map[string]any

type conn struct {
	c net.Conn
	r *bufio.Reader
}

func open(clientName string) (*conn, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, tlsConfig(clientName))
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(60 * time.Second))
	return &conn{c: c, r: bufio.NewReaderSize(c, 1<<20)}, nil
}

func (c *conn) send(m message) {
	data, _ := json.Marshal(m)
	_, err := c.c.Write(append(data, '\n'))
	check(err == nil, "sending: %v", err)
}

func (c *conn) read() (message, error) {
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var m message
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *conn) must() message {
	m, err := c.read()
	check(err == nil, "reading: %v", err)
	return m
}

func health() message {
	c, err := open("client")
	if err != nil {
		return nil
	}
	defer c.c.Close()
	if hello, err := c.read(); err != nil || hello["type"] != "hello" {
		return nil
	}
	c.send(message{"type": "health"})
	m, err := c.read()
	if err != nil || m["type"] != "health" {
		return nil
	}
	h, _ := m["health"].(map[string]any)
	return h
}

// settled waits until the launcher tracks no runs and the runtime reports no
// containers.
func settled(after string) {
	var h message
	for range 50 {
		h = health()
		if h != nil && h["active"] == 0.0 && h["containers"] == 0.0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	panic(fmt.Sprintf("sandboxes remained after %s: %v", after, h))
}

// run starts a program and answers its tool calls with answer, returning the
// final message and the calls seen.
func run(source string, input any, limits message, answer func(call message) message) (message, []message) {
	c, err := open("client")
	check(err == nil, "connecting: %v", err)
	defer c.c.Close()
	hello := c.must()
	check(hello["type"] == "hello", "no hello: %v", hello)
	start := message{"type": "start", "source": source}
	if input != nil {
		start["input"] = input
	}
	if limits != nil {
		start["limits"] = limits
	}
	c.send(start)
	var calls []message
	for {
		m := c.must()
		switch m["type"] {
		case "call":
			calls = append(calls, m)
			if answer == nil {
				continue
			}
			reply := answer(m)
			reply["id"] = m["id"]
			c.send(reply)
		case "done", "failed":
			return m, calls
		default:
			panic(fmt.Sprintf("unexpected message %v", m))
		}
	}
}

func lookup(call message) message {
	args, _ := call["arguments"].(map[string]any)
	count, _ := args["count"].(float64)
	if call["tool"] != "lookup" {
		return message{"type": "error", "error": message{"code": -32002, "message": "Tool call denied"}}
	}
	return message{"type": "result", "result": message{"found": count * 2}}
}

func failure(m message) (string, string) {
	f, _ := m["failure"].(map[string]any)
	kind, _ := f["kind"].(string)
	text, _ := f["message"].(string)
	return kind, text
}

func probe() {
	// Wait for the host.
	var h message
	for range 120 {
		if h = health(); h != nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	check(h != nil, "the sandbox service never answered a health query")
	want := env("EXPECT_BACKEND", "gvisor")
	check(h["backend"] == want && h["ready"] == true, "health: %v (want backend %s, ready)", h, want)
	selfTest, _ := h["self_test"].(map[string]any)
	for _, name := range []string{"network", "host file", "write", "processes"} {
		check(selfTest[name] == "blocked", "self-test %q: %v", name, selfTest)
	}
	fmt.Printf("Health: backend %s, self-test %v.\n", h["backend"], selfTest)

	// Only clients with a certificate from the configured authority get in.
	for _, name := range []string{"rogue", ""} {
		c, err := open(name)
		if err == nil {
			_, err = c.read()
			c.c.Close()
		}
		check(err != nil, "a client with certificate %q was served", name)
	}
	fmt.Println("Refused clients without a certificate from the configured authority.")

	// Tool calls, in sequence and in parallel, and a refused call.
	started := time.Now()
	m, calls := run(`
		const first = await connectors.governed.lookup({ count: input.start });
		const rest = await Promise.all([1, 2, 3].map((n) => connectors.governed.lookup({ count: n })));
		let refused;
		try { await connectors.other.change({}); } catch (e) { refused = e.message; }
		console.log("first", first.found);
		return { first: first.found, rest: rest.map((r) => r.found), refused };`, message{"start": 5}, nil, lookup)
	elapsed := time.Since(started)
	result, _ := json.Marshal(m["result"])
	check(m["type"] == "done" && string(result) == `{"first":10,"refused":"Tool call denied","rest":[2,4,6]}`, "tool calls: %v", m)
	check(len(calls) == 5 && calls[4]["proxy"] == "other" && calls[4]["tool"] == "change", "calls seen: %v", calls)
	console, _ := m["console"].([]any)
	check(len(console) == 1 && console[0] == "first 10", "console: %v", console)
	fmt.Printf("A program made five tool calls, three in parallel, and returned its result in %v.\n", elapsed.Round(time.Millisecond))
	settled("a finished run")

	// The program sees no host capabilities.
	m, _ = run(`
		const seen = {};
		for (const name of ["print", "fetch", "require", "process", "Deno"]) seen[name] = typeof globalThis[name];
		try { const std = await import("qjs:std"); const f = std.open("/etc/hostname", "r"); seen.file = f ? f.readAsString() : null; }
		catch (e) { seen.file = "refused"; }
		return seen;`, nil, nil, nil)
	result, _ = json.Marshal(m["result"])
	check(m["type"] == "done" && strings.Contains(string(result), `"fetch":"undefined"`) && strings.Contains(string(result), `"print":"undefined"`) &&
		(strings.Contains(string(result), `"file":null`) || strings.Contains(string(result), `"file":"refused"`)), "capabilities: %v", m)
	fmt.Println("The program found no host functions and could not open a file.")
	settled("the capabilities run")

	// Limits.
	for _, c := range []struct {
		name, source string
		limits       message
		want         string
	}{
		// A busy loop meets the processor budget or the run time, whichever
		// comes first on this machine.
		{"an endless loop", `while (true) {}`, message{"run_ms": 2000}, "exceeded its"},
		{"too much memory", `const a = []; for (;;) a.push(new Array(1e6).fill(1));`, message{"memory_bytes": 64 << 20}, "memory"},
		{"too much console output", `for (;;) console.log("x".repeat(1000));`, message{"console_bytes": 10000}, "console"},
		{"too many tool calls", `for (let i = 0; i < 5; i++) await connectors.governed.lookup({ count: i });`, message{"calls": 3}, "tool calls"},
	} {
		m, _ := run(c.source, nil, c.limits, lookup)
		kind, text := failure(m)
		check(m["type"] == "failed" && kind == "limit" && strings.Contains(text, c.want), "%s: %v", c.name, m)
		fmt.Printf("Stopped %s: %s.\n", c.name, text)
		settled(c.name)
	}

	// A run whose tool call is never answered ends at its run time.
	m, _ = run(`await connectors.governed.lookup({ count: 1 }); return 1;`, nil, message{"run_ms": 2000}, nil)
	kind, text := failure(m)
	check(m["type"] == "failed" && kind == "limit" && strings.Contains(text, "run time"), "unanswered call: %v", m)
	settled("an unanswered tool call")
	fmt.Println("Ended a run waiting on an unanswered tool call at its run time.")

	// A gateway that disconnects mid-run leaves nothing behind.
	c, err := open("client")
	check(err == nil, "connecting: %v", err)
	c.must()
	c.send(message{"type": "start", "source": `await connectors.governed.lookup({ count: 1 });`})
	check(c.must()["type"] == "call", "no call before disconnecting")
	c.c.Close()
	settled("a disconnected gateway")
	fmt.Println("Destroyed the sandbox of a run whose gateway disconnected.")

	// A host at capacity refuses further runs.
	capacity := 2
	var held []*conn
	for range capacity {
		c, err := open("client")
		check(err == nil, "connecting: %v", err)
		c.must()
		c.send(message{"type": "start", "source": `await connectors.governed.lookup({ count: 1 });`})
		check(c.must()["type"] == "call", "a held run made no call")
		held = append(held, c)
	}
	m, _ = run(`return 1;`, nil, nil, nil)
	kind, _ = failure(m)
	check(m["type"] == "failed" && kind == "busy", "a run beyond capacity: %v", m)
	for _, c := range held {
		c.c.Close()
	}
	settled("runs at capacity")
	fmt.Println("Refused a run beyond the host's capacity.")

	// Only the sandbox service's user may use the launcher.
	lc, err := net.Dial("unix", socket)
	check(err == nil, "dialing the launcher: %v", err)
	lc.Write([]byte(`{"op":"health"}` + "\n"))
	reply, _ := bufio.NewReader(lc).ReadString('\n')
	lc.Close()
	check(strings.Contains(reply, "refused"), "the launcher served another user: %s", reply)
	fmt.Printf("The launcher refused a connection from user %d.\n", os.Getuid())
	fmt.Println("All sandbox checks passed.")
}
