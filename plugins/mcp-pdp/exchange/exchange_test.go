package exchange

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	callerToken = "caller.token.value"
	secret      = "client:secret/+ value%"
)

// endpoint is a fake token endpoint. reply writes the response for each
// request it records.
type endpoint struct {
	t        *testing.T
	server   *httptest.Server
	caFile   string
	requests atomic.Int32
	mu       sync.Mutex
	forms    []url.Values
	auth     []string
	reply    func(w http.ResponseWriter, form url.Values)
}

func newEndpoint(t *testing.T, reply func(w http.ResponseWriter, form url.Values)) *endpoint {
	e := &endpoint{t: t, reply: reply}
	e.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.requests.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("request %s with content type %q", r.Method, r.Header.Get("Content-Type"))
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		e.mu.Lock()
		e.forms = append(e.forms, r.PostForm)
		e.auth = append(e.auth, r.Header.Get("Authorization"))
		e.mu.Unlock()
		e.reply(w, r.PostForm)
	}))
	t.Cleanup(e.server.Close)
	e.caFile = filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.server.Certificate().Raw})
	if err := os.WriteFile(e.caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

func issued(token string, expiresIn string) func(http.ResponseWriter, url.Values) {
	return func(w http.ResponseWriter, _ url.Values) {
		w.Header().Set("Content-Type", "application/json")
		body := `{"access_token":"` + token + `","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"`
		if expiresIn != "" {
			body += `,"expires_in":` + expiresIn
		}
		w.Write([]byte(body + "}"))
	}
}

func settings(t *testing.T, e *endpoint, extra map[string]string) *Settings {
	t.Helper()
	env := map[string]string{
		"EXCHANGE_TOKEN_URL":     e.server.URL + "/token",
		"EXCHANGE_TLS_CA":        e.caFile,
		"EXCHANGE_CLIENT_ID":     "gateway client",
		"EXCHANGE_CLIENT_SECRET": secret,
		"EXCHANGE_PROXIES":       "governed=https://mcp.example.com/mcp tools:read tools:write,other=https://other.example.com/mcp",
	}
	for k, v := range extra {
		env[k] = v
	}
	s, err := Load(func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRequestShape(t *testing.T) {
	e := newEndpoint(t, issued("issued-token", "300"))
	c := New(settings(t, e, nil))
	token, err := c.Exchange(context.Background(), "governed", callerToken, time.Now().Add(time.Hour))
	if err != nil || token != "issued-token" {
		t.Fatalf("got %q, %v", token, err)
	}
	if _, err := c.Exchange(context.Background(), "other", callerToken, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	want := []url.Values{
		{"grant_type": {grantType}, "subject_token": {callerToken}, "subject_token_type": {accessTokenType},
			"resource": {"https://mcp.example.com/mcp"}, "scope": {"tools:read tools:write"}},
		{"grant_type": {grantType}, "subject_token": {callerToken}, "subject_token_type": {accessTokenType},
			"resource": {"https://other.example.com/mcp"}},
	}
	for i, form := range e.forms {
		if form.Has("audience") {
			t.Errorf("request %d sent audience", i)
		}
		if form.Encode() != want[i].Encode() {
			t.Errorf("request %d: got %v, want %v", i, form, want[i])
		}
		// Basic authentication with the form-encoded client ID and secret.
		r := &http.Request{Header: http.Header{"Authorization": {e.auth[i]}}}
		// Both parts are form-encoded before Basic encoding, so a server
		// form-decodes them (RFC 6749 section 2.3.1).
		rawID, rawPass, ok := r.BasicAuth()
		id, idErr := url.QueryUnescape(rawID)
		pass, passErr := url.QueryUnescape(rawPass)
		if !ok || idErr != nil || passErr != nil || id != "gateway client" || pass != secret {
			t.Errorf("request %d: client authentication %q %q %v", i, id, pass, ok)
		}
	}
}

func TestTrust(t *testing.T) {
	e := newEndpoint(t, issued("issued-token", "300"))
	// Without EXCHANGE_TLS_CA only the system's certificate authorities are
	// trusted, and they do not include the test endpoint's.
	c := New(settings(t, e, map[string]string{"EXCHANGE_TLS_CA": ""}))
	_, err := c.Exchange(context.Background(), "governed", callerToken, time.Now().Add(time.Hour))
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != KindUnreachable || e.requests.Load() != 0 {
		t.Fatalf("an untrusted endpoint gave %v after %d requests", err, e.requests.Load())
	}
	// With it, that authority alone is trusted: the configured pool is
	// exactly the file's certificates, not the system's with them added.
	configured := settings(t, e, nil)
	want := x509.NewCertPool()
	want.AddCert(e.server.Certificate())
	if configured.TLS.RootCAs == nil || !configured.TLS.RootCAs.Equal(want) {
		t.Fatal("EXCHANGE_TLS_CA did not replace the system's certificate authorities")
	}
	if _, err := New(configured).Exchange(context.Background(), "governed", callerToken, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestCache(t *testing.T) {
	e := newEndpoint(t, issued("issued-token", "600"))
	c := New(settings(t, e, map[string]string{"EXCHANGE_EXPIRY_MARGIN": "60s"}))
	now := time.Now()
	c.now = func() time.Time { return now }
	exchange := func(proxy, caller string, expiry time.Time) {
		t.Helper()
		if _, err := c.Exchange(context.Background(), proxy, caller, expiry); err != nil {
			t.Fatal(err)
		}
	}
	far := now.Add(time.Hour)
	exchange("governed", "a", far)
	exchange("governed", "a", far)
	if n := e.requests.Load(); n != 1 {
		t.Fatalf("a cached token was exchanged again: %d requests", n)
	}
	// Another caller or another proxy is another entry.
	exchange("governed", "b", far)
	exchange("other", "a", far)
	if n := e.requests.Load(); n != 3 {
		t.Fatalf("got %d requests, want 3", n)
	}
	// The entry lasts expires_in minus the margin: 600s - 60s.
	now = now.Add(539 * time.Second)
	exchange("governed", "a", far)
	if n := e.requests.Load(); n != 3 {
		t.Fatalf("an entry expired early: %d requests", n)
	}
	now = now.Add(2 * time.Second)
	exchange("governed", "a", far)
	if n := e.requests.Load(); n != 4 {
		t.Fatalf("an expired entry was used: %d requests", n)
	}
}

func TestSlowReplyOutlivesIssuedToken(t *testing.T) {
	start := time.Now()
	var elapsed atomic.Int64
	reply := issued("issued-token", "60")
	// The reply arrives after the issued token's 60-second lifetime, counted
	// from when the request was sent, has run out.
	e := newEndpoint(t, func(w http.ResponseWriter, form url.Values) {
		elapsed.Store(int64(61 * time.Second))
		reply(w, form)
	})
	c := New(settings(t, e, nil))
	c.now = func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
	_, err := c.Exchange(context.Background(), "governed", callerToken, start.Add(time.Hour))
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != KindExpired {
		t.Fatalf("an issued token whose lifetime ran out during the exchange gave %v", err)
	}
}

func TestCacheNeverOutlivesCallerToken(t *testing.T) {
	e := newEndpoint(t, issued("issued-token", "3600"))
	c := New(settings(t, e, map[string]string{"EXCHANGE_EXPIRY_MARGIN": "10s"}))
	now := time.Now()
	c.now = func() time.Time { return now }
	callerExpiry := now.Add(100 * time.Second)
	for range 2 {
		if _, err := c.Exchange(context.Background(), "governed", "a", callerExpiry); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(91 * time.Second)
	if _, err := c.Exchange(context.Background(), "governed", "a", callerExpiry); err != nil {
		t.Fatal(err)
	}
	if n := e.requests.Load(); n != 2 {
		t.Fatalf("got %d requests, want 2: the entry must end 10s before the caller's token", n)
	}
	// A caller token expiring within the margin is exchanged but not cached.
	soon := now.Add(5 * time.Second)
	for range 2 {
		if _, err := c.Exchange(context.Background(), "governed", "b", soon); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.requests.Load(); n != 4 {
		t.Fatalf("got %d requests, want 4", n)
	}
}

func TestNoExpiresInIsNotCached(t *testing.T) {
	for _, expiresIn := range []string{"", "0", "-5", `"600"`, "1.5"} {
		e := newEndpoint(t, issued("issued-token", expiresIn))
		c := New(settings(t, e, nil))
		for range 2 {
			if token, err := c.Exchange(context.Background(), "governed", "a", time.Now().Add(time.Hour)); err != nil || token != "issued-token" {
				t.Fatalf("expires_in %q: %q, %v", expiresIn, token, err)
			}
		}
		if n := e.requests.Load(); n != 2 {
			t.Errorf("expires_in %q: got %d requests, want 2", expiresIn, n)
		}
	}
}

func TestEviction(t *testing.T) {
	e := newEndpoint(t, issued("issued-token", "600"))
	c := New(settings(t, e, map[string]string{"EXCHANGE_CACHE_MAX_ENTRIES": "2"}))
	far := time.Now().Add(time.Hour)
	for _, caller := range []string{"a", "b", "a", "c", "a", "b"} {
		if _, err := c.Exchange(context.Background(), "governed", caller, far); err != nil {
			t.Fatal(err)
		}
	}
	// a, b cached; a used again; c evicts b, the least recently used; a is
	// still cached; b must be exchanged again.
	if n := e.requests.Load(); n != 4 {
		t.Fatalf("got %d requests, want 4", n)
	}
}

func TestConcurrentMissesShareOneExchange(t *testing.T) {
	release := make(chan struct{})
	e := newEndpoint(t, func(w http.ResponseWriter, form url.Values) {
		<-release
		issued("issued-token", "600")(w, form)
	})
	c := New(settings(t, e, nil))
	var wg sync.WaitGroup
	results := make(chan string, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := c.Exchange(context.Background(), "governed", "a", time.Now().Add(time.Hour))
			if err != nil {
				t.Error(err)
			}
			results <- token
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)
	for token := range results {
		if token != "issued-token" {
			t.Errorf("got %q", token)
		}
	}
	if n := e.requests.Load(); n != 1 {
		t.Fatalf("got %d requests, want 1", n)
	}
}

func TestFailsClosed(t *testing.T) {
	refusal := func(status int, body string) func(http.ResponseWriter, url.Values) {
		return func(w http.ResponseWriter, _ url.Values) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write([]byte(body))
		}
	}
	ok := `"access_token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"`
	for _, c := range []struct {
		name  string
		reply func(http.ResponseWriter, url.Values)
		kind  string
		code  string
	}{
		{"invalid_request", refusal(400, `{"error":"invalid_request","error_description":"bad subject"}`), KindRejected, "invalid_request"},
		{"invalid_grant", refusal(400, `{"error":"invalid_grant"}`), KindRejected, "invalid_grant"},
		{"invalid_target", refusal(400, `{"error":"invalid_target"}`), KindRejected, "invalid_target"},
		// Only an exactly named, single error member gives a code.
		{"case-variant error member", refusal(400, `{"ERROR":"invalid_grant"}`), KindRejected, ""},
		{"repeated error member", refusal(400, `{"error":"invalid_grant","error":"invalid_target"}`), KindRejected, ""},
		{"server error", refusal(500, `oops`), KindRejected, ""},
		{"empty 502", refusal(502, ``), KindRejected, ""},
		{"redirect", func(w http.ResponseWriter, _ url.Values) {
			http.Redirect(w, &http.Request{}, "https://elsewhere.example/", 302)
		}, KindRejected, ""},
		{"not JSON", refusal(200, `access_token=t`), KindMalformed, ""},
		{"JSON array", refusal(200, `[1]`), KindMalformed, ""},
		{"no access_token", refusal(200, `{"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"}`), KindMalformed, ""},
		{"no issued_token_type", refusal(200, `{"access_token":"t","token_type":"Bearer"}`), KindMalformed, ""},
		{"no token_type", refusal(200, `{"access_token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}`), KindMalformed, ""},
		{"N_A token type", refusal(200, `{"access_token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"N_A"}`), KindMalformed, ""},
		{"other token type", refusal(200, `{"access_token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"DPoP"}`), KindMalformed, ""},
		{"id token issued", refusal(200, `{"access_token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:id_token","token_type":"Bearer"}`), KindMalformed, ""},
		{"token with a line break", refusal(200, `{"access_token":"t\r\nX-Injected: 1","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"}`), KindMalformed, ""},
		{"empty token", refusal(200, `{"access_token":"","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"}`), KindMalformed, ""},
		{"oversized", refusal(200, `{`+ok+`,"padding":"`+strings.Repeat("x", maxResponseBytes)+`"}`), KindMalformed, ""},
		{"timeout", func(w http.ResponseWriter, _ url.Values) { time.Sleep(700 * time.Millisecond) }, KindUnreachable, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEndpoint(t, c.reply)
			client := New(settings(t, e, map[string]string{"EXCHANGE_TIMEOUT": "300ms"}))
			token, err := client.Exchange(context.Background(), "governed", callerToken, time.Now().Add(time.Hour))
			var failure *Error
			if token != "" || !errors.As(err, &failure) || failure.Kind != c.kind || failure.Code != c.code {
				t.Fatalf("got %q, %#v", token, err)
			}
			// A failure is never cached.
			client.Exchange(context.Background(), "governed", callerToken, time.Now().Add(time.Hour))
			if n := e.requests.Load(); n != 2 {
				t.Fatalf("got %d requests, want 2", n)
			}
		})
	}
	// An unreachable endpoint.
	e := newEndpoint(t, issued("t", "60"))
	s := settings(t, e, nil)
	e.server.Close()
	if _, err := New(s).Exchange(context.Background(), "governed", callerToken, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("a closed endpoint gave a token")
	}
	// A proxy without exchange, or no caller token, is never exchanged.
	for _, c := range []struct{ proxy, subject string }{{"unlisted", callerToken}, {"governed", ""}} {
		e := newEndpoint(t, issued("t", "60"))
		if _, err := New(settings(t, e, nil)).Exchange(context.Background(), c.proxy, c.subject, time.Now().Add(time.Hour)); err == nil || e.requests.Load() != 0 {
			t.Errorf("%+v: %v after %d requests", c, err, e.requests.Load())
		}
	}
}

func TestLogsHoldNoSecrets(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	description := "subject " + callerToken + " was rejected"
	e := newEndpoint(t, func(w http.ResponseWriter, _ url.Values) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"` + description + `"}`))
	})
	_, err := New(settings(t, e, nil)).Exchange(context.Background(), "governed", callerToken, time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("a refusal gave a token")
	}
	out := logs.String() + err.Error()
	for _, leak := range []string{callerToken, secret, description, "error_description"} {
		if strings.Contains(out, leak) {
			t.Errorf("logs or error contain %q: %s", leak, out)
		}
	}
	if !strings.Contains(logs.String(), "proxy=governed") || !strings.Contains(logs.String(), "error_code=invalid_grant") {
		t.Errorf("the log should name the proxy and the error code: %s", logs.String())
	}
}

func TestLoad(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secretFile, []byte("from-file\n"), 0o600)
	emptyCA := filepath.Join(t.TempDir(), "empty.pem")
	os.WriteFile(emptyCA, []byte("not a certificate"), 0o600)
	base := map[string]string{
		"EXCHANGE_TOKEN_URL":     "https://idp.example.com/token",
		"EXCHANGE_CLIENT_ID":     "gateway",
		"EXCHANGE_CLIENT_SECRET": "from-env",
		"EXCHANGE_PROXIES":       "governed=https://mcp.example.com/mcp",
	}
	load := func(changes map[string]string) (*Settings, error) {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range changes {
			env[k] = v
		}
		return Load(func(name string) string { return env[name] })
	}
	if s, err := Load(func(string) string { return "" }); s != nil || err != nil {
		t.Fatalf("unconfigured: %v, %v", s, err)
	}
	s, err := load(map[string]string{"EXCHANGE_CLIENT_SECRET_FILE": secretFile})
	if err != nil || s.ClientSecret != "from-file" || s.Timeout != DefaultTimeout || s.CacheEntries != DefaultCacheEntries || s.ExpiryMargin != DefaultExpiryMargin {
		t.Fatalf("got %+v, %v", s, err)
	}
	if !s.On("governed") || s.On("other") {
		t.Fatal("On reports the wrong proxies")
	}
	if s, err := load(map[string]string{"EXCHANGE_TOKEN_URL": "http://idp:8080/token", "EXCHANGE_ALLOW_INSECURE_HTTP": "true"}); err != nil || s.TokenURL != "http://idp:8080/token" {
		t.Fatalf("an allowed http endpoint was refused: %v", err)
	}
	for name, changes := range map[string]map[string]string{
		"http without the flag":  {"EXCHANGE_TOKEN_URL": "http://idp.example.com/token"},
		"relative token URL":     {"EXCHANGE_TOKEN_URL": "/token"},
		"no client ID":           {"EXCHANGE_CLIENT_ID": ""},
		"no secret":              {"EXCHANGE_CLIENT_SECRET": ""},
		"unreadable secret file": {"EXCHANGE_CLIENT_SECRET_FILE": filepath.Join(t.TempDir(), "missing")},
		"relative resource":      {"EXCHANGE_PROXIES": "governed=/mcp"},
		"resource with fragment": {"EXCHANGE_PROXIES": "governed=https://mcp.example.com/mcp#x"},
		"no resource":            {"EXCHANGE_PROXIES": "governed="},
		"repeated proxy":         {"EXCHANGE_PROXIES": "governed=https://a.example/mcp,governed=https://b.example/mcp"},
		"no proxies":             {"EXCHANGE_PROXIES": ""},
		"bad timeout":            {"EXCHANGE_TIMEOUT": "15"},
		"zero margin":            {"EXCHANGE_EXPIRY_MARGIN": "0s"},
		"bad cache size":         {"EXCHANGE_CACHE_MAX_ENTRIES": "-1"},
		"unreadable CA":          {"EXCHANGE_TLS_CA": filepath.Join(t.TempDir(), "missing.pem")},
		"CA without certs":       {"EXCHANGE_TLS_CA": emptyCA},
	} {
		if _, err := load(changes); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "from-env") {
			t.Errorf("%s: the error shows the secret: %v", name, err)
		}
	}
	// A proxy named with an invalid target still has exchange on, so its
	// calls are refused; an unreadable entry turns it on for every proxy.
	if s, err := load(map[string]string{"EXCHANGE_PROXIES": "governed=/mcp"}); err == nil || !s.On("governed") {
		t.Fatal("a proxy with an invalid target must stay on")
	}
	if s, err := load(map[string]string{"EXCHANGE_PROXIES": "governed https://mcp.example.com/mcp"}); err == nil || !s.On("anything") {
		t.Fatal("an unreadable entry must turn exchange on for every proxy")
	}
}

func TestNeverUsedAfterCallerTokenExpires(t *testing.T) {
	// The caller's token expires while the exchange is under way.
	e := newEndpoint(t, func(w http.ResponseWriter, form url.Values) {
		time.Sleep(300 * time.Millisecond)
		issued("issued-token", "600")(w, form)
	})
	c := New(settings(t, e, map[string]string{"EXCHANGE_EXPIRY_MARGIN": "1ms"}))
	token, err := c.Exchange(context.Background(), "governed", callerToken, time.Now().Add(100*time.Millisecond))
	var failure *Error
	if token != "" || !errors.As(err, &failure) || failure.Kind != KindExpired {
		t.Fatalf("got %q, %v", token, err)
	}
}

func TestReplyMembersAreExact(t *testing.T) {
	for name, body := range map[string]string{
		"upper case":       `{"ACCESS_TOKEN":"t","ISSUED_TOKEN_TYPE":"urn:ietf:params:oauth:token-type:access_token","TOKEN_TYPE":"Bearer"}`,
		"mixed case":       `{"Access_Token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"}`,
		"repeated member":  `{"access_token":"t","access_token":"u","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"}`,
		"invalid encoding": "{\"access_token\":\"t\xff\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"token_type\":\"Bearer\"}",
	} {
		e := newEndpoint(t, func(w http.ResponseWriter, _ url.Values) { w.Write([]byte(body)) })
		_, err := New(settings(t, e, nil)).Exchange(context.Background(), "governed", callerToken, time.Now().Add(time.Hour))
		var failure *Error
		if !errors.As(err, &failure) || failure.Kind != KindMalformed {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestLifetimeCountsFromRequest(t *testing.T) {
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	// The reply takes 50 seconds of the clock to arrive.
	e := newEndpoint(t, func(w http.ResponseWriter, form url.Values) {
		advance(50 * time.Second)
		issued("issued-token", "100")(w, form)
	})
	c := New(settings(t, e, map[string]string{"EXCHANGE_EXPIRY_MARGIN": "30s"}))
	c.now = clock
	far := now.Add(time.Hour)
	if _, err := c.Exchange(context.Background(), "governed", "a", far); err != nil {
		t.Fatal(err)
	}
	// Issued at the request, so the entry ends 70 seconds after it, not 120.
	advance(21 * time.Second)
	if _, err := c.Exchange(context.Background(), "governed", "a", far); err != nil {
		t.Fatal(err)
	}
	if n := e.requests.Load(); n != 2 {
		t.Fatalf("an entry outlived its token: %d requests", n)
	}
}

func TestUnknownErrorCodesAreNotLogged(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	echoed := "echoed-credential-7"
	e := newEndpoint(t, func(w http.ResponseWriter, _ url.Values) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"` + echoed + `"}`))
	})
	_, err := New(settings(t, e, nil)).Exchange(context.Background(), "governed", callerToken, time.Now().Add(time.Hour))
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != "other" || strings.Contains(logs.String()+err.Error(), echoed) {
		t.Fatalf("got %v; logs %s", err, logs.String())
	}
}

func TestUnreadableProxyListTurnsExchangeOnEverywhere(t *testing.T) {
	for _, proxies := range []string{"", " , ,", ","} {
		env := map[string]string{"EXCHANGE_TOKEN_URL": "https://idp.example.com/token", "EXCHANGE_CLIENT_ID": "g", "EXCHANGE_CLIENT_SECRET": "s", "EXCHANGE_PROXIES": proxies}
		s, err := Load(func(name string) string { return env[name] })
		if err == nil || !s.On("governed") || !s.On("anything") {
			t.Errorf("EXCHANGE_PROXIES %q: %v, on %v", proxies, err, s.On("governed"))
		}
	}
}

func TestTokenWithoutLifetimeServesOneRequest(t *testing.T) {
	release := make(chan struct{})
	e := newEndpoint(t, func(w http.ResponseWriter, form url.Values) {
		<-release
		issued("issued-token", "")(w, form)
	})
	c := New(settings(t, e, nil))
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Exchange(context.Background(), "governed", "a", time.Now().Add(time.Hour)); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	// One shared exchange, then one more for each request that only waited.
	if n := e.requests.Load(); n != 3 {
		t.Fatalf("got %d requests, want 3", n)
	}
}

func TestCacheHitHonoursCallerExpiry(t *testing.T) {
	e := newEndpoint(t, issued("issued-token", "600"))
	c := New(settings(t, e, nil))
	if _, err := c.Exchange(context.Background(), "governed", "a", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	token, err := c.Exchange(context.Background(), "governed", "a", time.Now().Add(-time.Second))
	if token != "" || err == nil {
		t.Fatalf("an expired caller got %q, %v", token, err)
	}
}

func TestHugeLifetimeIsUnknown(t *testing.T) {
	raw := json.RawMessage("9223372036854775807")
	if lifetime(&raw) != 0 {
		t.Fatal("an unrepresentable lifetime was accepted")
	}
}

func TestPortWithoutHostIsRefused(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"token URL": {"EXCHANGE_TOKEN_URL": "https://:443/token", "EXCHANGE_PROXIES": "governed=https://mcp.example.com/mcp"},
		"resource":  {"EXCHANGE_TOKEN_URL": "https://idp.example.com/token", "EXCHANGE_PROXIES": "governed=https://:8443/mcp"},
	} {
		env["EXCHANGE_CLIENT_ID"], env["EXCHANGE_CLIENT_SECRET"] = "g", "s"
		if _, err := Load(func(name string) string { return env[name] }); err == nil {
			t.Errorf("%s with a port and no host was accepted", name)
		}
	}
}
