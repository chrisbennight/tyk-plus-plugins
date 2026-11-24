package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validDeck = `{
  "issuer": "https://issuer.example",
  "audience": "governed-mcp",
  "lifetimeSeconds": 600,
  "people": {
    "analyst": {"roles": ["analyst"], "tier": 2},
    "scoped": {"sub": "svc-7", "scope": "read write"}
  }
}`

func writeDeck(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deck.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDeckRejectsMistakes(t *testing.T) {
	for name, content := range map[string]string{
		"unknown field":         `{"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"p":{}},"extra":1}`,
		"trailing data":         `{"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"p":{}}} {}`,
		"no issuer":             `{"audience":"a","lifetimeSeconds":1,"people":{"p":{}}}`,
		"no audience":           `{"issuer":"i","lifetimeSeconds":1,"people":{"p":{}}}`,
		"zero lifetime":         `{"issuer":"i","audience":"a","lifetimeSeconds":0,"people":{"p":{}}}`,
		"negative lifetime":     `{"issuer":"i","audience":"a","lifetimeSeconds":-5,"people":{"p":{}}}`,
		"no people":             `{"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{}}`,
		"bad name":              `{"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"Alice Smith":{}}}`,
		"reserved claim":        `{"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"p":{"exp":1}}}`,
		"empty subject":         `{"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"p":{"sub":""}}}`,
		"numeric subject":       `{"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"p":{"sub":7}}}`,
		"repeated people field": `{"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"p":{}},"people":{"p":{"roles":["admin"]}}}`,
		"missing people":        `{"issuer":"i","audience":"a","lifetimeSeconds":1}`,
		"stray closing bracket": `{"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"p":{}}} ]`,
		"lifetime over a year":  `{"issuer":"i","audience":"a","lifetimeSeconds":31536001,"people":{"p":{}}}`,
		"null claims":           `{"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"p":null}}`,
		"duplicate person":      `{"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"p":{},"p":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadDeck(writeDeck(t, content)); err == nil {
				t.Fatal("deck accepted")
			}
		})
	}
}

func newTestServer(t *testing.T, now time.Time) *server {
	t.Helper()
	d, err := loadDeck(writeDeck(t, validDeck))
	if err != nil {
		t.Fatal(err)
	}
	key, err := publishedKey("")
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServer(d, key, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func get(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
	return rec
}

// verify checks a token against the published key set the way a gateway would
// and returns its header and claims.
func verify(t *testing.T, s *server, token string) (header, claims map[string]any, ok bool) {
	t.Helper()
	var set struct{ Keys []map[string]string }
	if err := json.Unmarshal(get(t, s, http.MethodGet, "/jwks", "").Body.Bytes(), &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("key set: %v", err)
	}
	jwk := set.Keys[0]
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	json.Unmarshal(decode(parts[0]), &header)
	json.Unmarshal(decode(parts[1]), &claims)
	if header["kid"] != jwk["kid"] {
		t.Fatalf("token key ID %v, published %v", header["kid"], jwk["kid"])
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(decode(jwk["n"])), E: int(new(big.Int).SetBytes(decode(jwk["e"])).Int64())}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return header, claims, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], decode(parts[2])) == nil
}

func TestPersonToken(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := newTestServer(t, now)
	rec := get(t, s, http.MethodGet, "/token/analyst", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d, cache %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	header, claims, ok := verify(t, s, rec.Body.String())
	if !ok {
		t.Fatal("published key does not verify the token")
	}
	if header["alg"] != "RS256" {
		t.Fatalf("alg %v", header["alg"])
	}
	want := map[string]any{"iss": "https://issuer.example", "aud": "governed-mcp", "sub": "analyst",
		"iat": float64(now.Unix()), "exp": float64(now.Unix() + 600), "tier": float64(2)}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("%s = %v, want %v", k, claims[k], v)
		}
	}
	if roles, _ := claims["roles"].([]any); len(roles) != 1 || roles[0] != "analyst" {
		t.Errorf("roles = %v", claims["roles"])
	}

	// A deck subject replaces the name, and a scope stays one string.
	_, claims, _ = verify(t, s, get(t, s, http.MethodGet, "/token/scoped", "").Body.String())
	if claims["sub"] != "svc-7" || claims["scope"] != "read write" {
		t.Errorf("scoped claims = %v", claims)
	}
}

func TestTokenRefusals(t *testing.T) {
	s := newTestServer(t, time.Now())
	for name, c := range map[string]struct {
		method, target, body string
		status               int
	}{
		"unknown person":    {http.MethodGet, "/token/nobody", "", http.StatusNotFound},
		"wrong method":      {http.MethodPut, "/token", `{}`, http.StatusMethodNotAllowed},
		"claims not object": {http.MethodPost, "/token", `["sub"]`, http.StatusBadRequest},
		"claims null":       {http.MethodPost, "/token", `null`, http.StatusBadRequest},
		"claims not JSON":   {http.MethodPost, "/token", `sub=alice`, http.StatusBadRequest},
		"claims too large":  {http.MethodPost, "/token", `{"x":"` + strings.Repeat("a", 70<<10) + `"}`, http.StatusRequestEntityTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			if rec := get(t, s, c.method, c.target, c.body); rec.Code != c.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.status, rec.Body)
			}
		})
	}

	key, err := publishedKey("")
	if err != nil {
		t.Fatal(err)
	}
	noDeck, err := newServer(nil, key, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if rec := get(t, noDeck, http.MethodGet, "/token/analyst", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("without a deck: status %d", rec.Code)
	}
}

// Tests build tokens the gateway must refuse from claims they choose; those
// claims are signed exactly as given.
func TestBodyClaimsSignedAsGiven(t *testing.T) {
	s := newTestServer(t, time.Now())
	body := `{"iss":"https://issuer.test","sub":"alice","exp":1}`
	_, claims, ok := verify(t, s, get(t, s, http.MethodPost, "/token", body).Body.String())
	if !ok || claims["exp"] != float64(1) || claims["aud"] != nil {
		t.Fatalf("verified %v, claims %v", ok, claims)
	}
}

func TestUnpublishedKeyFailsVerification(t *testing.T) {
	s := newTestServer(t, time.Now())
	for _, target := range []string{"/token/analyst?key=unpublished"} {
		if _, _, ok := verify(t, s, get(t, s, http.MethodGet, target, "").Body.String()); ok {
			t.Fatalf("%s verified with the published key", target)
		}
	}
	if _, _, ok := verify(t, s, get(t, s, http.MethodPost, "/token?key=unpublished", `{"sub":"a"}`).Body.String()); ok {
		t.Fatal("body token verified with the published key")
	}
}

func TestEachStartHasItsOwnKeyID(t *testing.T) {
	a, b := newTestServer(t, time.Now()), newTestServer(t, time.Now())
	if a.keyID == b.keyID || a.keyID == "" {
		t.Fatalf("key IDs %q and %q", a.keyID, b.keyID)
	}
}

// A key file keeps the key, and so the key ID a gateway has cached, across restarts.
func TestKeyFileKeepsTheKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issuer.pem")
	first, err := publishedKey(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v, mode %v", err, info.Mode().Perm())
	}
	again, err := publishedKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if thumbprint(&first.PublicKey) != thumbprint(&again.PublicKey) {
		t.Fatal("a second start read a different key")
	}
}

func TestKeyFileMustHoldAnRSAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issuer.pem")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publishedKey(path); err == nil {
		t.Fatal("accepted a file with no key")
	}
}

func TestLoopbackAddresses(t *testing.T) {
	for host, want := range map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true, "": false, "0.0.0.0": false, "issuer": false} {
		if isLoopback(host) != want {
			t.Errorf("isLoopback(%q) = %v", host, !want)
		}
	}
}

// A test can sign any JSON object exactly as written, including numbers no
// float64 can hold.
func TestBodyNumbersAreSignedAsWritten(t *testing.T) {
	s := newTestServer(t, time.Now())
	body := `{"sub":"alice","n":123456789012345678901234567890}`
	rec := get(t, s, http.MethodPost, "/token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(rec.Body.String(), ".")[1])
	if err != nil || string(payload) != body {
		t.Fatalf("signed %q, want %q", payload, body)
	}
}

// Creating the key file never replaces an existing file and leaves nothing
// behind when it cannot complete.
func TestKeyFileCreationIsAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "issuer.pem")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createExclusive(path, []byte("second")); err == nil {
		t.Fatal("replaced an existing key file")
	}
	if got, _ := os.ReadFile(path); string(got) != "first" {
		t.Fatalf("key file now holds %q", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left %d files behind", len(entries))
	}
}

// A deck claim is signed exactly as the deck writes it, even a number no
// float64 can hold.
func TestDeckNumbersAreSignedAsWritten(t *testing.T) {
	d, err := loadDeck(writeDeck(t, `{"issuer":"i","audience":"a","lifetimeSeconds":60,"people":{"p":{"id":9007199254740993}}}`))
	if err != nil {
		t.Fatal(err)
	}
	key, err := publishedKey("")
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServer(d, key, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(get(t, s, http.MethodGet, "/token/p", "").Body.String(), ".")[1])
	if err != nil || !strings.Contains(string(payload), `"id":9007199254740993`) {
		t.Fatalf("payload %s, %v", payload, err)
	}
}
