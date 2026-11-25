// Command issuer signs tokens for the examples and the integration tests and
// publishes its key as a JSON Web Key Set, so the gateway can verify tokens
// without an external identity provider.
//
// It is not an identity provider. Anyone who can reach it can obtain a token
// with any claims, so it must only be reachable on a local or test network.
//
// Settings, all optional:
//
//	ISSUER_DECK      a JSON deck of example people; enables GET /token/{name}
//	ISSUER_KEY_FILE  a PKCS #8 PEM signing key, created if missing, so restarts keep the key
//	ISSUER_LISTEN    the listening address; defaults to 127.0.0.1:8000
//	ISSUER_PUBLIC_URL the base URL browsers use to reach the issuer; enables
//	                 the OpenID Connect sign-in endpoints for the deck's clients
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

func main() {
	var d *deck
	if path := os.Getenv("ISSUER_DECK"); path != "" {
		var err error
		if d, err = loadDeck(path); err != nil {
			log.Fatalf("deck %s: %v", path, err)
		}
	}
	published, err := publishedKey(os.Getenv("ISSUER_KEY_FILE"))
	if err != nil {
		log.Fatalf("key file: %v", err)
	}
	s, err := newServer(d, published, time.Now)
	if err != nil {
		log.Fatal(err)
	}
	s.publicURL = strings.TrimSuffix(os.Getenv("ISSUER_PUBLIC_URL"), "/")
	addr := os.Getenv("ISSUER_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8000"
	}
	if host, _, _ := net.SplitHostPort(addr); !isLoopback(host) {
		log.Printf("WARNING: listening on %s. Anyone who can reach this address can obtain a token with any claims; keep it on a local or test network.", addr)
	}
	log.Fatal(http.ListenAndServe(addr, s))
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// publishedKey reads the signing key from path, or generates one and saves it
// there, so a restarted issuer keeps the key a gateway has cached. With no path
// each start generates a new key.
func publishedKey(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%s holds no PEM block", path)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s does not hold an RSA key", path)
		}
		return key, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := createExclusive(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
}

// createExclusive writes data to path only if nothing is there yet, and never
// leaves a partly written file at path. The data goes to a temporary file in
// the same directory first; linking it into place fails if path exists, so a
// second issuer sharing the file cannot replace a key the first published.
func createExclusive(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".issuer-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Link(tmp.Name(), path)
}

// deck lists the example people the issuer can sign tokens for, by name.
type deck struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// LifetimeSeconds is how long a person's token stays valid.
	LifetimeSeconds int64 `json:"lifetimeSeconds"`
	// People keeps each claim as written, so a token carries exactly the value
	// the deck sets, numbers included.
	People map[string]map[string]jsontext.Value `json:"people"`
	// Clients are the applications that may sign people in through the
	// OpenID Connect endpoints, by client ID.
	Clients map[string]client `json:"clients"`
}

// client is an application that signs people in. A sign-in returns only to
// one of its redirect URIs, compared exactly.
type client struct {
	Secret       string   `json:"secret"`
	RedirectURIs []string `json:"redirectURIs"`
}

var personName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// reserved claims are set from the deck itself, so a person cannot override them.
var reserved = []string{"iss", "aud", "exp", "iat", "nbf"}

// maxLifetimeSeconds bounds a token's lifetime. Example tokens never need more
// than a year, and the bound keeps iat plus the lifetime well inside int64.
const maxLifetimeSeconds = 365 * 24 * 60 * 60

func loadDeck(path string) (*deck, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// This decoder rejects a name repeated anywhere in the deck, a field it does
	// not know and data after the deck, so a typo cannot silently change a token.
	var d deck
	if err := jsonv2.Unmarshal(data, &d, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	switch {
	case d.Issuer == "":
		return nil, errors.New("issuer is required")
	case d.Audience == "":
		return nil, errors.New("audience is required")
	case d.LifetimeSeconds <= 0 || d.LifetimeSeconds > maxLifetimeSeconds:
		return nil, fmt.Errorf("lifetimeSeconds must be between 1 and %d", maxLifetimeSeconds)
	case len(d.People) == 0:
		return nil, errors.New("people must list at least one person")
	}
	for name, claims := range d.People {
		if !personName.MatchString(name) {
			return nil, fmt.Errorf("person %q: names use lowercase letters, digits and hyphens", name)
		}
		if claims == nil {
			return nil, fmt.Errorf("person %q: claims must be an object, even an empty one", name)
		}
		for _, claim := range reserved {
			if _, ok := claims[claim]; ok {
				return nil, fmt.Errorf("person %q: %q is set by the deck, not per person", name, claim)
			}
		}
		if sub, ok := claims["sub"]; ok {
			var s string
			if jsonv2.Unmarshal(sub, &s) != nil || s == "" {
				return nil, fmt.Errorf("person %q: sub must be a non-empty string", name)
			}
		}
	}
	for id, c := range d.Clients {
		if !personName.MatchString(id) {
			return nil, fmt.Errorf("client %q: names use lowercase letters, digits and hyphens", id)
		}
		if c.Secret == "" || len(c.RedirectURIs) == 0 {
			return nil, fmt.Errorf("client %q: a secret and at least one redirect URI are required", id)
		}
		for _, uri := range c.RedirectURIs {
			if u, err := url.Parse(uri); err != nil || !u.IsAbs() || u.Fragment != "" {
				return nil, fmt.Errorf("client %q: redirect URI %q must be an absolute URL without a fragment", id, uri)
			}
		}
	}
	return &d, nil
}

type server struct {
	deck *deck
	now  func() time.Time
	// published signs tokens the gateway accepts. unpublished signs tokens
	// that carry the same key ID but that the gateway must reject.
	published, unpublished *rsa.PrivateKey
	keyID                  string
	mux                    *http.ServeMux
	// publicURL is where browsers reach the issuer. Without it the OpenID
	// Connect endpoints are not served.
	publicURL string
	// codes holds the sign-in codes issued and not yet exchanged.
	codesMu sync.Mutex
	codes   map[string]signIn
}

func newServer(d *deck, published *rsa.PrivateKey, now func() time.Time) (*server, error) {
	unpublished, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	s := &server{deck: d, now: now, published: published, unpublished: unpublished, keyID: thumbprint(&published.PublicKey), mux: http.NewServeMux(),
		codes: map[string]signIn{}}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	s.mux.HandleFunc("GET /jwks", s.jwks)
	s.mux.HandleFunc("POST /token", s.signBody)
	s.mux.HandleFunc("GET /token/{name}", s.signPerson)
	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	s.mux.HandleFunc("GET /oauth/authorize", s.authorize)
	s.mux.HandleFunc("POST /oauth/token", s.exchange)
	return s, nil
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *server) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"keys": []any{publicJWK(&s.published.PublicKey, s.keyID)}})
}

// signBody signs exactly the claims in the request body, so tests can build
// tokens the gateway must refuse, such as expired ones or ones without a subject.
func (s *server) signBody(w http.ResponseWriter, r *http.Request) {
	const maxBody = 64 << 10
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "claims must be at most 64 KiB", http.StatusRequestEntityTooLarge)
		return
	}
	// Check the shape only, without decoding numbers, so a test can sign any
	// JSON object exactly as written.
	if !json.Valid(body) || !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		http.Error(w, "claims must be a JSON object", http.StatusBadRequest)
		return
	}
	s.write(w, r, body)
}

// signPerson signs a token for a person in the deck.
func (s *server) signPerson(w http.ResponseWriter, r *http.Request) {
	if s.deck == nil {
		http.Error(w, "no deck is loaded; set ISSUER_DECK", http.StatusNotFound)
		return
	}
	name := r.PathValue("name")
	if _, ok := s.deck.People[name]; !ok {
		http.Error(w, "no person named "+name+" in the deck", http.StatusNotFound)
		return
	}
	body, err := s.personClaims(name, s.deck.Audience, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.write(w, r, body)
}

// personClaims are the claims of a token for a person in the deck, for an
// audience, with any extra claims such as a sign-in's nonce.
func (s *server) personClaims(name, audience string, extra map[string]any) ([]byte, error) {
	now := s.now()
	claims := map[string]any{"sub": name}
	for k, v := range s.deck.People[name] {
		claims[k] = v
	}
	for k, v := range extra {
		claims[k] = v
	}
	claims["iss"] = s.deck.Issuer
	claims["aud"] = audience
	claims["iat"] = now.Unix()
	claims["exp"] = now.Unix() + s.deck.LifetimeSeconds
	return jsonv2.Marshal(claims)
}

func (s *server) write(w http.ResponseWriter, r *http.Request, claims []byte) {
	key := s.published
	if r.URL.Query().Get("key") == "unpublished" {
		key = s.unpublished
	}
	token, err := sign(key, s.keyID, claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, token)
}

var b64 = base64.RawURLEncoding.EncodeToString

func sign(key *rsa.PrivateKey, keyID string, claims []byte) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": keyID})
	signed := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signed + "." + b64(signature), nil
}

func publicJWK(key *rsa.PublicKey, keyID string) map[string]string {
	return map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": keyID,
		"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}
}

// thumbprint is the key's RFC 7638 thumbprint. Each start generates a new key
// and so a new key ID, which a verifier can tell apart from a key it cached
// before the issuer restarted.
func thumbprint(key *rsa.PublicKey) string {
	// RFC 7638 requires these members, in this order, with no whitespace.
	canonical := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, b64(big.NewInt(int64(key.E)).Bytes()), b64(key.N.Bytes()))
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}
