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
package main

import (
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
	"os"
	"regexp"
	"strings"
	"time"
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
	// O_EXCL keeps a second issuer sharing the file from replacing a key the
	// first already published.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return nil, err
	}
	return key, f.Close()
}

// deck lists the example people the issuer can sign tokens for, by name.
type deck struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// LifetimeSeconds is how long a person's token stays valid.
	LifetimeSeconds int64                     `json:"lifetimeSeconds"`
	People          map[string]map[string]any `json:"people"`
}

var personName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// reserved claims are set from the deck itself, so a person cannot override them.
var reserved = []string{"iss", "aud", "exp", "iat", "nbf"}

func loadDeck(path string) (*deck, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var d deck
	if err := dec.Decode(&d); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("unexpected data after the deck")
	}
	if name, err := duplicatePerson(f); err != nil || name != "" {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("person %q is listed twice", name)
	}
	switch {
	case d.Issuer == "":
		return nil, errors.New("issuer is required")
	case d.Audience == "":
		return nil, errors.New("audience is required")
	case d.LifetimeSeconds <= 0:
		return nil, errors.New("lifetimeSeconds must be positive")
	case len(d.People) == 0:
		return nil, errors.New("people must list at least one person")
	}
	for name, claims := range d.People {
		if !personName.MatchString(name) {
			return nil, fmt.Errorf("person %q: names use lowercase letters, digits and hyphens", name)
		}
		for _, claim := range reserved {
			if _, ok := claims[claim]; ok {
				return nil, fmt.Errorf("person %q: %q is set by the deck, not per person", name, claim)
			}
		}
		if sub, ok := claims["sub"]; ok {
			if s, isString := sub.(string); !isString || s == "" {
				return nil, fmt.Errorf("person %q: sub must be a non-empty string", name)
			}
		}
	}
	return &d, nil
}

// duplicatePerson rereads the deck and returns a name listed twice under
// "people". The standard decoder silently keeps the last entry of a repeated
// key, which would hide one of the two people.
func duplicatePerson(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	var top struct{ People json.RawMessage }
	if err := json.NewDecoder(f).Decode(&top); err != nil {
		return "", err
	}
	dec := json.NewDecoder(strings.NewReader(string(top.People)))
	if _, err := dec.Token(); err != nil { // the opening brace
		return "", err
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		name, _ := tok.(string)
		if seen[name] {
			return name, nil
		}
		seen[name] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return "", err
		}
	}
	return "", nil
}

type server struct {
	deck *deck
	now  func() time.Time
	// published signs tokens the gateway accepts. unpublished signs tokens
	// that carry the same key ID but that the gateway must reject.
	published, unpublished *rsa.PrivateKey
	keyID                  string
	mux                    *http.ServeMux
}

func newServer(d *deck, published *rsa.PrivateKey, now func() time.Time) (*server, error) {
	unpublished, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	s := &server{deck: d, now: now, published: published, unpublished: unpublished, keyID: thumbprint(&published.PublicKey), mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	s.mux.HandleFunc("GET /jwks", s.jwks)
	s.mux.HandleFunc("POST /token", s.signBody)
	s.mux.HandleFunc("GET /token/{name}", s.signPerson)
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
	var claims map[string]any
	if json.Unmarshal(body, &claims) != nil || claims == nil {
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
	person, ok := s.deck.People[name]
	if !ok {
		http.Error(w, "no person named "+name+" in the deck", http.StatusNotFound)
		return
	}
	now := s.now()
	claims := map[string]any{"sub": name}
	for k, v := range person {
		claims[k] = v
	}
	claims["iss"] = s.deck.Issuer
	claims["aud"] = s.deck.Audience
	claims["iat"] = now.Unix()
	claims["exp"] = now.Unix() + s.deck.LifetimeSeconds
	body, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.write(w, r, body)
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
