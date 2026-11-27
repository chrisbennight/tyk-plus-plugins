package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// The OpenID Connect endpoints let an application, such as the review
// dashboard, sign a person from the deck in with the authorization-code flow.
// There are no passwords: whoever opens the sign-in page chooses who to be.
// They are served only when ISSUER_PUBLIC_URL is set and the deck has clients.

// codeLifetime is how long a sign-in code may wait to be exchanged.
const codeLifetime = 60 * time.Second

// maxCodes bounds the sign-in codes waiting to be exchanged, and
// maxParameter the length of each value a sign-in keeps.
const (
	maxCodes     = 1024
	maxParameter = 512
)

// signIn is what a sign-in code stands for until it is exchanged.
type signIn struct {
	client, redirectURI, nonce, person, challenge string
	expires                                       time.Time
}

// oidcEnabled reports whether the OAuth endpoints are served, and answers
// with 404 when they are not.
func (s *server) oidcEnabled(w http.ResponseWriter) bool {
	if s.publicURL == "" || s.deck == nil || len(s.deck.Clients) == 0 {
		http.Error(w, "sign-in is not configured; set ISSUER_PUBLIC_URL and list clients in the deck", http.StatusNotFound)
		return false
	}
	return true
}

func (s *server) discovery(w http.ResponseWriter, _ *http.Request) {
	if !s.oidcEnabled(w) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                s.deck.Issuer,
		"authorization_endpoint":                s.publicURL + "/oauth/authorize",
		"token_endpoint":                        s.publicURL + "/oauth/token",
		"jwks_uri":                              s.publicURL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"grant_types_supported":                 []string{grantAuthorizationCode, grantTokenExchange},
		"scopes_supported":                      []string{"openid", "profile", "groups"},
	})
}

var chooser = template.Must(template.New("chooser").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head>
<body><h1>Sign in as</h1>
<p>Example issuer: anyone who can reach this page can sign in as anyone below.</p>
<ul>{{range .}}<li><a href="{{.URL}}">{{.Name}}</a></li>{{end}}</ul>
</body></html>
`))

// authorize starts a sign-in. A request that names a person in login_hint
// returns to the client at once with a code; otherwise a page lists the deck's
// people to choose from. A request with an unknown client or redirect URI is
// refused without redirecting, so the issuer never sends a browser elsewhere.
func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled(w) {
		return
	}
	q := r.URL.Query()
	c, ok := s.deck.Clients[q.Get("client_id")]
	redirectURI := q.Get("redirect_uri")
	if !ok || !c.allows(grantAuthorizationCode) || !slices.Contains(c.RedirectURIs, redirectURI) {
		http.Error(w, "unknown client or redirect URI", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" {
		http.Error(w, "only response_type=code is supported", http.StatusBadRequest)
		return
	}
	challenge := q.Get("code_challenge")
	if (challenge != "" || q.Has("code_challenge_method")) && (challenge == "" || q.Get("code_challenge_method") != "S256") {
		http.Error(w, "a code challenge needs code_challenge_method=S256, and that method needs a challenge", http.StatusBadRequest)
		return
	}
	if len(challenge) > maxParameter || len(q.Get("nonce")) > maxParameter || len(q.Get("state")) > maxParameter {
		http.Error(w, "state, nonce and code_challenge are limited to 512 bytes each", http.StatusBadRequest)
		return
	}
	person := q.Get("login_hint")
	if _, known := s.deck.People[person]; !known {
		s.choose(w, r)
		return
	}
	code, err := s.issueCode(signIn{client: q.Get("client_id"), redirectURI: redirectURI, nonce: q.Get("nonce"),
		person: person, challenge: challenge, expires: s.now().Add(codeLifetime)})
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	back, _ := url.Parse(redirectURI)
	values := back.Query()
	values.Set("code", code)
	if state := q.Get("state"); state != "" {
		values.Set("state", state)
	}
	back.RawQuery = values.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, back.String(), http.StatusFound)
}

// choose lists the deck's people, each a link to the same sign-in for them.
func (s *server) choose(w http.ResponseWriter, r *http.Request) {
	type choice struct{ Name, URL string }
	var choices []choice
	for name := range s.deck.People {
		q := r.URL.Query()
		q.Set("login_hint", name)
		choices = append(choices, choice{Name: name, URL: "/oauth/authorize?" + q.Encode()})
	}
	slices.SortFunc(choices, func(a, b choice) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	chooser.Execute(w, choices)
}

// issueCode stores a sign-in under a new random code.
func (s *server) issueCode(in signIn) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	code := b64(random)
	s.codesMu.Lock()
	defer s.codesMu.Unlock()
	now := s.now()
	for c, waiting := range s.codes {
		if !now.Before(waiting.expires) {
			delete(s.codes, c)
		}
	}
	if len(s.codes) >= maxCodes {
		return "", errTooManySignIns
	}
	s.codes[code] = in
	return code, nil
}

var errTooManySignIns = errors.New("too many sign-ins are waiting; try again shortly")

// token is the OAuth token endpoint. It authenticates the client, then
// handles the grant the request names, if the client may use it.
func (s *server) token(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	// A parameter sent without a value is treated as omitted, and a parameter
	// may appear only once (RFC 6749 section 3.2). resource and audience may
	// repeat under RFC 8693; the token-exchange grant refuses more than one
	// target itself.
	for name, values := range r.PostForm {
		values = slices.DeleteFunc(values, func(v string) bool { return v == "" })
		if len(values) == 0 {
			delete(r.PostForm, name)
			continue
		}
		r.PostForm[name] = values
		if len(values) > 1 && name != "resource" && name != "audience" {
			tokenError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	scheme, _, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	basic := strings.EqualFold(scheme, "Basic")
	// A client may use only one authentication method per request (RFC 6749
	// sections 2.3 and 5.2).
	if basic && r.PostForm.Has("client_secret") {
		tokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	clientID, ok := s.authenticate(r, basic)
	if !ok {
		// A client that tried HTTP Basic is answered with a challenge for
		// that scheme (RFC 6749 section 5.2).
		if basic {
			w.Header().Set("WWW-Authenticate", `Basic realm="example issuer"`)
		}
		tokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch grant := r.PostForm.Get("grant_type"); grant {
	case grantAuthorizationCode, grantTokenExchange:
		if !s.deck.Clients[clientID].allows(grant) {
			tokenError(w, http.StatusBadRequest, "unauthorized_client")
			return
		}
		if grant == grantAuthorizationCode {
			s.redeemCode(w, r, clientID)
		} else {
			s.exchangeToken(w, r, clientID)
		}
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

// authenticate returns the client a request authenticates as: by HTTP Basic
// when the request tried it, even with a malformed header, and otherwise by
// the client_id and client_secret form parameters.
func (s *server) authenticate(r *http.Request, basic bool) (clientID string, ok bool) {
	var secret string
	if basic {
		var parsed bool
		if clientID, secret, parsed = r.BasicAuth(); !parsed {
			return "", false
		}
		// HTTP Basic carries the client ID and secret form-encoded
		// (RFC 6749 section 2.3.1).
		var idErr, secretErr error
		clientID, idErr = url.QueryUnescape(clientID)
		secret, secretErr = url.QueryUnescape(secret)
		if idErr != nil || secretErr != nil {
			return "", false
		}
	} else {
		clientID, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	c, known := s.deck.Clients[clientID]
	if !known || subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 {
		return "", false
	}
	return clientID, true
}

// redeemCode turns a sign-in code into tokens for the client it was issued
// to. A code works once, only before it expires, and only with the redirect
// URI and code verifier of its sign-in.
func (s *server) redeemCode(w http.ResponseWriter, r *http.Request, clientID string) {
	// The code is removed before it is checked, so it cannot be used twice,
	// even by a failed attempt.
	code := r.PostForm.Get("code")
	s.codesMu.Lock()
	in, found := s.codes[code]
	delete(s.codes, code)
	s.codesMu.Unlock()
	if !found || !s.now().Before(in.expires) || in.client != clientID || in.redirectURI != r.PostForm.Get("redirect_uri") ||
		!verifierMatches(in.challenge, r.PostForm.Get("code_verifier")) {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	// The ID token carries the sign-in's nonce, or none; never one from the deck.
	extra := map[string]any{"nonce": in.nonce}
	if in.nonce == "" {
		extra["nonce"] = nil
	}
	idClaims, err := s.personClaims(in.person, clientID, extra)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The access token follows the JWT access token profile: it names the
	// client and has a unique ID (RFC 9068 section 2.2).
	jti, err := randomID()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	accessClaims, err := s.personClaims(in.person, s.deck.Audience, map[string]any{"client_id": clientID, "jti": jti})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idToken, err := sign(s.published, s.keyID, typJWT, idClaims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	accessToken, err := sign(s.published, s.keyID, typAccessJWT, accessClaims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeTokens(w, map[string]any{"access_token": accessToken, "id_token": idToken,
		"token_type": "Bearer", "expires_in": s.deck.LifetimeSeconds})
}

// writeTokens writes a successful token response, which must not be cached
// (RFC 6749 section 5.1).
func writeTokens(w http.ResponseWriter, response map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

// verifierMatches checks a PKCE code verifier against the sign-in's
// challenge. A sign-in without a challenge needs no verifier.
func verifierMatches(challenge, verifier string) bool {
	if challenge == "" {
		return verifier == ""
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier != "" && subtle.ConstantTimeCompare([]byte(b64(sum[:])), []byte(challenge)) == 1
}

func tokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}
