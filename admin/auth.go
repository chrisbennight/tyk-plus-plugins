package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// role is what a signed-in operator may do.
type role int

const (
	// viewer sees every page.
	viewer role = iota + 1
	// reviewer may also make decisions.
	reviewer
)

func (r role) String() string {
	if r == reviewer {
		return "reviewer"
	}
	return "viewer"
}

// session is a signed-in operator. Sessions are held in memory, so a restart
// signs everyone out.
type session struct {
	actor   policy.Actor
	role    role
	csrf    string
	expires time.Time
}

// loginState is a sign-in started in this browser and not yet finished. It
// travels in the browser's login cookie, which is HttpOnly and lasts at most
// loginTimeout, so the dashboard keeps nothing for sign-ins that never
// finish.
type loginState struct {
	state, nonce, verifier, next string
	started                      time.Time
}

func (l loginState) encode() string {
	parts := []string{l.state, l.nonce, l.verifier, l.next, strconv.FormatInt(l.started.Unix(), 10)}
	for i, p := range parts {
		parts[i] = base64.RawURLEncoding.EncodeToString([]byte(p))
	}
	return strings.Join(parts, ".")
}

func decodeLogin(value string) (loginState, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 5 {
		return loginState{}, false
	}
	for i, p := range parts {
		decoded, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			return loginState{}, false
		}
		parts[i] = string(decoded)
	}
	started, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		return loginState{}, false
	}
	return loginState{state: parts[0], nonce: parts[1], verifier: parts[2], next: localPath(parts[3]), started: time.Unix(started, 0)}, true
}

const (
	sessionCookie = "admin_session"
	loginCookie   = "admin_login"
	// loginTimeout bounds how long a sign-in may take at the identity
	// provider, and maxSession how long a session lasts.
	loginTimeout = 10 * time.Minute
	maxSession   = 8 * time.Hour
)

// auth signs operators in with OpenID Connect: the authorization code flow
// with PKCE, a nonce bound to the browser, and a verified ID token. The
// dashboard trusts no identity header; only the identity provider's signed
// token decides who an operator is, and its groups claim what they may do.
type auth struct {
	cfg    config
	public *url.URL

	mu       sync.Mutex
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	// client makes every request to the identity provider.
	client   *http.Client
	sessions map[string]*session
	now      func() time.Time
}

func newAuth(cfg config, public *url.URL) *auth {
	return &auth{cfg: cfg, public: public, client: providerClient(cfg), sessions: map[string]*session{}, now: time.Now}
}

// providerClient makes the client for every request to the identity
// provider: discovery, keys and the code exchange.
func providerClient(cfg config) *http.Client {
	// The provider's configuration and keys are the trust root for every
	// signed-in identity, so they are fetched only over https, redirects
	// included, unless an operator allows otherwise on a test network.
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" && !cfg.insecureProvider {
			return fmt.Errorf("refusing a redirect to %s, which is not https", req.URL.Redacted())
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}}
}

// connect discovers the identity provider once and keeps the result, so the
// dashboard starts even while the provider is not yet reachable.
func (a *auth) connect(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.provider != nil {
		return a.oauth, a.verifier, nil
	}
	ctx = oidc.ClientContext(ctx, a.client)
	discovery := a.cfg.issuer
	if a.cfg.discoveryURL != "" {
		// The provider is reached at another address than the issuer it
		// names, as on a private network; tokens must still name the issuer.
		ctx = oidc.InsecureIssuerURLContext(ctx, a.cfg.issuer)
		discovery = a.cfg.discoveryURL
	}
	provider, err := oidc.NewProvider(ctx, discovery)
	if err != nil {
		return nil, nil, fmt.Errorf("identity provider: %w", err)
	}
	var keys struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&keys); err != nil {
		return nil, nil, fmt.Errorf("identity provider: %w", err)
	}
	// The browser is sent to the authorization endpoint, the client secret to
	// the token endpoint, and ID tokens are verified with the keys.
	for name, endpoint := range map[string]string{"authorization": provider.Endpoint().AuthURL, "token": provider.Endpoint().TokenURL, "keys": keys.JWKSURI} {
		if strings.HasPrefix(endpoint, "https://") {
			continue
		}
		if !a.cfg.insecureProvider {
			return nil, nil, fmt.Errorf("identity provider: the %s endpoint %s is not https; set ADMIN_OIDC_ALLOW_INSECURE_HTTP=true only on a local or test network", name, endpoint)
		}
		slog.Warn("An identity provider endpoint is not https, as ADMIN_OIDC_ALLOW_INSECURE_HTTP allows.", "endpoint", name, "url", endpoint)
	}
	a.provider = provider
	a.verifier = provider.Verifier(&oidc.Config{ClientID: a.cfg.clientID})
	a.oauth = &oauth2.Config{
		ClientID:     a.cfg.clientID,
		ClientSecret: a.cfg.clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  a.link("/callback"),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "groups"},
	}
	return a.oauth, a.verifier, nil
}

// link returns the public URL of a dashboard path.
func (a *auth) link(path string) string {
	return strings.TrimSuffix(a.public.String(), "/") + path
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *auth) cookie(name, value string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: a.public.Path + "/", HttpOnly: true, Secure: a.public.Scheme == "https",
		SameSite: http.SameSiteLaxMode, MaxAge: int(maxAge / time.Second),
	}
}

// current returns the request's session, if it has a live one.
func (a *auth) current(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[c.Value]
	if s == nil || a.now().After(s.expires) {
		delete(a.sessions, c.Value)
		return nil
	}
	return s
}

// login starts a sign-in and sends the browser to the identity provider.
func (a *auth) login(w http.ResponseWriter, r *http.Request) {
	oauth, _, err := a.connect(r.Context())
	if err != nil {
		slog.Error("Sign-in is unavailable", "error", err)
		http.Error(w, "Sign-in is unavailable: the identity provider cannot be reached.", http.StatusServiceUnavailable)
		return
	}
	l := loginState{state: randomToken(), nonce: randomToken(), verifier: oauth2.GenerateVerifier(),
		next: localPath(r.URL.Query().Get("next")), started: a.now()}
	http.SetCookie(w, a.cookie(loginCookie, l.encode(), loginTimeout))
	http.Redirect(w, r, oauth.AuthCodeURL(l.state, oidc.Nonce(l.nonce), oauth2.S256ChallengeOption(l.verifier)), http.StatusFound)
}

// expire forgets expired sessions. The caller holds the lock.
func (a *auth) expire() {
	now := a.now()
	for id, s := range a.sessions {
		if now.After(s.expires) {
			delete(a.sessions, id)
		}
	}
}

// localPath keeps a return path only when it stays within the dashboard.
func localPath(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") || hasDotSegment(next) {
		return "/"
	}
	return next
}

// hasDotSegment reports whether a path has a "." or ".." segment, written
// plainly or percent-encoded, which a browser would resolve, possibly to
// somewhere outside the dashboard.
func hasDotSegment(next string) bool {
	p, _, _ := strings.Cut(next, "?")
	p, err := url.PathUnescape(p)
	if err != nil {
		return true
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// claims are the ID token's claims the dashboard reads; the groups claim is
// read separately, as its name is configured.
type claims struct {
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
}

// callback finishes a sign-in: the browser must bring back the state it was
// given, the code is exchanged with the PKCE verifier, and the ID token must
// verify and carry the nonce.
func (a *auth) callback(w http.ResponseWriter, r *http.Request) {
	oauth, verifier, err := a.connect(r.Context())
	if err != nil {
		http.Error(w, "Sign-in is unavailable: the identity provider cannot be reached.", http.StatusServiceUnavailable)
		return
	}
	state := r.URL.Query().Get("state")
	var l loginState
	ok := false
	if c, err := r.Cookie(loginCookie); err == nil {
		l, ok = decodeLogin(c.Value)
	}
	http.SetCookie(w, a.cookie(loginCookie, "", -time.Second))
	if !ok || state == "" || subtle.ConstantTimeCompare([]byte(l.state), []byte(state)) != 1 || a.now().After(l.started.Add(loginTimeout)) {
		http.Error(w, "This sign-in has expired or was not started in this browser. Sign in again.", http.StatusBadRequest)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		http.Error(w, "The identity provider refused the sign-in.", http.StatusForbidden)
		return
	}
	// The exchange sends the client secret, so it uses the provider client
	// and its rule on redirects.
	ctx := oidc.ClientContext(r.Context(), a.client)
	token, err := oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(l.verifier))
	if err != nil {
		slog.Warn("Sign-in code exchange failed", "error", err)
		http.Error(w, "The sign-in could not be completed. Sign in again.", http.StatusBadRequest)
		return
	}
	raw, _ := token.Extra("id_token").(string)
	idToken, err := verifier.Verify(ctx, raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(l.nonce)) != 1 {
		slog.Warn("Sign-in ID token refused", "error", err)
		http.Error(w, "The identity provider's token could not be verified.", http.StatusForbidden)
		return
	}
	var named claims
	var all map[string]any
	if err := idToken.Claims(&named); err != nil || idToken.Claims(&all) != nil {
		http.Error(w, "The identity provider's token could not be read.", http.StatusForbidden)
		return
	}
	granted, ok := a.roleOf(groupsOf(all[a.cfg.groupsClaim]))
	actor := policy.Actor{Issuer: idToken.Issuer, Subject: idToken.Subject, Name: firstOf(named.Name, named.PreferredUsername, named.Email, idToken.Subject)}
	if !ok {
		slog.Info("Sign-in refused: no dashboard role", "issuer", actor.Issuer, "subject", actor.Subject)
		http.Error(w, "You are signed in, but your account has no access to the review dashboard.", http.StatusForbidden)
		return
	}
	expires := a.now().Add(maxSession)
	if idToken.Expiry.Before(expires) {
		expires = idToken.Expiry
	}
	id := randomToken()
	a.mu.Lock()
	a.expire()
	a.sessions[id] = &session{actor: actor, role: granted, csrf: randomToken(), expires: expires}
	a.mu.Unlock()
	slog.Info("Signed in", "issuer", actor.Issuer, "subject", actor.Subject, "role", granted.String())
	http.SetCookie(w, a.cookie(sessionCookie, id, expires.Sub(a.now())))
	http.Redirect(w, r, a.link(l.next), http.StatusFound)
}

// logout ends the session.
func (a *auth) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, a.cookie(sessionCookie, "", -time.Second))
	http.Redirect(w, r, a.link("/signed-out"), http.StatusSeeOther)
}

// roleOf grants the reviewer role to members of the reviewer group, and the
// viewer role to members of the viewer group.
func (a *auth) roleOf(groups []string) (role, bool) {
	switch {
	case slices.Contains(groups, a.cfg.reviewerGroup):
		return reviewer, true
	case a.cfg.viewerGroup != "" && slices.Contains(groups, a.cfg.viewerGroup):
		return viewer, true
	}
	return 0, false
}

// groupsOf reads a groups claim: a list of names, or one name.
func groupsOf(claim any) []string {
	switch v := claim.(type) {
	case string:
		return []string{v}
	case []any:
		var groups []string
		for _, g := range v {
			if s, ok := g.(string); ok {
				groups = append(groups, s)
			}
		}
		return groups
	}
	return nil
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// errForbidden is returned to an operator whose role does not allow an
// action, or whose form is not from this session.
var errForbidden = errors.New("forbidden")

// checkForm accepts a form only from the dashboard itself, in the session
// that rendered it: the CSRF token must match, and a browser's Origin
// header, when sent, must be the dashboard's.
// origin is the dashboard's origin as browsers send it: the host in lower
// case, and the port only when it is not the scheme's default.
func (a *auth) origin() string {
	host := strings.ToLower(a.public.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := a.public.Port(); port != "" && !(a.public.Scheme == "https" && port == "443") && !(a.public.Scheme == "http" && port == "80") {
		host += ":" + port
	}
	return a.public.Scheme + "://" + host
}

func (a *auth) checkForm(r *http.Request, s *session) error {
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.origin() {
		return errForbidden
	}
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(s.csrf)) != 1 {
		return errForbidden
	}
	return nil
}
