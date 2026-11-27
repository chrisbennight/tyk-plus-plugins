package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// The token-exchange grant (RFC 8693) lets a client, such as the gateway,
// trade an access token this issuer signed for the gateway's audience for a
// token issued to one of the deck's targets. It is impersonation only: the
// issued token names the subject token's sub, and no actor.

// The token types the grant accepts and issues (RFC 8693 section 3).
const (
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
)

// exchangeToken handles a token-exchange request from an authenticated
// client, whose parameters the token endpoint has already checked do not
// repeat. A request it cannot accept is answered with the error code RFC 8693
// section 2.2.2 requires: invalid_request for an invalid request or subject
// token, invalid_target for a target the issuer cannot issue for. A scope the
// target does not allow is answered with invalid_scope (RFC 6749 section 5.2).
func (s *server) exchangeToken(w http.ResponseWriter, r *http.Request, clientID string) {
	form := r.PostForm
	// The issuer accepts no actor tokens, so any actor token is unacceptable
	// by policy.
	if form.Has("actor_token") || form.Has("actor_token_type") {
		tokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if subjectType := form.Get("subject_token_type"); form.Get("subject_token") == "" ||
		(subjectType != tokenTypeAccessToken && subjectType != tokenTypeJWT) {
		tokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if requested := form.Get("requested_token_type"); requested != "" && requested != tokenTypeAccessToken {
		tokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	resource, t, ok := s.target(form)
	if !ok {
		tokenError(w, http.StatusBadRequest, "invalid_target")
		return
	}
	subject, ok := s.verifySubject(form.Get("subject_token"))
	if !ok {
		tokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	scope, ok := grantedScope(form.Get("scope"), t.Scopes)
	if !ok {
		tokenError(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	if t.DelayMilliseconds > 0 {
		if s.sleep(r.Context(), time.Duration(t.DelayMilliseconds)*time.Millisecond) != nil {
			return // The caller gave up; there is no one to answer.
		}
	}
	jti, err := randomID()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The issued token follows the JWT access token profile (RFC 9068
	// section 2.2). Its aud is the target's resource URI (RFC 9068 section 3),
	// and client_id names the client that requested it (RFC 8693 section 4.3).
	now := s.now()
	claims := map[string]any{"iss": s.deck.Issuer, "sub": subject, "aud": resource, "client_id": clientID,
		"iat": now.Unix(), "exp": now.Unix() + s.deck.LifetimeSeconds, "jti": jti}
	if scope != "" {
		claims["scope"] = scope
	}
	body, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token, err := sign(s.published, s.keyID, typAccessJWT, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response := map[string]any{"access_token": token, "issued_token_type": tokenTypeAccessToken,
		"token_type": "Bearer", "expires_in": s.deck.LifetimeSeconds}
	if scope != "" {
		response["scope"] = scope
	}
	writeTokens(w, response)
}

// target returns the one target a request names, by resource URI or by
// audience name, and the resource URI the issued token's aud carries. A
// request that names no target, more than one, or one the deck does not list
// names none the issuer can issue for. resource and audience together name
// two targets (RFC 8693 section 2.1.1).
func (s *server) target(form url.Values) (string, target, bool) {
	resources, audiences := form["resource"], form["audience"]
	if len(resources)+len(audiences) != 1 {
		return "", target{}, false
	}
	if len(resources) == 1 {
		t, ok := s.deck.Targets[resources[0]]
		return resources[0], t, ok && validResource(resources[0])
	}
	for resource, t := range s.deck.Targets {
		if t.Audience != "" && t.Audience == audiences[0] {
			return resource, t, true
		}
	}
	return "", target{}, false
}

// verifySubject returns the subject of a subject token this issuer signed
// with its published key for the deck's audience, which is the gateway's.
// Any other token, including a valid one for another audience, is
// unacceptable.
func (s *server) verifySubject(raw string) (string, bool) {
	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(token.Headers) != 1 || token.Headers[0].KeyID != s.keyID {
		return "", false
	}
	var claims jwt.Claims
	if err := token.Claims(&s.published.PublicKey, &claims); err != nil {
		return "", false
	}
	now := s.now()
	// The current time must be before exp (RFC 7519 section 4.1.4).
	if claims.Subject == "" || claims.Expiry == nil || !now.Before(claims.Expiry.Time()) {
		return "", false
	}
	expected := jwt.Expected{Issuer: s.deck.Issuer, AnyAudience: jwt.Audience{s.deck.Audience}, Time: now}
	if claims.ValidateWithLeeway(expected, 0) != nil {
		return "", false
	}
	return claims.Subject, true
}

// grantedScope returns the scope to grant: exactly the requested scope values,
// if the target allows all of them. A request without a scope is granted none.
func grantedScope(requested string, allowed []string) (string, bool) {
	if requested == "" {
		return "", true
	}
	for _, value := range strings.Split(requested, " ") {
		if !slices.Contains(allowed, value) {
			return "", false
		}
	}
	return requested, true
}

// randomID returns a random value for a token's jti.
func randomID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return b64(random), nil
}

// sleepContext waits for d, or until ctx is done.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
