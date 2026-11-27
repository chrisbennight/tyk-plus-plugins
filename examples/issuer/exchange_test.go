package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

const exchangeDeck = `{
  "issuer": "https://issuer.example",
  "audience": "governed-mcp",
  "lifetimeSeconds": 600,
  "people": {
    "reviewer": {"groups": ["drift-reviewers"]},
    "scoped": {"sub": "svc-7"}
  },
  "clients": {
    "dashboard": {"secret": "s3cret", "redirectURIs": ["https://admin.example/callback"]},
    "gateway": {"secret": "gw-secret", "grants": ["urn:ietf:params:oauth:grant-type:token-exchange"]},
    "exchanger": {"secret": "ex-secret", "redirectURIs": ["https://admin.example/callback"],
      "grants": ["urn:ietf:params:oauth:grant-type:token-exchange"]}
  },
  "targets": {
    "https://notes.example/mcp": {"audience": "notes", "scopes": ["notes:read", "notes:write"]},
    "https://slow.example/mcp": {"delayMilliseconds": 1500}
  }
}`

const notes = "https://notes.example/mcp"

// sleeper records the delays the server asks for, and answers with err.
type sleeper struct {
	waited []time.Duration
	err    error
}

func (z *sleeper) sleep(_ context.Context, d time.Duration) error {
	z.waited = append(z.waited, d)
	return z.err
}

func newExchangeServer(t *testing.T) (*server, *clock, *sleeper) {
	t.Helper()
	d, err := loadDeck(writeDeck(t, exchangeDeck))
	if err != nil {
		t.Fatal(err)
	}
	key, err := publishedKey("")
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s, err := newServer(d, key, c.now)
	if err != nil {
		t.Fatal(err)
	}
	s.publicURL = "http://issuer.test:8000"
	z := &sleeper{}
	s.sleep = z.sleep
	return s, c, z
}

// personToken is a caller's token for a person in the deck, as the gateway
// receives it.
func personToken(t *testing.T, s *server, name string) string {
	t.Helper()
	rec := get(t, s, http.MethodGet, "/token/"+name, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("token for %s: %d", name, rec.Code)
	}
	return rec.Body.String()
}

// claimsToken signs exactly the given claims with the published key.
func claimsToken(t *testing.T, s *server, claims string) string {
	t.Helper()
	rec := get(t, s, http.MethodPost, "/token", claims)
	if rec.Code != http.StatusOK {
		t.Fatalf("token for %s: %d", claims, rec.Code)
	}
	return rec.Body.String()
}

func exchangeForm(subject string) url.Values {
	return url.Values{"grant_type": {grantTokenExchange}, "subject_token": {subject},
		"subject_token_type": {tokenTypeAccessToken}, "resource": {notes}}
}

type exchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
	Error           string `json:"error"`
}

func decodeExchange(t *testing.T, rec *httptest.ResponseRecorder) (exchangeResponse, map[string]any) {
	t.Helper()
	var typed exchangeResponse
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &typed); err != nil {
		t.Fatalf("%d %q: %v", rec.Code, rec.Body, err)
	}
	json.Unmarshal(rec.Body.Bytes(), &raw)
	return typed, raw
}

func TestExchangeIssuesAJWTAccessTokenForTheTarget(t *testing.T) {
	s, _, _ := newExchangeServer(t)
	form := exchangeForm(personToken(t, s, "reviewer"))
	form.Set("scope", "notes:read")
	rec := exchange(t, s, form, "gateway", "gw-secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body)
	}
	for name, want := range map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache"} {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	resp, _ := decodeExchange(t, rec)
	if resp.IssuedTokenType != tokenTypeAccessToken || resp.TokenType != "Bearer" || resp.ExpiresIn != 600 || resp.Scope != "notes:read" {
		t.Fatalf("response %+v", resp)
	}
	header, claims, ok := verify(t, s, resp.AccessToken)
	if !ok {
		t.Fatal("issued token did not verify against the published key")
	}
	if header["typ"] != "at+jwt" || header["alg"] != "RS256" {
		t.Errorf("header %v", header)
	}
	for name, want := range map[string]any{"iss": "https://issuer.example", "sub": "reviewer", "aud": notes,
		"client_id": "gateway", "iat": float64(1_800_000_000), "exp": float64(1_800_000_600), "scope": "notes:read"} {
		if claims[name] != want {
			t.Errorf("%s = %v, want %v", name, claims[name], want)
		}
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Errorf("jti %v", claims["jti"])
	}
	if _, ok := claims["groups"]; ok {
		t.Errorf("the person's other claims were copied: %v", claims)
	}

	again, _ := decodeExchange(t, exchange(t, s, form, "gateway", "gw-secret"))
	_, second, _ := verify(t, s, again.AccessToken)
	if second["jti"] == claims["jti"] {
		t.Errorf("two exchanges share jti %v", claims["jti"])
	}
}

func TestExchangeByAudienceNameIssuesForTheResourceURI(t *testing.T) {
	s, _, _ := newExchangeServer(t)
	form := exchangeForm(personToken(t, s, "scoped"))
	form.Del("resource")
	form.Set("audience", "notes")
	form.Set("subject_token_type", tokenTypeJWT)
	form.Set("requested_token_type", tokenTypeAccessToken)
	rec := exchange(t, s, form, "gateway", "gw-secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body)
	}
	resp, raw := decodeExchange(t, rec)
	if _, ok := raw["scope"]; ok {
		t.Errorf("a request without a scope was granted %v", raw["scope"])
	}
	_, claims, _ := verify(t, s, resp.AccessToken)
	if claims["aud"] != notes || claims["sub"] != "svc-7" {
		t.Fatalf("claims %v", claims)
	}
	if _, ok := claims["scope"]; ok {
		t.Errorf("token carries scope %v", claims["scope"])
	}
}

func TestExchangeClientCredentialsInTheForm(t *testing.T) {
	s, _, _ := newExchangeServer(t)
	form := exchangeForm(personToken(t, s, "reviewer"))
	form.Set("client_id", "gateway")
	form.Set("client_secret", "gw-secret")
	if rec := exchange(t, s, form, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body)
	}
}

func TestExchangeRefusals(t *testing.T) {
	type subjectFunc func(t *testing.T, s *server) string
	person := func(t *testing.T, s *server) string { return personToken(t, s, "reviewer") }
	claims := func(c string) subjectFunc {
		return func(t *testing.T, s *server) string { return claimsToken(t, s, c) }
	}
	// forged signs valid claims with a header that names alg, using a shared
	// secret anyone can choose.
	forged := func(alg string) subjectFunc {
		return func(t *testing.T, s *server) string {
			header, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": s.keyID})
			payload := `{"iss":"https://issuer.example","aud":"governed-mcp","sub":"reviewer","exp":1800000600}`
			signed := b64(header) + "." + b64([]byte(payload))
			if alg == "none" {
				return signed + "."
			}
			mac := hmac.New(sha256.New, []byte("guessable"))
			mac.Write([]byte(signed))
			return signed + "." + b64(mac.Sum(nil))
		}
	}
	for name, tc := range map[string]struct {
		subject    subjectFunc
		change     func(url.Values)
		user, pass string
		advance    time.Duration
		status     int
		error      string
	}{
		"wrong secret":               {user: "gateway", pass: "nope", status: 401, error: "invalid_client"},
		"unknown client":             {user: "stranger", pass: "gw-secret", status: 401, error: "invalid_client"},
		"client may not exchange":    {user: "dashboard", pass: "s3cret", status: 400, error: "unauthorized_client"},
		"no subject token":           {change: func(f url.Values) { f.Del("subject_token") }, status: 400, error: "invalid_request"},
		"no subject token type":      {change: func(f url.Values) { f.Del("subject_token_type") }, status: 400, error: "invalid_request"},
		"unsupported subject type":   {change: func(f url.Values) { f.Set("subject_token_type", "urn:ietf:params:oauth:token-type:id_token") }, status: 400, error: "invalid_request"},
		"unsupported requested type": {change: func(f url.Values) { f.Set("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token") }, status: 400, error: "invalid_request"},
		"actor token":                {change: func(f url.Values) { f.Set("actor_token", "x"); f.Set("actor_token_type", tokenTypeAccessToken) }, status: 400, error: "invalid_request"},
		"actor token type alone":     {change: func(f url.Values) { f.Set("actor_token_type", tokenTypeAccessToken) }, status: 400, error: "invalid_request"},
		"subject token twice":        {change: func(f url.Values) { f.Add("subject_token", "x") }, status: 400, error: "invalid_request"},
		"scope twice":                {change: func(f url.Values) { f.Add("scope", "notes:read"); f.Add("scope", "notes:write") }, status: 400, error: "invalid_request"},
		"no target":                  {change: func(f url.Values) { f.Del("resource") }, status: 400, error: "invalid_target"},
		"unknown resource":           {change: func(f url.Values) { f.Set("resource", "https://other.example/mcp") }, status: 400, error: "invalid_target"},
		"unknown audience":           {change: func(f url.Values) { f.Del("resource"); f.Set("audience", "other") }, status: 400, error: "invalid_target"},
		"two resources":              {change: func(f url.Values) { f.Add("resource", "https://slow.example/mcp") }, status: 400, error: "invalid_target"},
		"resource and audience":      {change: func(f url.Values) { f.Set("audience", "notes") }, status: 400, error: "invalid_target"},
		"relative resource":          {change: func(f url.Values) { f.Set("resource", "/mcp") }, status: 400, error: "invalid_target"},
		"resource with a fragment":   {change: func(f url.Values) { f.Set("resource", notes+"#x") }, status: 400, error: "invalid_target"},
		"scope the target lacks":     {change: func(f url.Values) { f.Set("scope", "notes:read notes:admin") }, status: 400, error: "invalid_scope"},
		"malformed scope":            {change: func(f url.Values) { f.Set("scope", "notes:read  notes:write") }, status: 400, error: "invalid_scope"},
		"subject token is not a JWT": {subject: func(*testing.T, *server) string { return "not-a-token" }, status: 400, error: "invalid_request"},
		"expired subject token":      {advance: 600 * time.Second, status: 400, error: "invalid_request"},
		"unpublished key": {subject: func(t *testing.T, s *server) string {
			return get(t, s, http.MethodGet, "/token/reviewer?key=unpublished", "").Body.String()
		}, status: 400, error: "invalid_request"},
		"token for another audience": {subject: claims(`{"iss":"https://issuer.example","aud":"other","sub":"reviewer","exp":1800000600}`), status: 400, error: "invalid_request"},
		"token from another issuer":  {subject: claims(`{"iss":"https://other.example","aud":"governed-mcp","sub":"reviewer","exp":1800000600}`), status: 400, error: "invalid_request"},
		"token without a subject":    {subject: claims(`{"iss":"https://issuer.example","aud":"governed-mcp","exp":1800000600}`), status: 400, error: "invalid_request"},
		"token without an expiry":    {subject: claims(`{"iss":"https://issuer.example","aud":"governed-mcp","sub":"reviewer"}`), status: 400, error: "invalid_request"},
		"token with a text expiry":   {subject: claims(`{"iss":"https://issuer.example","aud":"governed-mcp","sub":"reviewer","exp":"1800000600"}`), status: 400, error: "invalid_request"},
		"token not yet valid":        {subject: claims(`{"iss":"https://issuer.example","aud":"governed-mcp","sub":"reviewer","exp":1800000600,"nbf":1800000300}`), status: 400, error: "invalid_request"},
		"HS256 with a chosen secret": {subject: forged("HS256"), status: 400, error: "invalid_request"},
		"alg none":                   {subject: forged("none"), status: 400, error: "invalid_request"},
		"an exchanged token for notes": {subject: func(t *testing.T, s *server) string {
			resp, _ := decodeExchange(t, exchange(t, s, exchangeForm(personToken(t, s, "reviewer")), "gateway", "gw-secret"))
			return resp.AccessToken
		}, status: 400, error: "invalid_request"},
	} {
		t.Run(name, func(t *testing.T) {
			s, c, _ := newExchangeServer(t)
			subject := person
			if tc.subject != nil {
				subject = tc.subject
			}
			form := exchangeForm(subject(t, s))
			if tc.change != nil {
				tc.change(form)
			}
			user, pass := "gateway", "gw-secret"
			if tc.user != "" {
				user, pass = tc.user, tc.pass
			}
			c.t = c.t.Add(tc.advance)
			rec := exchange(t, s, form, user, pass)
			resp, _ := decodeExchange(t, rec)
			if rec.Code != tc.status || resp.Error != tc.error || resp.AccessToken != "" {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			challenge := rec.Header().Get("WWW-Authenticate")
			if (tc.error == "invalid_client") != strings.HasPrefix(challenge, "Basic ") {
				t.Errorf("WWW-Authenticate %q for %s", challenge, tc.error)
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("headers %v", rec.Header())
			}
		})
	}
}

func TestTwoClientAuthenticationMethodsAreRefused(t *testing.T) {
	s, _, _ := newExchangeServer(t)
	form := exchangeForm(personToken(t, s, "reviewer"))
	form.Set("client_secret", "gw-secret")
	rec := exchange(t, s, form, "gateway", "gw-secret")
	if resp, _ := decodeExchange(t, rec); rec.Code != http.StatusBadRequest || resp.Error != "invalid_request" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestAMalformedBasicHeaderIsChallenged(t *testing.T) {
	s, _, _ := newExchangeServer(t)
	form := exchangeForm(personToken(t, s, "reviewer"))
	form.Set("client_id", "gateway")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic not-base64!")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic ") {
		t.Fatalf("%d, WWW-Authenticate %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

func TestAWrongSecretInTheFormHasNoChallenge(t *testing.T) {
	s, _, _ := newExchangeServer(t)
	form := exchangeForm(personToken(t, s, "reviewer"))
	form.Set("client_id", "gateway")
	form.Set("client_secret", "nope")
	rec := exchange(t, s, form, "", "")
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("%d, WWW-Authenticate %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

func TestASlowTargetWaitsOnlyForAnAcceptedExchange(t *testing.T) {
	s, _, z := newExchangeServer(t)
	refused := exchangeForm(personToken(t, s, "reviewer"))
	refused.Set("resource", "https://slow.example/mcp")
	refused.Set("scope", "notes:read")
	if rec := exchange(t, s, refused, "gateway", "gw-secret"); rec.Code != http.StatusBadRequest || len(z.waited) != 0 {
		t.Fatalf("refused exchange: %d, waited %v", rec.Code, z.waited)
	}
	refused.Del("scope")
	if rec := exchange(t, s, refused, "gateway", "gw-secret"); rec.Code != http.StatusOK {
		t.Fatalf("slow exchange: %d %s", rec.Code, rec.Body)
	}
	if !slices.Equal(z.waited, []time.Duration{1500 * time.Millisecond}) {
		t.Fatalf("waited %v", z.waited)
	}
	if exchange(t, s, exchangeForm(personToken(t, s, "reviewer")), "gateway", "gw-secret"); len(z.waited) != 1 {
		t.Fatalf("a target without a delay waited: %v", z.waited)
	}
}

func TestAnAbandonedSlowExchangeIsNotAnswered(t *testing.T) {
	s, _, z := newExchangeServer(t)
	z.err = context.Canceled
	form := exchangeForm(personToken(t, s, "reviewer"))
	form.Set("resource", "https://slow.example/mcp")
	if rec := exchange(t, s, form, "gateway", "gw-secret"); rec.Body.Len() != 0 {
		t.Fatalf("answered %q", rec.Body)
	}
}

func TestSleepContextStopsWhenTheRequestIsAbandoned(t *testing.T) {
	if err := sleepContext(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("short sleep: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatalf("abandoned sleep: %v after %v", err, time.Since(start))
	}
}

func TestDiscoveryListsTheTokenExchangeGrant(t *testing.T) {
	s, _, _ := newExchangeServer(t)
	var doc struct {
		Grants  []string `json:"grant_types_supported"`
		Methods []string `json:"token_endpoint_auth_methods_supported"`
	}
	if err := json.Unmarshal(get(t, s, http.MethodGet, "/.well-known/openid-configuration", "").Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(doc.Grants, []string{grantAuthorizationCode, grantTokenExchange}) ||
		!slices.Equal(doc.Methods, []string{"client_secret_basic", "client_secret_post"}) {
		t.Fatalf("%+v", doc)
	}
}

func TestAnExchangeOnlyClientCannotSignIn(t *testing.T) {
	s, _, _ := newExchangeServer(t)
	// exchanger lists the redirect URI, so only its grants refuse the sign-in.
	rec := get(t, s, http.MethodGet, "/oauth/authorize?"+url.Values{"response_type": {"code"}, "client_id": {"exchanger"},
		"redirect_uri": {redirect}, "login_hint": {"reviewer"}}.Encode(), "")
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("%d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := exchange(t, s, url.Values{"grant_type": {grantAuthorizationCode}, "code": {"x"}}, "exchanger", "ex-secret"); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "unauthorized_client") {
		t.Fatalf("code grant: %d %s", rec.Code, rec.Body)
	}
}

func TestSignInAccessTokensFollowTheJWTAccessTokenProfile(t *testing.T) {
	s, _ := newSignInServer(t)
	rec := exchange(t, s, url.Values{"grant_type": {grantAuthorizationCode}, "code": {signInCode(t, s, url.Values{})},
		"redirect_uri": {redirect}}, "dashboard", "s3cret")
	if rec.Code != http.StatusOK || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("token: %d %v", rec.Code, rec.Header())
	}
	var tokens struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &tokens)
	idHeader, _, _ := verify(t, s, tokens.IDToken)
	header, claims, ok := verify(t, s, tokens.AccessToken)
	if !ok || header["typ"] != "at+jwt" || idHeader["typ"] != "JWT" {
		t.Fatalf("access token header %v, ID token header %v", header, idHeader)
	}
	if jti, _ := claims["jti"].(string); claims["client_id"] != "dashboard" || jti == "" || claims["iat"] != float64(1_800_000_000) {
		t.Fatalf("access token claims %v", claims)
	}
}

func TestDeckTargetsAndGrantsAreChecked(t *testing.T) {
	base := `"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"p":{}}`
	for name, rest := range map[string]string{
		"relative resource":              `"targets":{"/mcp":{}}`,
		"space in a resource":            `"targets":{"https://a.example/m cp":{}}`,
		"client named like the audience": `"clients":{"a":{"secret":"s","grants":["urn:ietf:params:oauth:grant-type:token-exchange"]}}`,
		"resource fragment":              `"targets":{"https://a.example/mcp#x":{}}`,
		"shared audience":                `"targets":{"https://a.example/mcp":{"audience":"x"},"https://b.example/mcp":{"audience":"x"}}`,
		"two scopes in one":              `"targets":{"https://a.example/mcp":{"scopes":["a b"]}}`,
		"empty scope":                    `"targets":{"https://a.example/mcp":{"scopes":[""]}}`,
		"negative delay":                 `"targets":{"https://a.example/mcp":{"delayMilliseconds":-1}}`,
		"long delay":                     `"targets":{"https://a.example/mcp":{"delayMilliseconds":60001}}`,
		"unknown target field":           `"targets":{"https://a.example/mcp":{"extra":1}}`,
		"unknown grant":                  `"clients":{"c":{"secret":"s","grants":["client_credentials"]}}`,
		"code without redirect":          `"clients":{"c":{"secret":"s","grants":["authorization_code","urn:ietf:params:oauth:grant-type:token-exchange"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadDeck(writeDeck(t, "{"+base+","+rest+"}")); err == nil {
				t.Fatal("deck accepted")
			}
		})
	}
	ok := `"clients":{"c":{"secret":"s","grants":["urn:ietf:params:oauth:grant-type:token-exchange"]}},` +
		`"targets":{"urn:example:notes":{"audience":"notes","scopes":["read"],"delayMilliseconds":60000}}`
	if _, err := loadDeck(writeDeck(t, "{"+base+","+ok+"}")); err != nil {
		t.Fatalf("an exchange-only client and a URN target were refused: %v", err)
	}
}
