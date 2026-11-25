package main

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const signInDeck = `{
  "issuer": "https://issuer.example",
  "audience": "governed-mcp",
  "lifetimeSeconds": 600,
  "people": {
    "reviewer": {"groups": ["drift-reviewers"], "nonce": "from-the-deck"},
    "scoped": {"sub": "svc-7", "scope": "read write"}
  },
  "clients": {
    "dashboard": {"secret": "s3cret", "redirectURIs": ["https://admin.example/callback"]},
    "special": {"secret": "a b+c/d", "redirectURIs": ["https://admin.example/callback"]}
  }
}`

const redirect = "https://admin.example/callback"

// clock is a settable time for the sign-in tests.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newSignInServer(t *testing.T) (*server, *clock) {
	t.Helper()
	d, err := loadDeck(writeDeck(t, signInDeck))
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
	return s, c
}

func authorizeURL(extra url.Values) string {
	q := url.Values{"response_type": {"code"}, "client_id": {"dashboard"}, "redirect_uri": {redirect},
		"state": {"st-1"}, "nonce": {"n-1"}}
	for k, v := range extra {
		q[k] = v
	}
	return "/oauth/authorize?" + q.Encode()
}

// signInCode runs the authorize step for a person and returns the code.
func signInCode(t *testing.T, s *server, extra url.Values) string {
	t.Helper()
	extra.Set("login_hint", "reviewer")
	rec := get(t, s, http.MethodGet, authorizeURL(extra), "")
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", rec.Code, rec.Body)
	}
	back, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(back.String(), redirect+"?") || back.Query().Get("state") != "st-1" || back.Query().Get("code") == "" {
		t.Fatalf("redirected to %q", rec.Header().Get("Location"))
	}
	return back.Query().Get("code")
}

func exchange(t *testing.T, s *server, form url.Values, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestDiscoveryNamesTheEndpoints(t *testing.T) {
	s, _ := newSignInServer(t)
	var doc map[string]any
	if err := json.Unmarshal(get(t, s, http.MethodGet, "/.well-known/openid-configuration", "").Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"issuer":                 "https://issuer.example",
		"authorization_endpoint": "http://issuer.test:8000/oauth/authorize",
		"token_endpoint":         "http://issuer.test:8000/oauth/token",
		"jwks_uri":               "http://issuer.test:8000/jwks",
	} {
		if doc[key] != want {
			t.Errorf("%s = %v, want %s", key, doc[key], want)
		}
	}
}

func TestSignInEndpointsNeedAPublicURL(t *testing.T) {
	s, _ := newSignInServer(t)
	s.publicURL = ""
	for _, target := range []string{"/.well-known/openid-configuration", authorizeURL(url.Values{"login_hint": {"reviewer"}})} {
		if rec := get(t, s, http.MethodGet, target, ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s answered %d without a public URL", target, rec.Code)
		}
	}
}

func TestSignInWithPKCEGivesAVerifiableIDToken(t *testing.T) {
	s, _ := newSignInServer(t)
	verifier := "a-long-random-verifier-0123456789abcdefghijk"
	sum := sha256.Sum256([]byte(verifier))
	code := signInCode(t, s, url.Values{"code_challenge": {b64(sum[:])}, "code_challenge_method": {"S256"}})
	rec := exchange(t, s, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"code_verifier": {verifier}}, "dashboard", "s3cret")
	if rec.Code != http.StatusOK {
		t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}
	var tokens struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	json.Unmarshal(rec.Body.Bytes(), &tokens)
	_, claims, ok := verify(t, s, tokens.IDToken)
	if !ok || tokens.TokenType != "Bearer" {
		t.Fatalf("ID token did not verify: %v", tokens)
	}
	if claims["iss"] != "https://issuer.example" || claims["aud"] != "dashboard" || claims["sub"] != "reviewer" ||
		claims["nonce"] != "n-1" || claims["exp"] != float64(1_800_000_600) {
		t.Fatalf("ID token claims %v", claims)
	}
	if groups, _ := claims["groups"].([]any); len(groups) != 1 || groups[0] != "drift-reviewers" {
		t.Fatalf("ID token groups %v", claims["groups"])
	}
	if _, access, ok := verify(t, s, tokens.AccessToken); !ok || access["aud"] != "governed-mcp" {
		t.Fatalf("access token %v", access)
	}
}

func TestClientSecretInTheForm(t *testing.T) {
	s, _ := newSignInServer(t)
	code := signInCode(t, s, url.Values{})
	rec := exchange(t, s, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {"dashboard"}, "client_secret": {"s3cret"}}, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}
}

func TestAnUnknownRedirectIsRefusedWithoutRedirecting(t *testing.T) {
	s, _ := newSignInServer(t)
	for _, extra := range []url.Values{
		{"redirect_uri": {"https://evil.example/callback"}, "login_hint": {"reviewer"}},
		{"client_id": {"other"}, "login_hint": {"reviewer"}},
	} {
		rec := get(t, s, http.MethodGet, authorizeURL(extra), "")
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Errorf("%v: %d, Location %q", extra, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestCodeRefusals(t *testing.T) {
	sum := sha256.Sum256([]byte("right-verifier"))
	for name, tc := range map[string]struct {
		challenge  bool
		form       url.Values
		user, pass string
		advance    time.Duration
		status     int
		error      string
	}{
		"wrong secret":     {user: "dashboard", pass: "nope", status: http.StatusUnauthorized, error: "invalid_client"},
		"unknown client":   {user: "other", pass: "s3cret", status: http.StatusUnauthorized, error: "invalid_client"},
		"wrong verifier":   {challenge: true, form: url.Values{"code_verifier": {"wrong-verifier"}}, user: "dashboard", pass: "s3cret", status: http.StatusBadRequest, error: "invalid_grant"},
		"missing verifier": {challenge: true, user: "dashboard", pass: "s3cret", status: http.StatusBadRequest, error: "invalid_grant"},
		"expired code":     {advance: codeLifetime, user: "dashboard", pass: "s3cret", status: http.StatusBadRequest, error: "invalid_grant"},
		"other redirect":   {form: url.Values{"redirect_uri": {"https://admin.example/other"}}, user: "dashboard", pass: "s3cret", status: http.StatusBadRequest, error: "invalid_grant"},
	} {
		t.Run(name, func(t *testing.T) {
			s, c := newSignInServer(t)
			extra := url.Values{}
			if tc.challenge {
				extra.Set("code_challenge", b64(sum[:]))
				extra.Set("code_challenge_method", "S256")
			}
			code := signInCode(t, s, extra)
			c.t = c.t.Add(tc.advance)
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}}
			for k, v := range tc.form {
				form[k] = v
			}
			rec := exchange(t, s, form, tc.user, tc.pass)
			var body map[string]string
			json.Unmarshal(rec.Body.Bytes(), &body)
			if rec.Code != tc.status || body["error"] != tc.error {
				t.Fatalf("%d %v", rec.Code, body)
			}
		})
	}
}

func TestACodeWorksOnce(t *testing.T) {
	s, _ := newSignInServer(t)
	code := signInCode(t, s, url.Values{})
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}}
	if rec := exchange(t, s, form, "dashboard", "s3cret"); rec.Code != http.StatusOK {
		t.Fatalf("first exchange: %d", rec.Code)
	}
	if rec := exchange(t, s, form, "dashboard", "s3cret"); rec.Code != http.StatusBadRequest {
		t.Fatalf("second exchange: %d", rec.Code)
	}
}

func TestTheSignInPageListsPeople(t *testing.T) {
	s, _ := newSignInServer(t)
	rec := get(t, s, http.MethodGet, authorizeURL(url.Values{"state": {"<script>"}}), "")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, ">reviewer</a>") || !strings.Contains(body, ">scoped</a>") ||
		strings.Contains(body, "<script>") || !strings.Contains(body, "login_hint=reviewer") {
		t.Fatalf("%d\n%s", rec.Code, body)
	}
}

func TestDeckClientsAreChecked(t *testing.T) {
	people := `"issuer":"i","audience":"a","lifetimeSeconds":1,"people":{"p":{}}`
	for name, clients := range map[string]string{
		"bad name":        `{"Bad Name":{"secret":"s","redirectURIs":["https://a.example/cb"]}}`,
		"no secret":       `{"c":{"redirectURIs":["https://a.example/cb"]}}`,
		"no redirect":     `{"c":{"secret":"s","redirectURIs":[]}}`,
		"relative":        `{"c":{"secret":"s","redirectURIs":["/cb"]}}`,
		"unknown field":   `{"c":{"secret":"s","redirectURIs":["https://a.example/cb"],"extra":1}}`,
		"with a fragment": `{"c":{"secret":"s","redirectURIs":["https://a.example/cb#x"]}}`,
		"own state":       `{"c":{"secret":"s","redirectURIs":["https://a.example/cb?state=x"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadDeck(writeDeck(t, "{"+people+`,"clients":`+clients+"}")); err == nil {
				t.Fatal("deck accepted")
			}
		})
	}
}

func TestBasicCredentialsAreFormDecoded(t *testing.T) {
	s, _ := newSignInServer(t)
	rec := get(t, s, http.MethodGet, authorizeURL(url.Values{"client_id": {"special"}, "login_hint": {"reviewer"}}), "")
	back, _ := url.Parse(rec.Header().Get("Location"))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")}, "redirect_uri": {redirect}}
	if rec := exchange(t, s, form, "special", url.QueryEscape("a b+c/d")); rec.Code != http.StatusOK {
		t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}
}

func TestPKCEMustBeComplete(t *testing.T) {
	s, _ := newSignInServer(t)
	for _, extra := range []url.Values{
		{"code_challenge_method": {"S256"}, "login_hint": {"reviewer"}},
		{"code_challenge": {"abc"}, "login_hint": {"reviewer"}},
		{"nonce": {strings.Repeat("n", maxParameter+1)}, "login_hint": {"reviewer"}},
	} {
		if rec := get(t, s, http.MethodGet, authorizeURL(extra), ""); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", extra, rec.Code)
		}
	}
	// A verifier sent for a sign-in without a challenge is refused.
	code := signInCode(t, s, url.Values{})
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {"v"}}
	if rec := exchange(t, s, form, "dashboard", "s3cret"); rec.Code != http.StatusBadRequest {
		t.Fatalf("verifier without challenge: %d", rec.Code)
	}
}

func TestTheIDTokenCarriesOnlyTheSignInNonce(t *testing.T) {
	s, _ := newSignInServer(t)
	extra := url.Values{"login_hint": {"reviewer"}}
	rec := get(t, s, http.MethodGet, "/oauth/authorize?"+url.Values{"response_type": {"code"}, "client_id": {"dashboard"},
		"redirect_uri": {redirect}, "state": {"st-1"}, "login_hint": extra["login_hint"]}.Encode(), "")
	back, _ := url.Parse(rec.Header().Get("Location"))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")}, "redirect_uri": {redirect}}
	res := exchange(t, s, form, "dashboard", "s3cret")
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	json.Unmarshal(res.Body.Bytes(), &tokens)
	if _, claims, ok := verify(t, s, tokens.IDToken); !ok || claims["nonce"] != nil {
		t.Fatalf("a sign-in without a nonce gave %v", claims["nonce"])
	}
}
