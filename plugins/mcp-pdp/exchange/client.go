package exchange

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
)

// The token-exchange values this client sends and accepts (RFC 8693).
const (
	grantType       = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessTokenType = "urn:ietf:params:oauth:token-type:access_token"
	jwtTokenType    = "urn:ietf:params:oauth:token-type:jwt"
)

// maxResponseBytes bounds what is read from the token endpoint.
const maxResponseBytes = 64 << 10

// Failure kinds, which the gateway logs and which never carry a token.
const (
	KindConfiguration = "configuration"
	KindUnreachable   = "unreachable"
	KindRejected      = "rejected"
	KindMalformed     = "malformed"
	// KindExpired means the caller's own token, or the issued token,
	// expired before the issued token could be used.
	KindExpired = "expired"
)

// Error explains why an exchange failed. It holds no token, no client secret
// and none of the provider's error_description.
type Error struct {
	Kind string
	// Status is the token endpoint's HTTP status, or 0 when none arrived.
	Status int
	// Code is the provider's OAuth error code when it sent a well-formed
	// one, and empty otherwise.
	Code string
}

func (e *Error) Error() string {
	switch {
	case e.Code != "":
		return fmt.Sprintf("token exchange %s: HTTP %d, error %s", e.Kind, e.Status, e.Code)
	case e.Status != 0:
		return fmt.Sprintf("token exchange %s: HTTP %d", e.Kind, e.Status)
	}
	return "token exchange " + e.Kind
}

// Client exchanges callers' tokens and caches the issued tokens in process
// memory only.
type Client struct {
	settings *Settings
	http     *http.Client
	now      func() time.Time

	mu      sync.Mutex
	entries map[[32]byte]*list.Element
	order   *list.List // most recently used at the front
	flights map[[32]byte]*flight
}

type entry struct {
	key     [32]byte
	token   string
	expires time.Time
}

type flight struct {
	done  chan struct{}
	token string
	err   error
	// once is set when the reply gave no lifetime, so its token serves only
	// the request that started the exchange.
	once bool
	// expires is when the issued token's reported lifetime ends, counted
	// from when the request was sent, and zero when the reply gave none.
	expires time.Time
}

// New makes a client for valid settings.
func New(s *Settings) *Client {
	return &Client{
		settings: s,
		http: &http.Client{
			Timeout:   s.Timeout,
			Transport: &http.Transport{TLSClientConfig: s.TLS, Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true},
			// A token endpoint does not redirect; following one could send
			// the caller's token somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:     time.Now,
		entries: map[[32]byte]*list.Element{},
		order:   list.New(),
		flights: map[[32]byte]*flight{},
	}
}

// Exchange returns a token issued to the proxy's upstream for the caller
// whose token is subject. subjectExpiry is when that token expires; an issued
// token is never used after it. Concurrent requests for the same caller and
// proxy share one exchange.
func (c *Client) Exchange(ctx context.Context, proxy, subject string, subjectExpiry time.Time) (string, error) {
	target, ok := c.settings.Proxies[proxy]
	if !ok || subject == "" {
		return "", c.failed(proxy, &Error{Kind: KindConfiguration})
	}
	key := sha256.Sum256([]byte(subject + "\x00" + target.Resource + "\x00" + target.Scope))

	c.mu.Lock()
	if el, ok := c.entries[key]; ok {
		e := el.Value.(*entry)
		if now := c.now(); now.Before(e.expires) && now.Before(subjectExpiry) {
			c.order.MoveToFront(el)
			c.mu.Unlock()
			return e.token, nil
		}
		c.order.Remove(el)
		delete(c.entries, key)
	}
	f, shared := c.flights[key]
	if !shared {
		f = &flight{done: make(chan struct{})}
		c.flights[key] = f
	}
	c.mu.Unlock()

	if !shared {
		// The exchange is not tied to the first caller's request, so one
		// caller giving up does not fail the others waiting for it.
		go c.fly(key, f, proxy, target, subject, subjectExpiry)
	}
	select {
	case <-f.done:
		if shared && f.err == nil && f.once {
			// A token without a known lifetime is used for one request, so
			// a request that only waited for it makes its own exchange.
			sent := c.now()
			token, lifetime, err := c.request(ctx, target, subject)
			if ctxErr := ctx.Err(); ctxErr != nil {
				return "", ctxErr
			}
			if err != nil {
				return "", c.failed(proxy, err)
			}
			f = &flight{token: token}
			if lifetime > 0 {
				f.expires = sent.Add(lifetime)
			}
		}
		if f.err != nil {
			return "", f.err
		}
		// The caller's authority ends with its token, even when the token
		// expired while the exchange was under way.
		// A slow reply can also use up the issued token's own lifetime.
		if now := c.now(); !now.Before(subjectExpiry) || (!f.expires.IsZero() && !now.Before(f.expires)) {
			return "", c.failed(proxy, &Error{Kind: KindExpired})
		}
		return f.token, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (c *Client) fly(key [32]byte, f *flight, proxy string, target Target, subject string, subjectExpiry time.Time) {
	// The issued token's lifetime is counted from when the request was sent,
	// not from when the reply arrived, so a slow reply cannot extend it.
	sent := c.now()
	// The exchange is shared by every request waiting for it, so it is not
	// cancelled with any one of them; the HTTP client's timeout bounds it.
	token, lifetime, err := c.request(context.Background(), target, subject)
	c.mu.Lock()
	delete(c.flights, key)
	if err == nil && lifetime > 0 {
		expires := sent.Add(lifetime)
		if subjectExpiry.Before(expires) {
			expires = subjectExpiry
		}
		if expires = expires.Add(-c.settings.ExpiryMargin); c.now().Before(expires) {
			c.store(key, token, expires)
		}
	}
	c.mu.Unlock()
	if err != nil {
		err = c.failed(proxy, err)
	}
	f.token, f.err, f.once = token, err, err == nil && lifetime == 0
	if err == nil && lifetime > 0 {
		f.expires = sent.Add(lifetime)
	}
	close(f.done)
}

// store adds an entry, evicting the least recently used beyond the bound.
// The caller holds c.mu.
func (c *Client) store(key [32]byte, token string, expires time.Time) {
	c.entries[key] = c.order.PushFront(&entry{key: key, token: token, expires: expires})
	for c.order.Len() > c.settings.CacheEntries {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*entry).key)
	}
}

// failed logs a failure with only the proxy and the error's own fields.
func (c *Client) failed(proxy string, err error) error {
	var e *Error
	if !errors.As(err, &e) {
		e = &Error{Kind: KindUnreachable}
	}
	slog.Warn("Token exchange failed", "proxy", proxy, "kind", e.Kind, "status", e.Status, "error_code", e.Code)
	return e
}

// request performs one exchange and returns the issued token and its
// lifetime, which is zero when the response gave none.
func (c *Client) request(ctx context.Context, target Target, subject string) (string, time.Duration, error) {
	form := url.Values{
		"grant_type":         {grantType},
		"subject_token":      {subject},
		"subject_token_type": {accessTokenType},
		// The resource names the upstream; audience is never sent with it,
		// as the two together would name two targets.
		"resource": {target.Resource},
	}
	if target.Scope != "" {
		form.Set("scope", target.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.settings.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, &Error{Kind: KindConfiguration}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// HTTP Basic client authentication, with both parts form-encoded first
	// (RFC 6749 section 2.3.1).
	req.SetBasicAuth(url.QueryEscape(c.settings.ClientID), url.QueryEscape(c.settings.ClientSecret))
	res, err := c.http.Do(req)
	if err != nil {
		return "", 0, &Error{Kind: KindUnreachable}
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return "", 0, &Error{Kind: KindUnreachable, Status: res.StatusCode}
	}
	if len(body) > maxResponseBytes {
		return "", 0, &Error{Kind: KindMalformed, Status: res.StatusCode}
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		// Any refusal fails, whatever its code.
		return "", 0, &Error{Kind: KindRejected, Status: res.StatusCode, Code: errorCode(body)}
	}
	var reply struct {
		AccessToken     *string          `json:"access_token"`
		IssuedTokenType *string          `json:"issued_token_type"`
		TokenType       *string          `json:"token_type"`
		ExpiresIn       *json.RawMessage `json:"expires_in"`
	}
	// Member names are matched exactly, and a repeated member is refused, so
	// "ACCESS_TOKEN" is not taken for access_token.
	if jsonv2.Unmarshal(body, &reply) != nil || reply.AccessToken == nil || reply.IssuedTokenType == nil || reply.TokenType == nil {
		return "", 0, &Error{Kind: KindMalformed, Status: res.StatusCode}
	}
	// The gateway can only send a bearer token; this also refuses N_A.
	if !strings.EqualFold(*reply.TokenType, "Bearer") {
		return "", 0, &Error{Kind: KindMalformed, Status: res.StatusCode}
	}
	if t := *reply.IssuedTokenType; t != accessTokenType && t != jwtTokenType {
		return "", 0, &Error{Kind: KindMalformed, Status: res.StatusCode}
	}
	// The token goes into a header, so it must be a bearer token's syntax
	// (RFC 6750 section 2.1).
	if !bearerToken.MatchString(*reply.AccessToken) {
		return "", 0, &Error{Kind: KindMalformed, Status: res.StatusCode}
	}
	return *reply.AccessToken, lifetime(reply.ExpiresIn), nil
}

var bearerToken = regexp.MustCompile(`^[A-Za-z0-9\-._~+/]+=*$`)

// lifetime reads expires_in as a positive whole number of seconds. Anything
// else gives zero, so the token is used once and not cached.
func lifetime(raw *json.RawMessage) time.Duration {
	if raw == nil {
		return 0
	}
	var seconds int64
	// A lifetime too long to represent is treated as unknown.
	if json.Unmarshal(*raw, &seconds) != nil || seconds <= 0 || seconds > int64(math.MaxInt64/int64(time.Second)) {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// errorCode returns the OAuth error code of a refusal when it is one of the
// registered codes a token endpoint uses, "other" for any other code, and
// empty when there is none. Only registered codes are kept, because a
// provider may echo request details, even a credential, in any field.
func errorCode(body []byte) string {
	var refusal struct {
		Error *string `json:"error"`
	}
	// As with a reply, the member's name is matched exactly and a repeated
	// member is refused.
	if jsonv2.Unmarshal(body, &refusal) != nil || refusal.Error == nil {
		return ""
	}
	if knownErrorCodes[*refusal.Error] {
		return *refusal.Error
	}
	return "other"
}

// knownErrorCodes are the error codes of RFC 6749 section 5.2, RFC 8693
// section 2.2.2 and RFC 8707, and the general codes a server may return.
var knownErrorCodes = map[string]bool{
	"invalid_request": true, "invalid_client": true, "invalid_grant": true, "unauthorized_client": true,
	"unsupported_grant_type": true, "invalid_scope": true, "invalid_target": true, "access_denied": true,
	"server_error": true, "temporarily_unavailable": true,
}
