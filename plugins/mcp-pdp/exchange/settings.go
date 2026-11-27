// Package exchange obtains, for a caller's token, a token the identity
// provider issues to a proxy's upstream, through OAuth 2.0 Token Exchange
// (RFC 8693). The issued token names the same user and is meant for that
// upstream alone. Exchange fails closed: on any doubt it returns an error,
// never another credential.
package exchange

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Defaults for the bounds. The timeout is longer than the timeout an
// intermediary in front of the identity provider would typically use, so
// such an intermediary answers first.
const (
	DefaultTimeout      = 15 * time.Second
	DefaultCacheEntries = 10000
	DefaultExpiryMargin = 30 * time.Second
)

// Target is what a proxy's upstream tokens are issued for.
type Target struct {
	// Resource is the upstream MCP server's canonical URI, sent as the
	// token-exchange request's resource.
	Resource string
	// Scope is the space-separated scope to request; empty requests none.
	Scope string
}

// Settings configure token exchange on one gateway.
type Settings struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	// TLS is the client configuration for the token endpoint: only the
	// certificate authorities in EXCHANGE_TLS_CA when it is set, the
	// system's otherwise.
	TLS          *tls.Config
	Timeout      time.Duration
	CacheEntries int
	ExpiryMargin time.Duration
	// Proxies maps each proxy with exchange on to its target. A proxy named
	// here with an invalid target is still listed, so its calls are refused.
	Proxies map[string]Target
	// AllProxies is set when EXCHANGE_PROXIES could not be read well enough
	// to know which proxies it names, so every proxy must be treated as
	// having exchange on, and refused.
	AllProxies bool
}

// On reports whether exchange is on for a proxy.
func (s *Settings) On(proxy string) bool {
	if s == nil {
		return false
	}
	_, on := s.Proxies[proxy]
	return on || s.AllProxies
}

// Load reads the settings from the environment. It returns nil settings and
// no error when exchange is not configured, and settings with an error when
// it is configured but unusable, so the gateway can refuse the affected
// calls and say why.
func Load(getenv func(string) string) (*Settings, error) {
	configured := false
	for _, name := range []string{"EXCHANGE_PROXIES", "EXCHANGE_TOKEN_URL", "EXCHANGE_CLIENT_ID"} {
		if getenv(name) != "" {
			configured = true
		}
	}
	if !configured {
		return nil, nil
	}
	s := &Settings{Timeout: DefaultTimeout, CacheEntries: DefaultCacheEntries, ExpiryMargin: DefaultExpiryMargin, Proxies: map[string]Target{}}
	var problems []string
	fail := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if err := s.parseProxies(getenv("EXCHANGE_PROXIES")); err != nil {
		fail("EXCHANGE_PROXIES: %v", err)
	}
	s.TokenURL = getenv("EXCHANGE_TOKEN_URL")
	if err := checkTokenURL(s.TokenURL, getenv("EXCHANGE_ALLOW_INSECURE_HTTP") == "true"); err != nil {
		fail("EXCHANGE_TOKEN_URL: %v", err)
	}
	if s.ClientID = getenv("EXCHANGE_CLIENT_ID"); s.ClientID == "" {
		fail("EXCHANGE_CLIENT_ID is not set")
	}
	// A secret in a file keeps it out of the process environment.
	s.ClientSecret = getenv("EXCHANGE_CLIENT_SECRET")
	if file := getenv("EXCHANGE_CLIENT_SECRET_FILE"); file != "" {
		secret, err := os.ReadFile(file)
		if err != nil {
			fail("EXCHANGE_CLIENT_SECRET_FILE could not be read")
		}
		s.ClientSecret = strings.TrimSpace(string(secret))
	}
	if s.ClientSecret == "" {
		fail("set EXCHANGE_CLIENT_SECRET_FILE or EXCHANGE_CLIENT_SECRET")
	}
	duration := func(name string, target *time.Duration) {
		if value := getenv(name); value != "" {
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				fail("%s must be a positive duration such as 15s, not %q", name, value)
				return
			}
			*target = d
		}
	}
	duration("EXCHANGE_TIMEOUT", &s.Timeout)
	duration("EXCHANGE_EXPIRY_MARGIN", &s.ExpiryMargin)
	if value := getenv("EXCHANGE_CACHE_MAX_ENTRIES"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 {
			fail("EXCHANGE_CACHE_MAX_ENTRIES must be a positive whole number, not %q", value)
		} else {
			s.CacheEntries = n
		}
	}
	var err error
	if s.TLS, err = clientTLS(getenv("EXCHANGE_TLS_CA")); err != nil {
		fail("EXCHANGE_TLS_CA: %v", err)
	}
	if len(problems) > 0 {
		return s, errors.New(strings.Join(problems, "; "))
	}
	return s, nil
}

func checkTokenURL(raw string, allowHTTP bool) error {
	if raw == "" {
		return errors.New("not set")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("not an absolute URL with a host and no user or fragment")
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && allowHTTP:
		return nil
	case u.Scheme == "http":
		return errors.New("must use https; set EXCHANGE_ALLOW_INSECURE_HTTP=true only on a local or test network")
	}
	return errors.New("must use https")
}

var proxyID = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// parseProxies reads "id=resource [scope ...],id2=resource2". An entry whose
// proxy ID can be read is listed even when its target is invalid, so that
// proxy refuses its calls; an entry whose proxy ID cannot be read makes
// every proxy refuse its calls.
func (s *Settings) parseProxies(value string) error {
	var problems []string
	for _, entry := range strings.Split(value, ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		id, target, ok := strings.Cut(entry, "=")
		id = strings.TrimSpace(id)
		if !ok || !proxyID.MatchString(id) {
			s.AllProxies = true
			problems = append(problems, fmt.Sprintf("entry %q is not proxy-id=resource", entry))
			continue
		}
		if _, dup := s.Proxies[id]; dup {
			problems = append(problems, fmt.Sprintf("proxy %q is listed twice", id))
			continue
		}
		fields := strings.Fields(target)
		t := Target{}
		if len(fields) > 0 {
			t.Resource, t.Scope = fields[0], strings.Join(fields[1:], " ")
		}
		s.Proxies[id] = t
		if err := checkResource(t.Resource); err != nil {
			problems = append(problems, fmt.Sprintf("proxy %q: %v", id, err))
		}
	}
	if len(s.Proxies) == 0 && !s.AllProxies {
		problems = append(problems, "no proxies are listed")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// checkResource accepts an upstream's canonical URI: an absolute URI with a
// scheme and no fragment (RFC 8707 section 2).
func checkResource(raw string) error {
	if raw == "" {
		return errors.New("no resource")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("resource %q is not an absolute URI with a host and no fragment", raw)
	}
	return nil
}

// clientTLS trusts only the certificate authorities in caFile when it is
// set, and the system's otherwise.
func clientTLS(caFile string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile == "" {
		return config, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.New("the file could not be read")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("the file holds no certificates")
	}
	config.RootCAs = roots
	return config, nil
}
