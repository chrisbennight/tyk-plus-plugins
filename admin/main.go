// Command cedar-admin serves the drift review dashboard: a web interface to
// the same review the cedar-policy drift commands provide, for operators
// signed in through an OpenID Connect identity provider.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// config is the dashboard's configuration, read from the environment.
type config struct {
	listen, publicURL          string
	store, pending             string
	issuer, discoveryURL       string
	clientID, clientSecret     string
	groupsClaim                string
	reviewerGroup, viewerGroup string
}

func readConfig() (config, error) {
	c := config{
		listen:        envOr("ADMIN_LISTEN", ":8000"),
		publicURL:     os.Getenv("ADMIN_PUBLIC_URL"),
		store:         envOr("ADMIN_STORE", "/opt/tyk-gateway/cedar"),
		pending:       envOr("ADMIN_PENDING_DIR", "/opt/tyk-gateway/cedar-pending"),
		issuer:        os.Getenv("ADMIN_OIDC_ISSUER"),
		discoveryURL:  os.Getenv("ADMIN_OIDC_DISCOVERY_URL"),
		clientID:      os.Getenv("ADMIN_OIDC_CLIENT_ID"),
		clientSecret:  os.Getenv("ADMIN_OIDC_CLIENT_SECRET"),
		groupsClaim:   envOr("ADMIN_GROUPS_CLAIM", "groups"),
		reviewerGroup: os.Getenv("ADMIN_REVIEWER_GROUP"),
		viewerGroup:   os.Getenv("ADMIN_VIEWER_GROUP"),
	}
	// A secret in a file keeps it out of the process environment.
	if file := os.Getenv("ADMIN_OIDC_CLIENT_SECRET_FILE"); file != "" {
		secret, err := os.ReadFile(file)
		if err != nil {
			return c, fmt.Errorf("ADMIN_OIDC_CLIENT_SECRET_FILE: %w", err)
		}
		c.clientSecret = strings.TrimSpace(string(secret))
	}
	var missing []string
	for name, value := range map[string]string{"ADMIN_PUBLIC_URL": c.publicURL, "ADMIN_OIDC_ISSUER": c.issuer,
		"ADMIN_OIDC_CLIENT_ID": c.clientID, "ADMIN_REVIEWER_GROUP": c.reviewerGroup} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return c, fmt.Errorf("set %s", strings.Join(missing, ", "))
	}
	if c.clientSecret == "" {
		return c, errors.New("set ADMIN_OIDC_CLIENT_SECRET_FILE or ADMIN_OIDC_CLIENT_SECRET")
	}
	return c, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	cfg, err := readConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cedar-admin: %v\n", err)
		os.Exit(1)
	}
	public, err := url.Parse(strings.TrimSuffix(cfg.publicURL, "/"))
	if err != nil || (public.Scheme != "https" && public.Scheme != "http") || public.Host == "" {
		fmt.Fprintf(os.Stderr, "cedar-admin: ADMIN_PUBLIC_URL must be an absolute http or https URL\n")
		os.Exit(1)
	}
	if public.Scheme != "https" {
		slog.Warn("ADMIN_PUBLIC_URL is not https: session cookies are sent without the Secure flag. Use this only on a local or test network.")
	}
	for _, provider := range []string{cfg.issuer, cfg.discoveryURL} {
		if provider != "" && !strings.HasPrefix(provider, "https://") {
			// The provider's configuration names the keys that verify ID
			// tokens and the endpoint that receives the client secret.
			slog.Warn("The identity provider is reached without https: whoever can alter that traffic can sign in as anyone. Use this only on a local or test network.", "url", provider)
		}
	}
	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           newServer(cfg, newAuth(cfg, public)).routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	slog.Info("Serving the review dashboard", "listen", cfg.listen, "public", public.String())
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "cedar-admin: %v\n", err)
		os.Exit(1)
	}
}
