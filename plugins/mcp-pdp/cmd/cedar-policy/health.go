package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

const healthUsage = `Usage:
  cedar-policy health [-conf FILE] [-status FILE] [-timeout DURATION]
      Exit 0 when the gateway in this container is healthy, 1 otherwise.
      Healthy means Tyk's readiness endpoint answers 200, which it does only
      while Redis is connected and the APIs have loaded, and, when a status
      file is named, that the gateway enforces a policy set. A rejected new
      set leaves the previous one enforced and stays healthy.
`

// tykConfig holds the settings that decide where Tyk serves its readiness
// endpoint. Field names follow Tyk's configuration file.
type tykConfig struct {
	ListenAddress              string `json:"listen_address"`
	ListenPort                 int    `json:"listen_port"`
	ControlAPIHostname         string `json:"control_api_hostname"`
	ControlAPIPort             int    `json:"control_api_port"`
	ReadinessCheckEndpointName string `json:"readiness_check_endpoint_name"`
	HTTPServerOptions          struct {
		UseSSL bool `json:"use_ssl"`
	} `json:"http_server_options"`
}

func runHealth(args []string, lookup func(string) (string, bool), out io.Writer) error {
	flags := flag.NewFlagSet("health", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	conf := flags.String("conf", "/opt/tyk-gateway/tyk.conf", "Tyk configuration file")
	statusDefault, _ := lookup("CEDAR_STATUS_FILE")
	status := flags.String("status", statusDefault, "the gateway's policy status file; empty skips the policy check")
	timeout := flags.Duration("timeout", 2*time.Second, "how long to wait for the gateway")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(out, healthUsage)
		return nil
	} else if err != nil {
		return fmt.Errorf("%w\n\n%s", err, healthUsage)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("health takes no arguments\n\n%s", healthUsage)
	}
	if *timeout <= 0 {
		return fmt.Errorf("-timeout must be positive, got %v", *timeout)
	}
	cfg, err := readTykConfig(*conf, lookup)
	if err != nil {
		return err
	}
	if err := checkReady(cfg, *timeout); err != nil {
		return err
	}
	if *status == "" {
		fmt.Fprintln(out, "healthy")
		return nil
	}
	enforcing, err := checkEnforcing(*status)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "healthy: enforcing %s\n", enforcing)
	return nil
}

// readTykConfig reads the configuration file, then applies the environment
// variables Tyk reads in its place, as Tyk does.
func readTykConfig(path string, lookup func(string) (string, bool)) (tykConfig, error) {
	var cfg tykConfig
	omit := false
	if v, ok := lookup("TYK_GW_OMITCONFIGFILE"); ok && v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return cfg, fmt.Errorf("TYK_GW_OMITCONFIGFILE: %w", err)
		}
		omit = parsed
	}
	if !omit {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("reading the Tyk configuration: %w", err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("reading the Tyk configuration %s: %w", path, err)
		}
	}
	strs := map[string]*string{
		"TYK_GW_LISTENADDRESS":              &cfg.ListenAddress,
		"TYK_GW_CONTROLAPIHOSTNAME":         &cfg.ControlAPIHostname,
		"TYK_GW_READINESSCHECKENDPOINTNAME": &cfg.ReadinessCheckEndpointName,
	}
	for name, field := range strs {
		if v, ok := lookup(name); ok && v != "" {
			*field = v
		}
	}
	ints := map[string]*int{"TYK_GW_LISTENPORT": &cfg.ListenPort, "TYK_GW_CONTROLAPIPORT": &cfg.ControlAPIPort}
	for name, field := range ints {
		if v, ok := lookup(name); ok && v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return cfg, fmt.Errorf("%s: %w", name, err)
			}
			*field = n
		}
	}
	if v, ok := lookup("TYK_GW_HTTPSERVEROPTIONS_USESSL"); ok && v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return cfg, fmt.Errorf("TYK_GW_HTTPSERVEROPTIONS_USESSL: %w", err)
		}
		cfg.HTTPServerOptions.UseSSL = parsed
	}
	return cfg, nil
}

// readyURL is where Tyk serves its readiness endpoint: the control API port
// when one is set, otherwise the listen port, on the listen address.
func readyURL(cfg tykConfig) string {
	port := cfg.ControlAPIPort
	if port == 0 {
		port = cfg.ListenPort
	}
	if port == 0 {
		port = 8080 // Tyk's default
	}
	host := loopbackFor(cfg.ListenAddress)
	scheme := "http"
	if cfg.HTTPServerOptions.UseSSL {
		scheme = "https"
	}
	name := cfg.ReadinessCheckEndpointName
	if name == "" {
		name = "ready"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/" + name
}

// loopbackFor is the address to probe a listener bound to host from inside
// the same container: loopback when it listens on every address, in the
// listener's own address family.
func loopbackFor(host string) string {
	ip := net.ParseIP(host)
	switch {
	case host == "" || (ip != nil && ip.Equal(net.IPv4zero)):
		return "127.0.0.1"
	case ip != nil && ip.IsUnspecified():
		return "::1"
	}
	return host
}

func checkReady(cfg tykConfig, timeout time.Duration) error {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// The gateway is in this container: a proxy configured for
			// upstream traffic must not carry the probe.
			Proxy: nil,
			// The gateway's certificate names its public host, not the
			// address the probe dials. The probe sends nothing secret and
			// reads only the status code.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	url := readyURL(cfg)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if cfg.ControlAPIHostname != "" {
		req.Host = cfg.ControlAPIHostname
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("the gateway did not answer at %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the gateway is not ready: %s answered %s", url, resp.Status)
	}
	return nil
}

// checkEnforcing returns the policy set the gateway's status report says it
// enforces, or an error when it enforces none and so denies every call.
func checkEnforcing(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("the gateway has not written its policy status to %s", path)
	}
	if err != nil {
		return "", fmt.Errorf("reading the policy status: %w", err)
	}
	var status policy.Status
	if err := json.Unmarshal(data, &status); err != nil {
		return "", fmt.Errorf("reading the policy status %s: %w", path, err)
	}
	if status.Enforcing == "" {
		return "", fmt.Errorf("the gateway enforces no policy set and denies every tool call (last outcome: %s)", status.Outcome)
	}
	return status.Enforcing, nil
}
