package main

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// probeAddress is where to reach a dashboard listening on listen from inside
// the same container: loopback when it listens on every address, in the
// listener's own address family.
func probeAddress(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("ADMIN_LISTEN %q: %w", listen, err)
	}
	ip := net.ParseIP(host)
	switch {
	case host == "" || (ip != nil && ip.Equal(net.IPv4zero)):
		host = "127.0.0.1"
	case ip != nil && ip.IsUnspecified():
		host = "::1"
	}
	return net.JoinHostPort(host, port), nil
}

// healthcheck asks the dashboard listening on listen, in this container,
// for /healthz. It is for container health checks; the images have no shell
// or HTTP client.
func healthcheck(listen string, timeout time.Duration) error {
	addr, err := probeAddress(listen)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: timeout,
		// The dashboard is in this container: a configured proxy must not
		// carry the probe.
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	url := "http://" + addr + "/healthz"
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("the dashboard did not answer at %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", url, resp.Status)
	}
	return nil
}
