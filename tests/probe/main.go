// Command probe exercises authorization through Tyk and counts the actual
// upstream dispatches. It runs inside the test Compose project.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	defer func() {
		if failure := recover(); failure != nil {
			fmt.Fprintln(os.Stderr, "FAILED:", failure)
			os.Exit(1)
		}
	}()
	waitForGateway()
	if os.Getenv("PROBE_PHASE") == "restarted" {
		restarted()
		return
	}
	k := keys{keyCred(key("support")), keyCred(key("operator")), keyCred(key("guest"))}
	policySuite(k)
	codeModeSuite(k)
	for _, version := range []string{olderProtocol, newerProtocol} {
		baseline(k, version)
		driftSuite(k, version)
		exchangeSuite(k, version)
	}
	leaveRejectedSet(k)
}

// waitForGateway waits until Tyk reports healthy, the governed API answers
// (an unloaded API returns 404), and the upstream is reachable. The peer
// gateway must be ready too.
func waitForGateway() {
	for range 60 {
		if healthy("gateway") && healthy("gateway-peer") && apiLoaded(gateway) && apiLoaded(secondGateway) && apiLoaded(exchangeGateway) && apiLoaded(peerGateway) && upstreamUp() {
			return
		}
		time.Sleep(time.Second)
	}
	panic("gateway or upstream did not become ready")
}

func healthy(host string) bool {
	res, err := httpClient.Get("http://" + host + ":9696/hello")
	if err != nil {
		return false
	}
	defer res.Body.Close()
	var health struct{ Status string }
	return json.NewDecoder(res.Body).Decode(&health) == nil && health.Status == "pass"
}

func apiLoaded(url string) bool {
	res, err := httpClient.Post(url, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":0,"method":"tools/list"}`))
	if err != nil {
		return false
	}
	res.Body.Close()
	return res.StatusCode != http.StatusNotFound
}

func upstreamUp() bool {
	res, err := httpClient.Get("http://upstream:8000/requests")
	if err != nil {
		return false
	}
	res.Body.Close()
	return true
}
