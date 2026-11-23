// Command probe exercises authorization through Tyk and counts the actual
// upstream dispatches. It runs inside the test Compose project.
package main

import (
	"fmt"
	"net/http"
	"os"
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
	for _, version := range []string{olderProtocol, newerProtocol} {
		baseline(k, version)
	}
	leaveRejectedSet(k)
}

func waitForGateway() {
	for range 30 {
		res, err := httpClient.Get("http://gateway:9696/hello")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				if up, err := httpClient.Get("http://upstream:8000/requests"); err == nil {
					up.Body.Close()
					return
				}
			}
		}
		time.Sleep(time.Second)
	}
	panic("gateway or upstream did not become ready")
}
