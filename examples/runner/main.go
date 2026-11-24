// Command runner checks a gateway against the examples' expected outcomes and
// prints example credentials for MCP clients.
//
//	runner run     check every row of expected.json in both protocol versions (the default)
//	runner env     print shell exports of example credentials for Claude Code and Codex
//	runner checks  print the policy set's activation checks, derived from expected.json
//
// Settings come from the environment; the defaults suit the examples' Compose network:
//
//	EXAMPLES_DIR  the examples directory (/examples)
//	GATEWAY_URL   the gateway under test (http://gateway:8080)
//	ISSUER_URL    the example token issuer (http://issuer:8000)
//	SERVER_URL    the mock servers' address pattern, %s being the server name (http://%s:8000)
//	CONTROL_URL   Tyk's control API, used to create keys (http://gateway:9696)
//	TYK_GW_SECRET the secret for Tyk's control API
//
// To check a gateway other than Tyk, set EXAMPLE_<NAME>_KEY for each key caller
// in callers/keys.json, and EXAMPLE_KEY_WITHOUT_METADATA_KEY for a key your
// gateway recognizes but that carries no identity; the runner then uses those
// keys instead of creating them through Tyk.
package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

func main() {
	command := "run"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	e, err := load(setting("EXAMPLES_DIR", "/examples"))
	if err != nil {
		fail(err)
	}
	switch command {
	case "run":
		if !run(e) {
			os.Exit(1)
		}
	case "env":
		printEnv(e)
	case "checks":
		out, err := e.checks()
		if err != nil {
			fail(err)
		}
		os.Stdout.Write(out)
	default:
		fail(fmt.Errorf("unknown command %q; use run, env or checks", command))
	}
}

// credentialText is the alphabet of JWTs and Tyk keys.
var credentialText = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func setting(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "runner:", err)
	os.Exit(2)
}

// envName turns a caller name into the variable suffix the client
// configurations use, for example "analyst" into "ANALYST".
func envName(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// printEnv prints exports for every example caller. Tokens expire after the
// deck's lifetime; run it again for fresh ones.
func printEnv(e *examples) {
	creds, err := newCredentials(e)
	if err != nil {
		fail(err)
	}
	var names []string
	for name := range e.deck.People {
		names = append(names, name)
	}
	for name := range e.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Println("# Example credentials for a local gateway. Never use them anywhere else.")
	for _, name := range names {
		c, err := creds.of(name)
		if err != nil {
			fail(err)
		}
		kind, value := "TOKEN", strings.TrimPrefix(c["Authorization"], "Bearer ")
		if key := c["X-API-Key"]; key != "" {
			kind, value = "KEY", key
		}
		// The output is meant for eval, so a value from the issuer or the
		// control API must be plain token characters before it is printed.
		if !credentialText.MatchString(value) {
			fail(fmt.Errorf("the %s for %s contains characters a token or key never has; refusing to print it", strings.ToLower(kind), name))
		}
		fmt.Printf("export EXAMPLE_%s_%s='%s'\n", envName(name), kind, value)
	}
}
