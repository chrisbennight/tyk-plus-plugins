package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// baseline is the common set of checks every supported client version must
// pass against every supported upstream.
func baseline(k keys, version string) {
	// The newer protocol is used only when the upstream supports it; otherwise
	// the client falls back to the older handshake, as the specification requires.
	want := version
	if version == newerProtocol && os.Getenv("UPSTREAM_SUPPORTS_NEWER") != "true" {
		want = olderProtocol
	}
	// Publish the baseline's whole set at once, independent of what earlier checks staged.
	inventory, _ := json.Marshal(map[string]any{"governed": map[string]any{"upstream": upstream, "tools": map[string]any{
		"lookup": map[string]any{"facts": args("readOnly", true), "arguments": args("count", "long")},
		"change": map[string]any{"arguments": args("count", "long")},
	}}})
	publish("activated", map[string]string{"rules.cedar": exampleRules, "tools.json": string(inventory), "checks.json": "[]"})
	c := connect(k.operator, version)
	check(c.version == want, "%s client negotiated %s, want %s", version, c.version, want)
	catalog := catalogOf(c, k.operator)
	check(catalog["lookup"] != nil && catalog["change"] != nil, "%s client listed %v", version, catalog)

	// Exact checks: where each call went and how it was refused.
	call(c, k.support, "lookup", args("count", 1), "found")
	denied := call(c, k.support, "change", args("count", 2))
	unknown := call(c, k.support, "unknown", args("count", 2))
	check(sameRefusal(denied, unknown), "%s: hidden %+v, unknown %+v", version, denied, unknown)
	call(c, k.operator, "change", args("count", 2), "updated")
	call(c, bearerCred(token("published", args("app_roles", []string{"support"}))), "lookup", args(), "found")
	r := c.rpc(bearerCred(token("published", args("app_roles", []string{"support"}, "exp", nil))), "tools/list", map[string]any{})
	check(r.Status == http.StatusForbidden, "%s: unidentified caller listed tools: %d %+v", version, r.Status, r)

	// The same checks through a real MCP client.
	sdkBaseline(k, version, want)
	fmt.Printf("Verified the baseline for a %s client (using %s).\n", version, want)
}

type withHeaders struct{ cred credential }

func (t withHeaders) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	for name, value := range t.cred {
		req.Header.Set(name, value)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func sdkSession(ctx context.Context, cred credential, version string) *mcp.ClientSession {
	client := mcp.NewClient(&mcp.Implementation{Name: "probe-sdk", Version: "1"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: gateway, HTTPClient: &http.Client{Transport: withHeaders{cred}}}
	session, err := client.Connect(ctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: version})
	check(err == nil, "%s SDK client could not connect: %v", version, err)
	return session
}

func sdkBaseline(k keys, version, want string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, caller := range []struct {
		name string
		cred credential
	}{
		{"support key", k.support},
		{"support token", bearerCred(token("published", args("app_roles", []string{"support"})))},
	} {
		session := sdkSession(ctx, caller.cred, version)
		if result := session.InitializeResult(); result != nil {
			check(result.ProtocolVersion == want, "%s SDK client (%s) negotiated %s, want %s", version, caller.name, result.ProtocolVersion, want)
		}
		listing, err := session.ListTools(ctx, nil)
		check(err == nil, "%s SDK client (%s) could not list tools: %v", version, caller.name, err)
		names := map[string]bool{}
		for _, tool := range listing.Tools {
			names[tool.Name] = true
		}
		check(names["lookup"] && names["change"], "%s SDK client (%s) listed %v", version, caller.name, names)

		// A permitted call runs with the caller's arguments.
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "lookup", Arguments: args("count", 5)})
		check(err == nil && !result.IsError && len(result.Content) == 1, "%s SDK client (%s) permitted call: %v %+v", version, caller.name, err, result)
		text, ok := result.Content[0].(*mcp.TextContent)
		check(ok && text.Text == "found", "%s SDK client (%s) got %+v", version, caller.name, result.Content)
		_, seen := observed()
		check(sameJSON(seen, args("count", 5)), "%s SDK client (%s): upstream saw %v", version, caller.name, seen)

		// A denied call never runs: the upstream still holds the previous arguments.
		result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "change", Arguments: args("count", 41)})
		check(err != nil || (result != nil && result.IsError), "%s SDK client (%s) denied call succeeded: %+v", version, caller.name, result)
		_, seen = observed()
		check(sameJSON(seen, args("count", 5)), "%s SDK client (%s): denied call reached the upstream: %v", version, caller.name, seen)
		session.Close()
	}
}
