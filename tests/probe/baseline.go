package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// baseline is the common set of checks every supported client version must
// pass against every supported upstream.
func baseline(k keys, version string) {
	// UPSTREAM_DISCOVERY says what server/discover does on this upstream. A
	// newer client uses the newer version only when it is offered and otherwise
	// falls back to the older handshake, as the specification requires.
	discovery := os.Getenv("UPSTREAM_DISCOVERY")
	want := version
	if version == newerProtocol && discovery != discoveryNewer {
		want = olderProtocol
	}
	// Publish the baseline's whole set at once, independent of what earlier checks staged.
	inventory, _ := json.Marshal(map[string]any{"governed": map[string]any{"upstream": upstream, "tools": map[string]any{
		"lookup": map[string]any{"facts": args("readOnly", true), "arguments": args("count", "long")},
		"change": map[string]any{"arguments": args("count", "long")},
	}}})
	publish("activated", map[string]string{"rules.cedar": exampleRules, "approved_tools.json": string(inventory), "approved_instructions.json": "{}", "checks.json": "[]"})
	connectBefore, _ := observed()
	c := connect(k.operator, version)
	connectAfter, _ := observed()
	if version == newerProtocol && discovery == discoveryUnsupported {
		// The discovery attempt, the older handshake and its notification all
		// reached the upstream: the fallback followed the upstream's own answer.
		check(connectAfter-connectBefore == 3, "%s client: %d requests reached the upstream while connecting, want 3", version, connectAfter-connectBefore)
	}
	check(c.version == want, "%s client negotiated %s, want %s", version, c.version, want)
	if version == newerProtocol {
		check(c.discovery == discovery, "%s client saw discovery %q, want %q", version, c.discovery, discovery)
		if discovery == discoveryUnsupported {
			// Through Tyk the reason is reported as Tyk's own error, so confirm it
			// at the source: the upstream itself rejects the newer version.
			rejects, reply := upstreamRejectsNewer()
			check(rejects, "%s: the upstream did not reject the newer version: %s", version, reply)
		}
	}
	catalog := catalogOf(c, k.operator)
	check(catalog["lookup"] != nil && catalog["change"] != nil, "%s client listed %v", version, catalog)
	// The upstream must really use the transport this job declares.
	streamed, sessions := os.Getenv("UPSTREAM_STREAM") != "", os.Getenv("UPSTREAM_SESSIONS") != ""
	check(c.lastStreamed == streamed, "%s client: streamed reply %v, want %v", version, c.lastStreamed, streamed)
	// Some releases issue a session ID even when stateless, so only a job that
	// declares sessions is checked: it must receive one.
	if c.version == olderProtocol && sessions {
		check(c.session != "", "%s client: no session from an upstream that keeps sessions", version)
	}

	// Exact checks: where each call went and how it was refused.
	call(c, k.support, "lookup", args("count", 1), "found")
	// A permitted call's reply comes from the upstream, in the job's reply format.
	check(c.lastStreamed == streamed, "%s client: streamed tool-call reply %v, want %v", version, c.lastStreamed, streamed)
	// The gateway speaks to the upstream in the version the client negotiated.
	check(upstreamVersion() == want, "%s client: the gateway used %q upstream, want %q", version, upstreamVersion(), want)
	denied := call(c, k.support, "change", args("count", 2))
	unknown := call(c, k.support, "unknown", args("count", 2))
	check(sameRefusal(denied, unknown), "%s: hidden %v, unknown %v", version, denied, unknown)
	// Malformed arguments must not reveal a hidden tool either.
	malformedHidden := call(c, k.support, "change", args("count", "wrong"))
	malformedUnknown := call(c, k.support, "unknown", args("count", "wrong"))
	check(sameRefusal(malformedHidden, malformedUnknown) && sameRefusal(malformedHidden, denied), "%s: malformed hidden %v, unknown %v", version, malformedHidden, malformedUnknown)
	call(c, k.operator, "change", args("count", 2), "updated")
	supportToken := bearerCred(token("published", args("app_roles", []string{"support"})))
	call(c, supportToken, "lookup", args(), "found")
	tokenDenied := call(c, supportToken, "change", args("count", 2))
	tokenUnknown := call(c, supportToken, "unknown", args("count", 2))
	check(sameRefusal(tokenDenied, tokenUnknown) && sameRefusal(tokenDenied, denied), "%s: token caller hidden %v, unknown %v", version, tokenDenied, tokenUnknown)
	// A caller that cannot be identified is refused on every method. So is a
	// request carrying both a key and a token, whichever of them is valid: it
	// has no single caller, and is refused before either is tried.
	unidentified := bearerCred(token("published", args("app_roles", []string{"support"}, "exp", nil)))
	for _, refusal := range []struct {
		name string
		cred credential
	}{
		{"unidentified caller", unidentified},
		{"key and token", k.support.with(supportToken)},
		{"unknown key and token", keyCred("not-a-key").with(supportToken)},
	} {
		call(c, refusal.cred, "lookup", args())
		before, _ := observed()
		r := c.rpc(refusal.cred, "tools/list", map[string]any{})
		after, _ := observed()
		check(r.Status == http.StatusForbidden && r.Error != nil && r.Error.Message == "Caller not identified" && after == before,
			"%s: %s listed tools: %v (requests %d -> %d)", version, refusal.name, r, before, after)
		if c.version == olderProtocol {
			before, _ = observed()
			status := c.notifyStatus(refusal.cred, "notifications/initialized")
			after, _ = observed()
			check(status == http.StatusForbidden && after == before, "%s: %s's notification got %d (requests %d -> %d)", version, refusal.name, status, before, after)
		}
		// Neither handshake lets the request reach the upstream.
		for _, handshake := range []struct{ version, method string }{{olderProtocol, "initialize"}, {newerProtocol, "server/discover"}} {
			before, _ := observed()
			fresh := &conn{url: gateway, version: handshake.version}
			r := fresh.rpc(refusal.cred, handshake.method, map[string]any{"protocolVersion": olderProtocol, "capabilities": map[string]any{},
				"clientInfo": map[string]any{"name": "probe", "version": "1"}})
			after, _ := observed()
			check(r.Status == http.StatusForbidden && r.Error != nil && r.Error.Message == "Caller not identified" && after == before,
				"%s: %s's %s was not refused before the upstream: %v (requests %d -> %d)", version, refusal.name, handshake.method, r, before, after)
		}
	}

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
	// A caller that cannot be identified cannot even connect.
	client := mcp.NewClient(&mcp.Implementation{Name: "probe-sdk", Version: "1"}, nil)
	unidentified := bearerCred(token("published", args("app_roles", []string{"support"}, "exp", nil)))
	transport := &mcp.StreamableClientTransport{Endpoint: gateway, HTTPClient: &http.Client{Transport: withHeaders{unidentified}}}
	session, err := client.Connect(ctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err == nil {
		session.Close()
	}
	check(err != nil && isRefusal(err), "%s SDK client without an identifiable caller: %v", version, err)

	for _, caller := range []struct {
		name string
		cred credential
	}{
		{"support key", k.support},
		{"support token", bearerCred(token("published", args("app_roles", []string{"support"})))},
	} {
		session := sdkSession(ctx, caller.cred, version)
		result := session.InitializeResult()
		check(result != nil && result.ProtocolVersion == want, "%s SDK client (%s) negotiated %+v, want %s", version, caller.name, result, want)
		listing, err := session.ListTools(ctx, nil)
		check(err == nil, "%s SDK client (%s) could not list tools: %v", version, caller.name, err)
		names := map[string]bool{}
		for _, tool := range listing.Tools {
			names[tool.Name] = true
		}
		check(names["lookup"] && names["change"], "%s SDK client (%s) listed %v", version, caller.name, names)

		// A permitted call reaches the upstream exactly once with the caller's arguments.
		before, _ := observed()
		called, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "lookup", Arguments: args("count", 5)})
		after, seen := observed()
		check(err == nil && !called.IsError && len(called.Content) == 1, "%s SDK client (%s) permitted call: %v %+v", version, caller.name, err, called)
		text, ok := called.Content[0].(*mcp.TextContent)
		check(ok && text.Text == "found", "%s SDK client (%s) got %+v", version, caller.name, called.Content)
		check(after == before+1 && sameJSON(seen, args("count", 5)), "%s SDK client (%s): requests %d -> %d, upstream saw %v", version, caller.name, before, after, seen)
		check(upstreamVersion() == want, "%s SDK client (%s): the gateway used %q upstream, want %q", version, caller.name, upstreamVersion(), want)

		// A denied call and an unknown tool never reach the upstream, and the
		// client cannot tell them apart.
		var refusals []string
		for _, name := range []string{"change", "unknown"} {
			before, _ = observed()
			called, err = session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args("count", 41)})
			after, _ = observed()
			check(err != nil && isRefusal(err), "%s SDK client (%s) call to %s was not refused by the gateway: %v %+v", version, caller.name, name, err, called)
			check(after == before, "%s SDK client (%s): call to %s reached the upstream (%d -> %d)", version, caller.name, name, before, after)
			refusals = append(refusals, err.Error())
		}
		check(refusals[0] == refusals[1], "%s SDK client (%s): hidden %q, unknown %q", version, caller.name, refusals[0], refusals[1])
		session.Close()
	}
}

// isRefusal reports whether an SDK error is one of the gateway's refusals
// rather than a transport failure.
func isRefusal(err error) bool {
	text := err.Error()
	return strings.Contains(text, "Tool call denied") || strings.Contains(text, "Caller not identified") || strings.Contains(text, "403")
}
