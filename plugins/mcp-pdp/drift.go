package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"strconv"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// observed holds the definition each upstream last declared for each tool,
// as seen by this gateway.
var observed drift.Observations

// maxReply bounds a plain reply, or one streamed event, that the
// gateway reads to check it.
const maxReply = 16 << 20

// limits bound the work of checking lists. Both are configurable: an
// operator may approve larger definitions or expect more unapproved tools.
var limits = drift.Limits{
	MaxDefinitionBytes:    positiveSetting("CEDAR_PENDING_MAX_DEFINITION_BYTES", 256<<10),
	MaxUnapprovedPerProxy: positiveSetting("CEDAR_PENDING_MAX_PER_PROXY", 200),
}

func positiveSetting(variable string, fallback int) int {
	value := os.Getenv(variable)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		slog.Error("Invalid setting; using the default", "variable", variable, "value", value, "default", fallback)
		return fallback
	}
	return parsed
}

// checkedMethods are the methods whose replies CheckResponse reads: tool
// lists, and the handshakes that carry the server's instructions.
var checkedMethods = map[string]bool{"tools/list": true, "initialize": true, "server/discover": true}

// CheckResponse is a Tyk response hook. On a proxy under drift enforcement it
// checks tools/list, initialize and server/discover replies, plain or
// streamed, so only approved definitions and instructions reach clients, and
// records what the upstream declared for its tools. Without a valid policy
// set the gateway cannot tell what is approved, so it withholds lists and
// removes instructions; calls are refused in that state anyway.
func CheckResponse(w http.ResponseWriter, res *http.Response, req *http.Request) {
	method := ctx.GetMCPMethod(req)
	if !checkedMethods[method] {
		return
	}
	if !underDriftReview(req) {
		// The stream passes unparsed, but if drift review starts while it is
		// open, it ends rather than deliver an unchecked list.
		if mediaType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type")); mediaType == "text/event-stream" {
			res.Body = drift.UntilReview(res.Body, func() bool { return underDriftReview(req) })
		}
		return
	}
	proxy := ctx.GetOASDefinition(req).GetTykExtension().Info.ID
	upstream := ctx.GetOASDefinition(req).GetTykExtension().Upstream.URL
	// Each message is checked against the set active when it arrives, so a
	// long stream follows set changes.
	// A message is numbered as it is received: a plain reply when its
	// headers arrive, a streamed event when it is complete.
	check := func(received uint64, message []byte) []byte {
		state := current()
		// Without approvals to compare with, a list is withheld and
		// instructions are removed, so the session can still start.
		unchecked := func() []byte {
			if method == "tools/list" {
				return drift.Failed(requestID(req))
			}
			return drift.FilterInstructions(message, "", true, method == "server/discover", requestID(req))
		}
		if state == nil {
			return unchecked()
		}
		view, enforcing := state.Drift(proxy)
		if !enforcing {
			// The proxy left drift review while the reply was streaming; its
			// remaining messages pass as they would for any other proxy.
			return message
		}
		if view.Upstream() != upstream {
			// The proxy now targets an upstream other than the one reviewed;
			// calls to it are refused, so nothing it declares is passed on or
			// recorded against the reviewed tools.
			return unchecked()
		}
		if method != "tools/list" {
			approved, _ := state.Instructions(proxy)
			return drift.FilterInstructions(message, approved, view.StripInstructions(), method == "server/discover", requestID(req))
		}
		var declared []drift.Observation
		// Visibility is decided only when a list needs it, so errors and
		// notifications on the stream cost nothing extra.
		var visible map[string]bool
		isVisible := func(tool string) bool {
			if visible == nil {
				visible = state.VisibleTools(requestCaller(req), proxy)
			}
			return visible[tool]
		}
		out := drift.FilterToolsList(message, view, limits, requestID(req), isVisible, func(tool, fingerprint string, approved bool) {
			declared = append(declared, drift.Observation{Tool: tool, Fingerprint: fingerprint, Approved: approved})
		})
		observed.Record(proxy, received, declared, limits.MaxUnapprovedPerProxy)
		return out
	}
	plainReceived := observed.Received()
	// The reply now depends on the gateway's approvals as well as the
	// upstream, so upstream validators and freshness do not describe it.
	res.Header.Del("ETag")
	res.Header.Del("Last-Modified")
	res.Header.Set("Cache-Control", "private, no-cache")
	// Authorize asks for an uncompressed reply. One that is compressed anyway
	// cannot be checked, so it is not passed on.
	if res.Header.Get("Content-Encoding") != "" {
		res.Body.Close()
		replaceBody(res, drift.Failed(requestID(req)))
		res.Header.Del("Content-Encoding")
		slog.Warn("Drift check refused a compressed reply", "proxy", proxy, "method", method)
		return
	}
	if mediaType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type")); mediaType == "text/event-stream" {
		// The reply that answers the request ends the stream, as MCP servers
		// do, so a second reply cannot replace what the first recorded. What
		// the gateway sends is classified rather than what it received: a
		// rebuilt message is either a request or notification, or a reply.
		var stream *drift.EventRewriter
		stream = drift.NewEventRewriter(res.Body, maxReply, drift.Failed(requestID(req)), func(message []byte) []byte {
			out := check(observed.Received(), message)
			if !drift.CarriesMethod(out) {
				stream.End()
			}
			return out
		})
		res.Body = stream
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		return
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxReply+1))
	res.Body.Close()
	// A plain reply answers the request; only a stream may also carry the
	// upstream's own requests and notifications.
	if err != nil || len(body) > maxReply || drift.CarriesMethod(body) {
		replaceBody(res, drift.Failed(requestID(req)))
		return
	}
	replaceBody(res, check(plainReceived, body))
}

func replaceBody(res *http.Response, body []byte) {
	res.Header.Set("Content-Type", "application/json")
	res.Body = io.NopCloser(bytes.NewReader(body))
	res.ContentLength = int64(len(body))
	res.Header.Set("Content-Length", strconv.Itoa(len(body)))
}

// underDriftReview reports whether CheckResponse will read this request's
// reply: on a proxy under drift review, or on any proxy while the gateway has
// no valid set and so cannot tell.
func underDriftReview(req *http.Request) bool {
	oas := ctx.GetOASDefinition(req)
	if oas == nil || oas.GetTykExtension() == nil {
		return false
	}
	state := current()
	if state == nil {
		return true
	}
	_, enforcing := state.Drift(oas.GetTykExtension().Info.ID)
	return enforcing
}

// callerKey keys the caller of a tools/list request in its context, so the
// response hook can leave out tools the caller could never call.
type callerKey struct{}

// rememberCaller records the caller for CheckResponse.
func rememberCaller(r *http.Request, who policy.Caller) {
	*r = *r.WithContext(context.WithValue(r.Context(), callerKey{}, who))
}

// requestCaller returns the caller rememberCaller recorded. A request without
// one has an empty caller, which rules can tell from any identified caller.
func requestCaller(r *http.Request) policy.Caller {
	who, _ := r.Context().Value(callerKey{}).(policy.Caller)
	return who
}

// requestIDKey keys the JSON-RPC ID of a request whose reply CheckResponse
// reads, so the response hook can answer for that request and check that a
// result answers it.
type requestIDKey struct{}

// rememberRequestID records the request's JSON-RPC ID for CheckResponse. Tyk
// passes response hooks the request its middleware updated, so the request is
// replaced in place as Tyk's own context helpers do.
func rememberRequestID(r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		return
	}
	var envelope struct {
		ID jsontext.Value `json:"id"`
	}
	if jsonv2.Unmarshal(body, &envelope) != nil || len(envelope.ID) == 0 {
		return
	}
	*r = *r.WithContext(context.WithValue(r.Context(), requestIDKey{}, envelope.ID))
}

// requestID returns the ID rememberRequestID recorded, or nil.
func requestID(r *http.Request) jsontext.Value {
	id, _ := r.Context().Value(requestIDKey{}).(jsontext.Value)
	return id
}
