package main

import (
	"bytes"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"strconv"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
)

// observed holds the definition each upstream last declared for each tool,
// as seen by this gateway.
var observed drift.Observations

// maxReply bounds a plain tools/list reply, or one streamed event, that the
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

// CheckResponse is a Tyk response hook. On a proxy under drift enforcement it
// checks tools/list replies, plain or streamed, so only approved definitions
// reach clients, and records what the upstream declared. Without a valid
// policy set the gateway cannot tell what is approved, so it withholds the
// list; calls are refused in that state anyway.
func CheckResponse(w http.ResponseWriter, res *http.Response, req *http.Request) {
	if ctx.GetMCPMethod(req) != "tools/list" || !underDriftReview(req) {
		return
	}
	proxy := ctx.GetOASDefinition(req).GetTykExtension().Info.ID
	// Each message is checked against the set active when it arrives, so a
	// long stream follows set changes.
	transform := func(message []byte) []byte {
		state := current()
		if state == nil {
			return drift.CheckFailed(message)
		}
		view, enforcing := state.Drift(proxy)
		if !enforcing {
			// The proxy left drift review while the reply was streaming; its
			// remaining messages pass as they would for any other proxy.
			return message
		}
		var declared []drift.Observation
		out := drift.FilterToolsList(message, view, limits, func(tool, fingerprint string, approved bool) {
			declared = append(declared, drift.Observation{Tool: tool, Fingerprint: fingerprint, Approved: approved})
		})
		observed.Record(proxy, declared, limits.MaxUnapprovedPerProxy)
		return out
	}
	// The reply now depends on the gateway's approvals as well as the
	// upstream, so upstream validators and freshness do not describe it.
	res.Header.Del("ETag")
	res.Header.Del("Last-Modified")
	res.Header.Set("Cache-Control", "private, no-cache")
	// Authorize asks for an uncompressed reply. One that is compressed anyway
	// cannot be checked, so it is not passed on.
	if res.Header.Get("Content-Encoding") != "" {
		res.Body.Close()
		replaceBody(res, drift.CheckFailed(nil))
		res.Header.Del("Content-Encoding")
		slog.Warn("Drift check refused a compressed tools/list reply", "proxy", proxy)
		return
	}
	if mediaType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type")); mediaType == "text/event-stream" {
		res.Body = drift.NewEventRewriter(res.Body, maxReply, transform)
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		return
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxReply+1))
	res.Body.Close()
	if err != nil || len(body) > maxReply {
		replaceBody(res, drift.CheckFailed(nil))
		return
	}
	replaceBody(res, transform(body))
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
