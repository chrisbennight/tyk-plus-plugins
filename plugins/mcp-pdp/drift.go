package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
)

// observed holds the definition each upstream last declared for each tool,
// as seen by this gateway.
var observed drift.Observations

// maxReply bounds a plain tools/list reply the gateway reads to check it.
const maxReply = 16 << 20

// CheckResponse is a Tyk response hook. On a proxy under drift enforcement it
// checks tools/list replies, plain or streamed, so only approved definitions
// reach clients, and records what the upstream declared. Without a valid
// policy set the gateway cannot tell what is approved, so it withholds the
// list; calls are refused in that state anyway.
func CheckResponse(w http.ResponseWriter, res *http.Response, req *http.Request) {
	if ctx.GetMCPMethod(req) != "tools/list" {
		return
	}
	oas := ctx.GetOASDefinition(req)
	if oas == nil || oas.GetTykExtension() == nil {
		return
	}
	proxy := oas.GetTykExtension().Info.ID
	transform := drift.CheckFailed
	if state := current(); state != nil {
		view, enforcing := state.Drift(proxy)
		if !enforcing {
			return
		}
		transform = func(message []byte) []byte {
			seen := map[string]string{}
			out := drift.FilterToolsList(message, view, func(name, fingerprint string) { seen[name] = fingerprint })
			observed.Record(proxy, seen)
			return out
		}
	}
	// A compressed reply cannot be checked, so it is not passed on.
	if res.Header.Get("Content-Encoding") != "" {
		res.Body.Close()
		replaceBody(res, drift.CheckFailed(nil))
		res.Header.Del("Content-Encoding")
		slog.Warn("Drift check refused a compressed tools/list reply", "proxy", proxy)
		return
	}
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		res.Body = drift.NewEventRewriter(res.Body, transform)
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
	res.Body = io.NopCloser(bytes.NewReader(body))
	res.ContentLength = int64(len(body))
	res.Header.Set("Content-Length", strconv.Itoa(len(body)))
}
