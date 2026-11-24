// Package drift keeps unapproved upstream text away from clients. It checks
// tools/list replies against the approved definitions in the active policy
// set and decides whether a tool may be called given what the upstream last
// declared for it.
package drift

import (
	"bytes"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

// Reasons a call to a tool is refused before Cedar decides it. Clients see the
// same refusal as for an unknown tool; the decision log records the reason.
const (
	UnapprovedTool       = "unapproved_tool"
	UnapprovedDefinition = "unapproved_definition"
)

// CallReason returns why a tool may not be called on a proxy under drift
// enforcement, or "" if Cedar should decide. latest is the fingerprint of the
// definition the upstream last declared for the tool, if any was seen.
// complete reports whether the gateway records every tool the proxy's
// upstream declares; when it does not, an unseen tool may have been dropped
// at the limit, so it is refused until a list shows its definition.
func CallReason(view policy.DriftView, name, latest string, seen, complete bool) string {
	approved, _, ok := view.Approved(name)
	switch {
	case !ok:
		return UnapprovedTool
	case seen && latest != approved, !seen && !complete:
		return UnapprovedDefinition
	}
	return ""
}

// Limits bound the work and memory of checking upstream lists.
type Limits struct {
	// MaxDefinitionBytes is the largest upstream definition the gateway
	// fingerprints. A larger one counts as a changed definition.
	MaxDefinitionBytes int
	// MaxUnapprovedPerProxy bounds how many tools without approval the
	// gateway remembers for each proxy.
	MaxUnapprovedPerProxy int
}

// FilterToolsList checks one JSON-RPC message answering tools/list. A tool
// whose upstream definition matches the approved one is sent as approved, so
// even its unfingerprinted _meta is reviewed text. A changed tool is left
// out, or shown with its approved definition when the proxy serves approved
// definitions. New tools are left out, and each tool is listed at most once.
// observe receives the fingerprint the upstream declared for each tool, ""
// when it cannot be fingerprinted or one reply declared it more than once
// with different definitions, and whether the tool is approved. A message
// that cannot be checked is replaced with an error, so unchecked upstream
// text never reaches the client.
//
// request is the ID of the tools/list request being answered, when known. A
// result answering any other ID is not a reply to this request: it is
// refused and nothing it declares is recorded.
func FilterToolsList(message []byte, view policy.DriftView, limits Limits, request jsontext.Value, observe func(name, fingerprint string, approved bool)) []byte {
	var envelope map[string]jsontext.Value
	if err := jsonv2.Unmarshal(message, &envelope); err != nil {
		return checkFailed(nil)
	}
	if string(envelope["jsonrpc"]) != `"2.0"` || !validID(envelope["id"]) {
		return checkFailed(envelope["id"])
	}
	// Every message passed on is rebuilt from the members JSON-RPC defines,
	// spelled exactly, so a client that matches names loosely cannot find
	// unchecked text under a variant spelling.
	keep := func(from map[string]jsontext.Value, names ...string) map[string]jsontext.Value {
		out := map[string]jsontext.Value{}
		for _, name := range names {
			if value, ok := from[name]; ok {
				out[name] = value
			}
		}
		return out
	}
	encode := func(rebuilt map[string]jsontext.Value) []byte {
		out, err := jsonv2.Marshal(rebuilt, jsonv2.Deterministic(true))
		if err != nil {
			return checkFailed(envelope["id"])
		}
		return out
	}
	raw, ok := envelope["result"]
	if !ok {
		// Error replies, and requests and notifications sharing the stream,
		// carry no tool definitions. Anything else is not a valid message.
		switch {
		case envelope["error"] != nil:
			// Only the error code passes on. The upstream's message and data
			// are text no one reviewed, so a fixed message replaces them.
			var failure struct {
				Code    *int64  `json:"code"`
				Message *string `json:"message"`
			}
			if jsonv2.Unmarshal(envelope["error"], &failure) != nil || failure.Code == nil || failure.Message == nil {
				return checkFailed(envelope["id"])
			}
			rebuilt := keep(envelope, "jsonrpc", "id")
			rebuilt["error"], _ = jsonv2.Marshal(map[string]any{"code": *failure.Code, "message": "Upstream could not list tools"})
			return encode(rebuilt)
		case envelope["method"] != nil:
			if method := envelope["method"]; method[0] != '"' {
				return checkFailed(envelope["id"])
			}
			return encode(keep(envelope, "jsonrpc", "id", "method", "params"))
		default:
			return checkFailed(envelope["id"])
		}
	}
	if len(request) > 0 && !SameID(envelope["id"], request) {
		return checkFailed(envelope["id"])
	}
	var result map[string]jsontext.Value
	if err := jsonv2.Unmarshal(raw, &result); err != nil {
		return checkFailed(envelope["id"])
	}
	listed, ok := result["tools"]
	if !ok || len(listed) == 0 || listed[0] != '[' {
		// A tools/list result must carry its tools as an array.
		return checkFailed(envelope["id"])
	}
	var tools []jsontext.Value
	if err := jsonv2.Unmarshal(listed, &tools); err != nil {
		return checkFailed(envelope["id"])
	}
	if cursor, ok := result["nextCursor"]; ok && (len(cursor) == 0 || cursor[0] != '"') {
		return checkFailed(envelope["id"])
	}
	var order []string
	declared := map[string]string{}
	for _, definition := range tools {
		var named struct {
			Name string `json:"name"`
		}
		// Names match exactly, as the policy set reads them.
		if jsonv2.Unmarshal(definition, &named) != nil || named.Name == "" {
			continue
		}
		fingerprint := ""
		if len(definition) <= limits.MaxDefinitionBytes {
			fingerprint, _ = policy.DefinitionFingerprint(definition)
		}
		previous, repeated := declared[named.Name]
		switch {
		case !repeated:
			order = append(order, named.Name)
			declared[named.Name] = fingerprint
		case previous != fingerprint:
			// Conflicting definitions of one tool match nothing.
			declared[named.Name] = ""
		}
	}
	kept := make([]jsontext.Value, 0, len(order))
	for _, name := range order {
		fingerprint := declared[name]
		approved, approvedDefinition, ok := view.Approved(name)
		observe(name, fingerprint, ok)
		if ok && (fingerprint == approved || view.ServeApproved()) {
			kept = append(kept, jsontext.Value(approvedDefinition))
		}
	}
	// Result metadata is upstream text no one reviewed, so only the cursor
	// that pages the list is kept.
	rebuiltResult := keep(result, "nextCursor")
	rebuiltResult["tools"], _ = jsonv2.Marshal(kept)
	rebuilt := keep(envelope, "jsonrpc", "id")
	rebuilt["result"], _ = jsonv2.Marshal(rebuiltResult)
	return encode(rebuilt)
}

// CarriesMethod reports whether a message is a request or notification
// rather than a reply.
func CarriesMethod(message []byte) bool {
	var envelope map[string]jsontext.Value
	return jsonv2.Unmarshal(message, &envelope) == nil && envelope["method"] != nil
}

// CheckFailed replaces a whole reply the gateway cannot check, keeping its
// request ID when the reply is readable enough to have one.
func CheckFailed(message []byte) []byte {
	var envelope struct {
		ID jsontext.Value `json:"id"`
	}
	_ = jsonv2.Unmarshal(message, &envelope)
	return checkFailed(envelope.ID)
}

// Failed is the gateway's error reply for a list it could not check,
// answering the request with this ID ("null" when it is unknown).
func Failed(request jsontext.Value) []byte { return checkFailed(request) }

// SameID reports whether two JSON-RPC IDs are the same value. IDs are strings
// or numbers, compared by their canonical JSON.
func SameID(a, b jsontext.Value) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	x, y := a.Clone(), b.Clone()
	if x.Canonicalize() != nil || y.Canonicalize() != nil {
		return false
	}
	return bytes.Equal(x, y)
}

// checkFailed is the error reply that replaces unchecked upstream text.
// validID reports whether a message's ID is absent, as for a
// notification, or a string, number or null, as JSON-RPC allows.
func validID(id jsontext.Value) bool {
	return len(id) == 0 || id[0] == '"' || id[0] == '-' || id[0] >= '0' && id[0] <= '9' || string(id) == "null"
}

func checkFailed(id jsontext.Value) []byte {
	// Only a valid ID is kept, so no other upstream content can ride along
	// in the gateway's own error.
	if len(id) == 0 || !validID(id) {
		id = jsontext.Value("null")
	}
	out, _ := jsonv2.Marshal(map[string]any{"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": -32603, "message": "Upstream reply could not be checked"}})
	return out
}
