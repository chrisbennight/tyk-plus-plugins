// Package drift keeps unapproved upstream text away from clients. It checks
// tools/list replies against the approved definitions in the active policy
// set and decides whether a tool may be called given what the upstream last
// declared for it.
package drift

import (
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
func CallReason(view policy.DriftView, name, latest string, seen bool) string {
	approved, _, ok := view.Approved(name)
	switch {
	case !ok:
		return UnapprovedTool
	case seen && latest != approved:
		return UnapprovedDefinition
	}
	return ""
}

// FilterToolsList checks one JSON-RPC message answering tools/list. A tool
// whose upstream definition matches the approved one is sent as approved, so
// even its unfingerprinted _meta is reviewed text. A changed tool is left
// out, or shown with its approved definition when the proxy serves approved
// definitions. New tools are left out, and each tool is listed at most once.
// observe receives the fingerprint each approved tool's upstream declared, or
// "" when one reply declared it more than once with different definitions. A
// message that cannot be checked is replaced with an error, so unchecked
// upstream text never reaches the client.
func FilterToolsList(message []byte, view policy.DriftView, observe func(name, fingerprint string)) []byte {
	var envelope map[string]jsontext.Value
	if err := jsonv2.Unmarshal(message, &envelope); err != nil {
		return checkFailed(nil)
	}
	raw, ok := envelope["result"]
	if !ok {
		// Error replies, and requests and notifications sharing the stream,
		// carry no tool definitions. Anything else is not a valid message.
		if _, isError := envelope["error"]; isError {
			return message
		}
		if _, isRequest := envelope["method"]; isRequest {
			return message
		}
		return checkFailed(envelope["id"])
	}
	var result map[string]jsontext.Value
	if err := jsonv2.Unmarshal(raw, &result); err != nil {
		return checkFailed(envelope["id"])
	}
	listed, ok := result["tools"]
	if !ok {
		// A tools/list result must carry its tools.
		return checkFailed(envelope["id"])
	}
	var tools []jsontext.Value
	if err := jsonv2.Unmarshal(listed, &tools); err != nil {
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
		if _, _, ok := view.Approved(named.Name); !ok {
			continue
		}
		fingerprint, err := policy.DefinitionFingerprint(definition)
		if err != nil {
			fingerprint = ""
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
		observe(name, fingerprint)
		approved, approvedDefinition, _ := view.Approved(name)
		if fingerprint == approved || view.ServeApproved() {
			kept = append(kept, jsontext.Value(approvedDefinition))
		}
	}
	result["tools"], _ = jsonv2.Marshal(kept)
	envelope["result"], _ = jsonv2.Marshal(result)
	out, err := jsonv2.Marshal(envelope)
	if err != nil {
		return checkFailed(envelope["id"])
	}
	return out
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

// checkFailed is the error reply that replaces unchecked upstream text.
func checkFailed(id jsontext.Value) []byte {
	// Only a string or number is kept, so no other upstream content can ride
	// along in the gateway's own error.
	if len(id) == 0 || (id[0] != '"' && id[0] != '-' && (id[0] < '0' || id[0] > '9')) {
		id = jsontext.Value("null")
	}
	out, _ := jsonv2.Marshal(map[string]any{"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": -32603, "message": "Upstream reply could not be checked"}})
	return out
}
