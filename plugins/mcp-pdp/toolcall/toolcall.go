// Package toolcall reads a tools/call request the one way the plug-in
// decides it.
//
// The upstream receives the client's original bytes and parses them with its
// own JSON parser, which may match member names regardless of letter case.
// A request is refused when its envelope holds a member such a parser could
// read in place of the one the plug-in read, so both read the same call.
package toolcall

import (
	"encoding/json"
	"errors"
	"strings"

	jsonv2 "github.com/go-json-experiment/json"
)

// ErrAmbiguous reports a member whose name differs from a name the gateway
// reads only by letter case, such as "Params" or "Arguments".
var ErrAmbiguous = errors.New("a member name differs from a name the gateway reads only by letter case")

// Call is a tools/call request as the plug-in reads it.
type Call struct {
	ID        json.RawMessage
	Method    string
	Name      string
	Arguments json.RawMessage
	Meta      json.RawMessage
}

// The members Tyk or the plug-in read, at the top level and in params.
var (
	envelopeNames = []string{"jsonrpc", "id", "method", "params"}
	paramsNames   = []string{"name", "arguments", "_meta"}
)

// Parse reads a tools/call request with exact member names, rejecting
// duplicate names and invalid UTF-8. It returns ErrAmbiguous for an envelope
// that a case-insensitive parser could read differently. On any error the
// returned call still holds the request ID when it could be read, for the
// refusal.
func Parse(body []byte) (Call, error) {
	var envelope struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params *struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Meta      json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	err := jsonv2.Unmarshal(body, &envelope)
	c := Call{ID: envelope.ID, Method: envelope.Method}
	if envelope.Params != nil {
		c.Name, c.Arguments, c.Meta = envelope.Params.Name, envelope.Params.Arguments, envelope.Params.Meta
	}
	if err != nil {
		return c, err
	}
	var members map[string]json.RawMessage
	if err := jsonv2.Unmarshal(body, &members); err != nil {
		return c, err
	}
	if ambiguous(members, envelopeNames) {
		return c, ErrAmbiguous
	}
	if envelope.Params != nil {
		var params map[string]json.RawMessage
		if err := jsonv2.Unmarshal(members["params"], &params); err != nil {
			return c, err
		}
		if ambiguous(params, paramsNames) {
			return c, ErrAmbiguous
		}
	}
	return c, nil
}

// ambiguous reports whether a member name is not exactly a known name but
// equals one under Unicode case folding, which also matches "ſ" to "s" and
// the Kelvin sign to "k".
func ambiguous(members map[string]json.RawMessage, known []string) bool {
	for name := range members {
		for _, k := range known {
			if name != k && strings.EqualFold(name, k) {
				return true
			}
		}
	}
	return false
}
