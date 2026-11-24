package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/go-json-experiment/json/jsontext"
)

// DefinitionFingerprint identifies an upstream definition by its content: the
// SHA-256 of its canonical form, without the top-level _meta member, which
// carries protocol metadata rather than text a reviewer approves. In the
// canonical form object keys are sorted, whitespace is removed, strings are
// compared by their text rather than their escapes, and numbers keep their
// exact written form, so no two different values share a fingerprint.
func DefinitionFingerprint(definition []byte) (string, error) {
	// The decoder rejects repeated keys at any depth and reads each token once.
	dec := jsontext.NewDecoder(bytes.NewReader(definition))
	if dec.PeekKind() != '{' {
		return "", errors.New("definition must be a JSON object")
	}
	canonical, err := canonicalValue(dec, true)
	if err != nil {
		return "", err
	}
	if _, err := dec.ReadToken(); err != io.EOF {
		return "", errors.New("definition has data after the object")
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// canonicalValue reads one value from the decoder and returns its canonical
// form. At the top level the _meta member is left out.
func canonicalValue(dec *jsontext.Decoder, top bool) ([]byte, error) {
	switch dec.PeekKind() {
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		type member struct {
			key   string
			value []byte
		}
		var members []member
		for dec.PeekKind() != '}' {
			token, err := dec.ReadToken()
			if err != nil {
				return nil, err
			}
			key := token.String()
			value, err := canonicalValue(dec, false)
			if err != nil {
				return nil, err
			}
			if top && key == "_meta" {
				continue
			}
			members = append(members, member{key, value})
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		slices.SortFunc(members, func(a, b member) int { return strings.Compare(a.key, b.key) })
		out := []byte{'{'}
		for i, m := range members {
			if i > 0 {
				out = append(out, ',')
			}
			var err error
			if out, err = jsontext.AppendQuote(out, m.key); err != nil {
				return nil, err
			}
			out = append(append(out, ':'), m.value...)
		}
		return append(out, '}'), nil
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		out := []byte{'['}
		for first := true; dec.PeekKind() != ']'; first = false {
			value, err := canonicalValue(dec, false)
			if err != nil {
				return nil, err
			}
			if !first {
				out = append(out, ',')
			}
			out = append(out, value...)
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return append(out, ']'), nil
	case '"':
		token, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		return jsontext.AppendQuote(nil, token.String())
	default:
		// Numbers, true, false and null keep their exact text.
		value, err := dec.ReadValue()
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), value...), nil
	}
}
