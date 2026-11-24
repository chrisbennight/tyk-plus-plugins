package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// DefinitionFingerprint identifies an upstream definition by its content: the
// SHA-256 of its canonical form, without the top-level _meta member, which
// carries protocol metadata rather than text a reviewer approves. In the
// canonical form object keys are sorted, whitespace is removed, strings are
// compared by their text rather than their escapes, and numbers keep their
// exact written form, so no two different values share a fingerprint.
func DefinitionFingerprint(definition []byte) (string, error) {
	var fields map[string]jsontext.Value
	if err := jsonv2.Unmarshal(definition, &fields); err != nil || fields == nil {
		return "", errors.New("definition must be a JSON object without repeated keys")
	}
	delete(fields, "_meta")
	canonical, err := canonicalObject(nil, fields)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalObject(out []byte, fields map[string]jsontext.Value) ([]byte, error) {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out = append(out, '{')
	for i, key := range keys {
		if i > 0 {
			out = append(out, ',')
		}
		var err error
		if out, err = jsontext.AppendQuote(out, key); err != nil {
			return nil, err
		}
		out = append(out, ':')
		if out, err = canonicalValue(out, fields[key]); err != nil {
			return nil, err
		}
	}
	return append(out, '}'), nil
}

// canonicalValue appends one value. The JSON library rejects repeated keys
// at every depth while decoding.
func canonicalValue(out []byte, value jsontext.Value) ([]byte, error) {
	switch value.Kind() {
	case '{':
		var fields map[string]jsontext.Value
		if err := jsonv2.Unmarshal(value, &fields); err != nil {
			return nil, err
		}
		return canonicalObject(out, fields)
	case '[':
		var items []jsontext.Value
		if err := jsonv2.Unmarshal(value, &items); err != nil {
			return nil, err
		}
		out = append(out, '[')
		for i, item := range items {
			if i > 0 {
				out = append(out, ',')
			}
			var err error
			if out, err = canonicalValue(out, item); err != nil {
				return nil, err
			}
		}
		return append(out, ']'), nil
	case '"':
		var text string
		if err := jsonv2.Unmarshal(value, &text); err != nil {
			return nil, err
		}
		return jsontext.AppendQuote(out, text)
	default:
		// Numbers, true, false and null keep their exact text.
		compact := value.Clone()
		if err := compact.Compact(); err != nil {
			return nil, err
		}
		return append(out, compact...), nil
	}
}
