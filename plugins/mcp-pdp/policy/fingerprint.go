package policy

import (
	"bufio"
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
	root, err := canonicalValue(dec, true)
	if err != nil {
		return "", err
	}
	if _, err := dec.ReadToken(); err != io.EOF {
		return "", errors.New("definition has data after the object")
	}
	sum := sha256.New()
	root.writeTo(bufio.NewWriter(sum))
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// Canonical returns any JSON value in the canonical form fingerprints use,
// keeping every member, so two values compare equal exactly when they would
// fingerprint alike.
func Canonical(value []byte) (string, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(value))
	root, err := canonicalValue(dec, false)
	if err != nil {
		return "", err
	}
	if _, err := dec.ReadToken(); err != io.EOF {
		return "", errors.New("value has data after it")
	}
	var out bytes.Buffer
	w := bufio.NewWriter(&out)
	root.writeTo(w)
	return out.String(), nil
}

// InstructionsFingerprint identifies server instructions by the SHA-256 of
// their UTF-8 text.
func InstructionsFingerprint(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// canonical is a value in canonical form, kept as a tree so each byte is
// written once: copying a child's text into every enclosing level would make
// the work grow with depth times size.
type canonical struct {
	// text is a scalar's canonical text, or an object member's quoted key.
	text []byte
	// open and close are '{' and '}' or '[' and ']' for a container.
	open, close byte
	// children are an array's items, or an object's members sorted by key,
	// each a key node whose single child is the value.
	children []*canonical
}

func (c *canonical) writeTo(w *bufio.Writer) {
	defer w.Flush()
	c.write(w)
}

func (c *canonical) write(w *bufio.Writer) {
	if c.open == 0 {
		w.Write(c.text)
		if c.children != nil {
			w.WriteByte(':')
			c.children[0].write(w)
		}
		return
	}
	w.WriteByte(c.open)
	for i, child := range c.children {
		if i > 0 {
			w.WriteByte(',')
		}
		child.write(w)
	}
	w.WriteByte(c.close)
}

// canonicalValue reads one value from the decoder and returns its canonical
// form. At the top level the _meta member is left out.
func canonicalValue(dec *jsontext.Decoder, top bool) (*canonical, error) {
	switch dec.PeekKind() {
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		object := &canonical{open: '{', close: '}'}
		var keys []string
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
			quoted, err := jsontext.AppendQuote(nil, key)
			if err != nil {
				return nil, err
			}
			keys = append(keys, key)
			object.children = append(object.children, &canonical{text: quoted, children: []*canonical{value}})
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		order := make([]int, len(keys))
		for i := range order {
			order[i] = i
		}
		slices.SortFunc(order, func(a, b int) int { return strings.Compare(keys[a], keys[b]) })
		sorted := make([]*canonical, len(order))
		for i, at := range order {
			sorted[i] = object.children[at]
		}
		object.children = sorted
		return object, nil
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		array := &canonical{open: '[', close: ']'}
		for dec.PeekKind() != ']' {
			value, err := canonicalValue(dec, false)
			if err != nil {
				return nil, err
			}
			array.children = append(array.children, value)
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return array, nil
	case '"':
		token, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		text, err := jsontext.AppendQuote(nil, token.String())
		return &canonical{text: text}, err
	default:
		// Numbers, true, false and null keep their exact text.
		value, err := dec.ReadValue()
		if err != nil {
			return nil, err
		}
		return &canonical{text: append([]byte(nil), value...)}, nil
	}
}
