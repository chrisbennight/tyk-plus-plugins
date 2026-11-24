package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gowebpki/jcs"
)

// DefinitionFingerprint identifies an upstream definition by its content: the
// SHA-256 of its RFC 8785 canonical JSON, without the top-level _meta member,
// which carries protocol metadata rather than text a reviewer approves.
// Field order and whitespace do not change it; any other change does.
func DefinitionFingerprint(definition []byte) (string, error) {
	// Canonicalizing the whole definition first rejects duplicate keys at any
	// depth, which the map below would otherwise silently collapse.
	if _, err := jcs.Transform(definition); err != nil {
		return "", fmt.Errorf("definition is not canonical JSON: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(definition, &fields); err != nil || fields == nil {
		return "", errors.New("definition must be a JSON object")
	}
	delete(fields, "_meta")
	trimmed, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(trimmed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
