// Package identity turns what Tyk authenticated into the caller that Cedar sees.
package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

// Method names how the gateway identified a caller.
type Method string

const (
	Token Method = "token"
	Key   Method = "key"
)

// claimPrefix is how Tyk exposes the claims of a validated token in the
// request context. Only Tyk's token middleware writes entries with it.
const claimPrefix = "jwt_claims_"

// ClaimNames lists the token claims that hold roles, groups, and scopes.
// An empty name means the caller has none of that kind.
type ClaimNames struct {
	Roles, Groups, Scopes string
}

// Resolve identifies the caller. A validated token always wins, and its claims
// are the whole identity; key metadata applies only when no token was used.
func Resolve(context map[string]any, metadata map[string]any, names ClaimNames) (policy.Caller, Method, error) {
	for name := range context {
		if strings.HasPrefix(name, claimPrefix) {
			caller, err := fromClaims(context, names)
			return caller, Token, err
		}
	}
	caller, err := fromMetadata(metadata)
	return caller, Key, err
}

func fromClaims(context map[string]any, names ClaimNames) (policy.Caller, error) {
	var caller policy.Caller
	var err error
	if caller.Issuer, err = text(context, "iss"); err != nil {
		return policy.Caller{}, err
	}
	if caller.Subject, err = text(context, "sub"); err != nil {
		return policy.Caller{}, err
	}
	// Tyk rejects an expiry in the past but accepts a token with none. Such a
	// token would never lapse, so it cannot identify a caller.
	if _, ok := context[claimPrefix+"exp"].(float64); !ok {
		return policy.Caller{}, errors.New(`claim "exp" must be a number`)
	}
	for _, field := range []struct {
		claim string
		into  *[]string
	}{{names.Roles, &caller.Roles}, {names.Groups, &caller.Groups}, {names.Scopes, &caller.Scopes}} {
		if field.claim == "" {
			continue
		}
		value, present := context[claimPrefix+field.claim]
		if !present {
			continue
		}
		if *field.into, err = list(value); err != nil {
			return policy.Caller{}, fmt.Errorf("claim %q: %w", field.claim, err)
		}
	}
	return caller, nil
}

func text(context map[string]any, claim string) (string, error) {
	value, _ := context[claimPrefix+claim].(string)
	if value == "" {
		return "", fmt.Errorf("claim %q must be a non-empty string", claim)
	}
	return value, nil
}

// list accepts a JSON array of strings or a space-separated string, the two
// shapes identity providers use for roles, groups, and scopes. A claim that is
// present with any other value, including null, is malformed.
func list(value any) ([]string, error) {
	switch v := value.(type) {
	case string:
		return strings.Fields(v), nil
	case []any:
		items := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, errors.New("must contain only strings")
			}
			items = append(items, s)
		}
		return items, nil
	default:
		return nil, errors.New("must be a string or a list of strings")
	}
}

func fromMetadata(metadata map[string]any) (policy.Caller, error) {
	var caller policy.Caller
	data, err := json.Marshal(metadata["cedar"])
	if err == nil {
		err = json.Unmarshal(data, &caller)
	}
	if err != nil {
		return policy.Caller{}, err
	}
	if caller.Issuer == "" || caller.Subject == "" {
		return policy.Caller{}, errors.New("key metadata needs cedar.issuer and cedar.subject")
	}
	return caller, nil
}

// Expiry returns when the caller's validated token expires, from its exp
// claim, and false when no token identified the caller.
func Expiry(context map[string]any) (time.Time, bool) {
	exp, ok := context[claimPrefix+"exp"].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(exp), 0), true
}
