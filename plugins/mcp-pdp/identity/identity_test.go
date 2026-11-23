package identity

import (
	"reflect"
	"testing"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

var names = ClaimNames{Roles: "roles", Groups: "groups", Scopes: "scope"}

func TestTokenClaimsBecomeTheCaller(t *testing.T) {
	context := map[string]any{
		"jwt_claims_iss": "https://idp.example", "jwt_claims_sub": "alice",
		"jwt_claims_roles": []any{"support"}, "jwt_claims_groups": "team-a team-b",
		"jwt_claims_scope": "mcp:call", "headers_Authorization": "Bearer secret",
	}
	metadata := map[string]any{"cedar": map[string]any{"issuer": "keys", "subject": "service", "roles": []any{"operator"}}}
	caller, method, err := Resolve(context, metadata, names)
	want := policy.Caller{Issuer: "https://idp.example", Subject: "alice", Roles: []string{"support"},
		Groups: []string{"team-a", "team-b"}, Scopes: []string{"mcp:call"}}
	if err != nil || method != Token || !reflect.DeepEqual(caller, want) {
		t.Fatalf("got %+v %q %v", caller, method, err)
	}
}

func TestTokenWithoutIssuerOrSubjectIsRejected(t *testing.T) {
	for _, context := range []map[string]any{
		{"jwt_claims_sub": "alice"},
		{"jwt_claims_iss": "https://idp.example", "jwt_claims_sub": 7.0},
		{"jwt_claims_alg": "RS256"},
	} {
		// Key metadata must never stand in for a token that lacks an identity.
		metadata := map[string]any{"cedar": map[string]any{"issuer": "keys", "subject": "service"}}
		if _, method, err := Resolve(context, metadata, names); err == nil || method != Token {
			t.Fatalf("%v: got %q %v", context, method, err)
		}
	}
}

func TestMalformedListClaimIsRejected(t *testing.T) {
	context := map[string]any{"jwt_claims_iss": "i", "jwt_claims_sub": "s", "jwt_claims_roles": []any{"a", 1.0}}
	if _, _, err := Resolve(context, nil, names); err == nil {
		t.Fatal("accepted a non-string role")
	}
	context["jwt_claims_roles"] = map[string]any{"a": true}
	if _, _, err := Resolve(context, nil, names); err == nil {
		t.Fatal("accepted an object as roles")
	}
}

func TestUnmappedClaimsAreIgnored(t *testing.T) {
	context := map[string]any{"jwt_claims_iss": "i", "jwt_claims_sub": "s", "jwt_claims_roles": []any{"operator"}}
	caller, _, err := Resolve(context, nil, ClaimNames{})
	if err != nil || caller.Roles != nil {
		t.Fatalf("got %+v %v", caller, err)
	}
}

func TestKeyMetadataIdentifiesServiceAccounts(t *testing.T) {
	metadata := map[string]any{"cedar": map[string]any{"issuer": "keys", "subject": "indexer", "roles": []any{"support"}}}
	caller, method, err := Resolve(map[string]any{"headers_Authorization": "k"}, metadata, names)
	want := policy.Caller{Issuer: "keys", Subject: "indexer", Roles: []string{"support"}}
	if err != nil || method != Key || !reflect.DeepEqual(caller, want) {
		t.Fatalf("got %+v %q %v", caller, method, err)
	}
	for _, bad := range []map[string]any{nil, {"cedar": "x"}, {"cedar": map[string]any{"subject": "s"}}} {
		if _, _, err := Resolve(nil, bad, names); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}
