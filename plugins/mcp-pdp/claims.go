package main

import (
	"os"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/identity"
)

// claimNames says which token claims carry roles, groups, and scopes. Each
// can be renamed, or set to an empty value to ignore that kind of claim.
var claimNames = identity.ClaimNames{
	Roles:  claimName("CEDAR_ROLES_CLAIM", "roles"),
	Groups: claimName("CEDAR_GROUPS_CLAIM", "groups"),
	Scopes: claimName("CEDAR_SCOPES_CLAIM", "scope"),
}

func claimName(variable, fallback string) string {
	if value, set := os.LookupEnv(variable); set {
		return value
	}
	return fallback
}
