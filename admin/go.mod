module github.com/chrisbennight/tyk-plus-plugins/admin

go 1.26.5

require (
	github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp v0.0.0
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/go-json-experiment/json v1.27.2
	golang.org/x/oauth2 v0.38.0
)

require (
	github.com/cedar-policy/cedar-go v1.9.3 // indirect
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	golang.org/x/exp v0.0.0-20220921023135-46d9e7742f1e // indirect
)

// The dashboard uses the plug-in's review packages from this repository.
replace (
	github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp => ../plugins/mcp-pdp
	github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol => ../sandbox/protocol
)
