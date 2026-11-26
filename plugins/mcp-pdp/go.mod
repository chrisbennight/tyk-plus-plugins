module github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp

go 1.26.5

require github.com/cedar-policy/cedar-go v1.9.3

require github.com/go-json-experiment/json v1.27.2

require github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol v0.0.0

require golang.org/x/exp v0.0.0-20220921023135-46d9e7742f1e // indirect

// Not imported by the plug-in. The gateway builds Tyk in the same Go
// workspace, so this raises the version Tyk is built with to one that fixes
// GHSA-mgcc-cww5-fp2q. Keep it until Tyk requires this version or later.
require github.com/go-jose/go-jose/v4 v4.1.6

// The sandbox message format lives beside the sandbox host in this repository.
replace github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol => ../../sandbox/protocol
