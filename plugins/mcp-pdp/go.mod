module github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp

go 1.26.5

require github.com/cedar-policy/cedar-go v1.9.3

require github.com/go-json-experiment/json v1.27.2

require github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol v0.0.0

require golang.org/x/exp v0.0.0-20220921023135-46d9e7742f1e // indirect

// The sandbox message format lives beside the sandbox host in this repository.
replace github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol => ../../sandbox/protocol
