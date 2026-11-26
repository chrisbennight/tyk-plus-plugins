module github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp

go 1.26.5

require github.com/cedar-policy/cedar-go v1.9.3

require github.com/go-json-experiment/json v1.27.2

require github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol v0.0.0

require golang.org/x/exp v0.0.0-20220921023135-46d9e7742f1e // indirect

// Not imported by the plug-in. The gateway builds Tyk in the same Go
// workspace, so these raise the versions Tyk is built with to ones that fix
// known vulnerabilities, with the modules those versions need. Remove each
// once Tyk itself requires that version or later.
require (
	github.com/apache/thrift v0.25.0
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/go-jose/go-jose/v4 v4.1.6
	github.com/gobwas/httphead v0.1.0
	github.com/gobwas/ws v1.5.0
	github.com/klauspost/compress v1.20.2
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/sdk v1.47.0
	go.opentelemetry.io/otel/trace v1.47.0
	golang.org/x/crypto v0.59.0
	golang.org/x/net v0.62.0
)

// The sandbox message format lives beside the sandbox host in this repository.
replace github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol => ../../sandbox/protocol
