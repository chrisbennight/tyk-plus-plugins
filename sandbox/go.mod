module github.com/chrisbennight/tyk-plus-plugins/sandbox

go 1.26.5

require (
	github.com/aperturerobotics/go-quickjs-wasi-reactor v0.15.2-0.20261120061749-69a91b9bfdb9
	github.com/aperturerobotics/go-quickjs-wasi-reactor/wazero-quickjs v0.0.0-20261120061749-69a91b9bfdb9
	github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol v0.0.0
	github.com/tetratelabs/wazero v1.12.0
)

require golang.org/x/sys v0.44.0 // indirect

// The message format is its own module, with no dependencies, so the gateway
// plug-in can share it without taking on the sandbox's dependencies.
replace github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol => ./protocol
