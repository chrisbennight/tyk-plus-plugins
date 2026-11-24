package main

import (
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/drift"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

// storeRoot is where the gateway reads the policy store.
const storeRoot = "/opt/tyk-gateway/cedar"

// active holds the configuration tool calls are decided against. Calls read it
// without locking or touching the filesystem; only the refresh loop replaces it.
var active atomic.Pointer[policy.Snapshot]

// The default interval keeps a promoted change visible within seconds while
// reading the store rarely.
const defaultRefreshInterval = 5 * time.Second

// reviewedTool reports whether the active set reviews a tool on a proxy under
// drift review, so only declarations that can affect calls are read.
func reviewedTool(proxy, tool string) bool {
	state := current()
	if state == nil {
		return false
	}
	view, ok := state.Drift(proxy)
	return ok && view.Has(tool)
}

// current returns the active configuration without blocking.
func current() *policy.Snapshot {
	return active.Load()
}

// The gateway loads the plug-in before it serves traffic, so the first
// configuration is loaded and the refresh loop started before any tool call.
func init() {
	interval := defaultRefreshInterval
	if value := os.Getenv("CEDAR_REFRESH_INTERVAL"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 {
			slog.Error("Invalid CEDAR_REFRESH_INTERVAL; using the default", "value", value, "default", interval.String())
		} else {
			interval = parsed
		}
	}
	gateway, _ := os.Hostname()
	pending, err := drift.OpenPending(os.Getenv("CEDAR_PENDING_DIR"), gateway, limits)
	if err != nil {
		// Calls are still decided on what this gateway sees itself.
		slog.Error("Could not open the drift review directory; declarations are not shared", "error", err)
		pending, _ = drift.OpenPending("", gateway, limits)
	}
	shared = pending
	reloader := policy.NewReloader(storeRoot, os.Getenv("CEDAR_STATUS_FILE"), &active)
	reloader.Load()
	shared.Refresh(reviewedTool)
	go func() {
		for range time.Tick(interval) {
			reloader.Load()
			shared.Refresh(reviewedTool)
		}
	}()
}
