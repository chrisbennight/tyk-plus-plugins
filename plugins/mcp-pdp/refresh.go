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

// reviewedBy reports whether a set reviews a tool on a proxy under drift
// review, so only declarations that can affect calls are read.
func reviewedBy(state *policy.Snapshot) func(proxy, tool string) bool {
	return func(proxy, tool string) bool {
		if state == nil {
			return false
		}
		view, ok := state.Drift(proxy)
		return ok && view.Has(tool)
	}
}

// refreshShared reads the shared declarations for a set.
func refreshShared(state *policy.Snapshot) {
	version := ""
	if state != nil {
		version = state.Version
	}
	shared.Refresh(version, reviewedBy(state))
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
	// A stable name keeps a gateway's shared declarations in one file across
	// restarts; without one, the host name is used.
	gateway := os.Getenv("CEDAR_GATEWAY_ID")
	if gateway == "" {
		gateway, _ = os.Hostname()
	}
	shared = drift.OpenPending(os.Getenv("CEDAR_PENDING_DIR"), gateway, limits)
	reloader := policy.NewReloader(storeRoot, os.Getenv("CEDAR_STATUS_FILE"), &active)
	// A new set's shared declarations are read before it becomes active, so
	// calls never use it without them.
	reloader.BeforeActivate = refreshShared
	reloader.Load()
	go func() {
		for range time.Tick(interval) {
			reloader.Load()
			refreshShared(current())
		}
	}()
}
