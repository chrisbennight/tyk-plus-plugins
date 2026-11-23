package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

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
	r := reloader{statusFile: os.Getenv("CEDAR_STATUS_FILE")}
	r.load()
	go func() {
		for range time.Tick(interval) {
			r.load()
		}
	}()
}

// Status reports which policy set a gateway enforces and the outcome of its
// most recent evaluation of the active pointer.
type status struct {
	Enforcing      string `json:"enforcing"`
	EnforcingLabel string `json:"enforcingLabel,omitempty"`
	Active         string `json:"active"`
	Outcome        string `json:"outcome"`
	Error          string `json:"error,omitempty"`
	UpdatedAt      string `json:"updatedAt"`
}

// reloader is owned by the refresh loop, so its state needs no lock.
type reloader struct {
	statusFile     string
	evaluated      string
	enforcingLabel string
	report         status
}

// load evaluates a newly named active set and activates it only if it is
// complete and valid. An incomplete set is retried on the next check. A
// rejected or unreadable set leaves the last good configuration active. A
// panic during validation is contained so the gateway keeps serving.
func (r *reloader) load() {
	defer func() {
		if failure := recover(); failure != nil {
			slog.Error("Cedar configuration refresh failed", "panic", fmt.Sprint(failure))
		}
	}()
	pointer, err := policy.ReadPointer(storeRoot)
	if err != nil {
		// Evaluate the named set again once the pointer is readable.
		r.evaluated = ""
		r.record(status{Active: "", Outcome: "unreadable", Error: err.Error()})
		return
	}
	if pointer.Set == r.evaluated {
		return
	}
	next, manifest, err := policy.LoadSet(storeRoot, pointer.Set)
	var notReady *policy.NotReadyError
	switch {
	case errors.As(err, &notReady):
		r.record(status{Active: pointer.Set, Outcome: "not_ready", Error: err.Error()})
		return
	case err != nil:
		r.evaluated = pointer.Set
		r.record(status{Active: pointer.Set, Outcome: "rejected", Error: err.Error()})
		return
	}
	r.evaluated = pointer.Set
	active.Store(next)
	r.enforcingLabel = manifest.Label
	r.record(status{Active: pointer.Set, Outcome: "activated"})
}

// record logs and publishes a change in the evaluation outcome. The enforced
// set always reflects the configuration calls are decided against.
func (r *reloader) record(next status) {
	if snapshot := active.Load(); snapshot != nil {
		next.Enforcing = snapshot.Version
		next.EnforcingLabel = r.enforcingLabel
	}
	previous := r.report
	previous.UpdatedAt = ""
	if previous == next {
		return
	}
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	r.report = next
	attrs := []any{"active", next.Active, "enforcing", next.Enforcing, "label", next.EnforcingLabel}
	switch next.Outcome {
	case "activated":
		slog.Info("Cedar configuration activated", attrs...)
	default:
		slog.Warn("Cedar configuration "+next.Outcome, append(attrs, "error", next.Error)...)
	}
	if r.statusFile == "" {
		return
	}
	data, err := json.MarshalIndent(next, "", "  ")
	if err == nil {
		err = policy.WriteFileAtomically(r.statusFile, append(data, '\n'))
	}
	if err != nil {
		slog.Error("Cedar status report not written", "path", r.statusFile, "error", err.Error())
	}
}
