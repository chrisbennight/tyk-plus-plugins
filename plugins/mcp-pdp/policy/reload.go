package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

// Status reports which policy set a gateway enforces and the outcome of its
// most recent evaluation of the active pointer.
type Status struct {
	Enforcing      string `json:"enforcing"`
	EnforcingLabel string `json:"enforcingLabel,omitempty"`
	Active         string `json:"active"`
	Outcome        string `json:"outcome"`
	Error          string `json:"error,omitempty"`
	UpdatedAt      string `json:"updatedAt"`
}

// Reloader follows a store's active pointer and replaces Active only with a
// complete, valid set. Only one goroutine may call Load, so its state needs
// no lock; Active may be read concurrently.
type Reloader struct {
	Root       string
	StatusFile string
	Active     *atomic.Pointer[Snapshot]

	evaluated string
	report    Status
	written   bool
}

// NewReloader prepares a reloader. It needs no recovery state of its own:
// the store's active pointer only moves to sets that passed the same
// validation, so after a restart the gateway enforces the same last good set.
// If the pointer names a set this gateway rejects, for example after a manual
// edit, calls are denied rather than falling back to an older set, which
// could grant access a later set revoked.
func NewReloader(root, statusFile string, active *atomic.Pointer[Snapshot]) *Reloader {
	return &Reloader{Root: root, StatusFile: statusFile, Active: active}
}

// Load evaluates a newly named active set. An incomplete set is retried on
// the next call. A rejected or unreadable set leaves the last good
// configuration active. A panic during validation is contained so the
// gateway keeps serving.
func (r *Reloader) Load() {
	defer func() {
		if failure := recover(); failure != nil {
			slog.Error("Cedar configuration refresh failed", "panic", fmt.Sprint(failure))
		}
	}()
	pointer, err := ReadPointer(r.Root)
	if err != nil {
		// Evaluate the named set again once the pointer is readable.
		r.evaluated = ""
		r.record(Status{Outcome: "unreadable", Error: err.Error()})
		return
	}
	if pointer.Set == r.evaluated {
		r.flush()
		return
	}
	next, _, err := LoadSet(r.Root, pointer.Set)
	var notReady *NotReadyError
	switch {
	case errors.As(err, &notReady):
		// Evaluate again on the next call, including if the pointer returns
		// to the set already enforced.
		r.evaluated = ""
		r.record(Status{Active: pointer.Set, Outcome: "not_ready", Error: err.Error()})
	case err != nil:
		r.evaluated = pointer.Set
		r.record(Status{Active: pointer.Set, Outcome: "rejected", Error: err.Error()})
	default:
		r.evaluated = pointer.Set
		r.Active.Store(next)
		r.record(Status{Active: pointer.Set, Outcome: "activated"})
	}
}

// record logs a change in the evaluation outcome and publishes it. The
// enforced set always reflects the configuration calls are decided against.
func (r *Reloader) record(next Status) {
	if snapshot := r.Active.Load(); snapshot != nil {
		next.Enforcing, next.EnforcingLabel = snapshot.Version, snapshot.Label
	}
	previous := r.report
	previous.UpdatedAt = ""
	if previous != next {
		next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		r.report, r.written = next, false
		attrs := []any{"active", next.Active, "enforcing", next.Enforcing, "label", next.EnforcingLabel}
		if next.Outcome == "activated" {
			slog.Info("Cedar configuration activated", attrs...)
		} else {
			slog.Warn("Cedar configuration "+next.Outcome, append(attrs, "error", next.Error)...)
		}
	}
	r.flush()
}

// flush writes the current report if the last write did not succeed.
func (r *Reloader) flush() {
	if r.StatusFile == "" || r.written {
		return
	}
	data, err := json.MarshalIndent(r.report, "", "  ")
	if err == nil {
		err = writeAtomically(r.StatusFile, append(data, '\n'), 0o644)
	}
	if err != nil {
		slog.Error("Cedar status report not written", "path", r.StatusFile, "error", err.Error())
		return
	}
	r.written = true
}
