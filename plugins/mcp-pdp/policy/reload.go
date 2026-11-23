package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
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
	recovered string
}

// NewReloader prepares a reloader. A status report left by an earlier run
// names the set that run enforced, which a restart can fall back to.
func NewReloader(root, statusFile string, active *atomic.Pointer[Snapshot]) *Reloader {
	r := &Reloader{Root: root, StatusFile: statusFile, Active: active}
	if statusFile != "" {
		if data, err := os.ReadFile(statusFile); err == nil {
			var previous Status
			if json.Unmarshal(data, &previous) == nil && fingerprintPattern.MatchString(previous.Enforcing) {
				r.recovered = previous.Enforcing
			}
		}
	}
	return r
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
		r.fallBack(pointer)
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
		r.fallBack(pointer)
		r.record(Status{Active: pointer.Set, Outcome: "not_ready", Error: err.Error()})
	case err != nil:
		r.evaluated = pointer.Set
		r.fallBack(pointer)
		r.record(Status{Active: pointer.Set, Outcome: "rejected", Error: err.Error()})
	default:
		r.evaluated = pointer.Set
		r.Active.Store(next)
		r.record(Status{Active: pointer.Set, Outcome: "activated"})
	}
}

// fallBack restores a last good set after a restart, when the active pointer
// names a set this process cannot enforce. It prefers the set this gateway
// last reported enforcing, then the set the pointer recorded as previous.
func (r *Reloader) fallBack(pointer Pointer) {
	if r.Active.Load() != nil {
		return
	}
	for _, set := range []string{r.recovered, pointer.Previous} {
		if set == "" || set == pointer.Set {
			continue
		}
		if snapshot, _, err := LoadSet(r.Root, set); err == nil {
			r.Active.Store(snapshot)
			slog.Warn("Cedar configuration restored the last good set", "set", set)
			return
		}
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
		err = writeAtomically(r.StatusFile, append(data, '\n'))
	}
	if err != nil {
		slog.Error("Cedar status report not written", "path", r.StatusFile, "error", err.Error())
		return
	}
	r.written = true
}
