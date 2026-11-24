package drift

import (
	"maps"
	"sync/atomic"
)

// Observations records, for each proxy and tool, the fingerprint of the
// definition the upstream last declared. Readers never take a lock: each
// update publishes a new copy.
//
// Tools without approval are recorded too, so a later approval of a
// definition the upstream is not declaring is caught, but only up to a
// per-proxy limit so an upstream cannot grow the record without bound.
type Observations struct {
	current atomic.Pointer[observed]
}

type observed struct {
	latest map[string]string
	// unapproved counts, per proxy, the tools recorded without approval.
	unapproved map[string]int
}

// Observation is one tool an upstream declared.
type Observation struct {
	Tool, Fingerprint string
	Approved          bool
}

func observationKey(proxy, tool string) string { return proxy + "\x00" + tool }

// Record stores what one reply declared. A tool without approval that is
// not yet recorded is added only while the proxy has fewer than
// maxUnapproved such tools.
func (o *Observations) Record(proxy string, declared []Observation, maxUnapproved int) {
	if len(declared) == 0 {
		return
	}
	for {
		previous := o.current.Load()
		next := &observed{latest: map[string]string{}, unapproved: map[string]int{}}
		if previous != nil {
			next.latest = maps.Clone(previous.latest)
			next.unapproved = maps.Clone(previous.unapproved)
		}
		for _, d := range declared {
			key := observationKey(proxy, d.Tool)
			if _, known := next.latest[key]; !known && !d.Approved {
				if next.unapproved[proxy] >= maxUnapproved {
					continue
				}
				next.unapproved[proxy]++
			}
			next.latest[key] = d.Fingerprint
		}
		if o.current.CompareAndSwap(previous, next) {
			return
		}
	}
}

// Latest returns the fingerprint the upstream last declared for a tool.
func (o *Observations) Latest(proxy, tool string) (string, bool) {
	current := o.current.Load()
	if current == nil {
		return "", false
	}
	fingerprint, ok := current.latest[observationKey(proxy, tool)]
	return fingerprint, ok
}
