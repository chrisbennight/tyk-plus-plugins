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
	// incomplete marks proxies with a tool left unrecorded at the limit.
	incomplete map[string]bool
}

// maxToolName is the longest tool name the MCP specification recommends. A
// longer name without approval is not recorded, so names cannot make the
// record large.
const maxToolName = 128

// Observation is one tool an upstream declared.
type Observation struct {
	Tool, Fingerprint string
	Approved          bool
}

func observationKey(proxy, tool string) string { return proxy + "\x00" + tool }

// Record stores what one reply declared. A tool without approval that is
// not yet recorded is added only while the proxy has fewer than
// maxUnapproved such tools and its name is not unusually long; otherwise the
// proxy is marked incomplete.
func (o *Observations) Record(proxy string, declared []Observation, maxUnapproved int) {
	if len(declared) == 0 {
		return
	}
	for {
		previous := o.current.Load()
		next := &observed{latest: map[string]string{}, unapproved: map[string]int{}, incomplete: map[string]bool{}}
		if previous != nil {
			next.latest = maps.Clone(previous.latest)
			next.unapproved = maps.Clone(previous.unapproved)
			next.incomplete = maps.Clone(previous.incomplete)
		}
		for _, d := range declared {
			key := observationKey(proxy, d.Tool)
			if _, known := next.latest[key]; !known && !d.Approved {
				if next.unapproved[proxy] >= maxUnapproved || len(d.Tool) > maxToolName {
					next.incomplete[proxy] = true
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

// Complete reports whether every tool the proxy's upstream declared to this
// gateway was recorded.
func (o *Observations) Complete(proxy string) bool {
	current := o.current.Load()
	return current == nil || !current.incomplete[proxy]
}
