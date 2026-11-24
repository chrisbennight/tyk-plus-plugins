package drift

import (
	"maps"
	"sync/atomic"
	"time"
)

// Observations records, for each proxy and tool, the fingerprint of the
// definition the upstream last declared. Readers never take a lock: each
// update publishes a new copy.
//
// Tools without approval are recorded too, so a later approval of a
// definition the upstream is not declaring is caught, but only up to a
// per-proxy limit so an upstream cannot grow the record without bound.
type Observations struct {
	current  atomic.Pointer[observed]
	sequence atomic.Uint64
}

type observed struct {
	latest map[string]entry
	// unapproved counts, per proxy, the recorded tools charged to its limit.
	unapproved map[string]int
	// incomplete marks proxies with a tool left unrecorded at the limit.
	incomplete map[string]bool
}

type entry struct {
	fingerprint string
	// sequence orders declarations by when the gateway received them.
	sequence uint64
	// charged is set while the tool counts against the proxy's limit.
	charged bool
	// seenAt is when the declaration was recorded.
	seenAt time.Time
}

// maxToolName is the longest tool name the MCP specification recommends. A
// longer name without approval is not recorded, so names cannot make the
// record large.
const maxToolName = 128

// Observation is one tool an upstream declared, with the fingerprint of its
// definition ("" when it could not be fingerprinted) and whether it is
// approved.
type Observation struct {
	Tool, Fingerprint string
	Approved          bool
}

func observationKey(proxy, tool string) string { return proxy + "\x00" + tool }

// Received numbers a reply as the gateway receives it, before checking it,
// so a reply checked later cannot overwrite what a newer reply declared.
func (o *Observations) Received() uint64 { return o.sequence.Add(1) }

// Record stores what one reply, numbered by Received, declared. A newer
// declaration always updates a tool. An older one that disagrees with the
// record marks the tool unsettled: its fingerprint becomes "", which matches
// no approval, until a newer reply declares it again. Concurrent replies have
// no reliable order, so neither of two disagreeing declarations is trusted,
// whatever is approved now or later. A tool without approval is added only while the proxy has fewer than
// maxUnapproved such tools and its name is not unusually long; otherwise the
// proxy is marked incomplete. A tool stops counting once it is approved.
func (o *Observations) Record(proxy string, received uint64, declared []Observation, maxUnapproved int) {
	o.RecordAt(proxy, received, time.Now(), declared, maxUnapproved)
}

// RecordAt is Record for a reply received at a known time, which the record
// keeps as when the declarations were seen, so it orders them as the
// gateways' shared declarations do.
func (o *Observations) RecordAt(proxy string, received uint64, now time.Time, declared []Observation, maxUnapproved int) {
	if len(declared) == 0 {
		return
	}
	for {
		previous := o.current.Load()
		next := &observed{latest: map[string]entry{}, unapproved: map[string]int{}, incomplete: map[string]bool{}}
		if previous != nil {
			next.latest = maps.Clone(previous.latest)
			next.unapproved = maps.Clone(previous.unapproved)
			next.incomplete = maps.Clone(previous.incomplete)
		}
		for _, d := range declared {
			key := observationKey(proxy, d.Tool)
			old, known := next.latest[key]
			fingerprint := d.Fingerprint
			if known && old.sequence > received {
				if old.fingerprint == fingerprint {
					continue
				}
				fingerprint = ""
			}
			sequence := max(received, old.sequence)
			// A tool already recorded is always updated, since that adds
			// nothing to the record; only new tools without approval count
			// against the limit.
			charged := known && old.charged
			switch {
			case d.Approved && charged:
				next.unapproved[proxy]--
				charged = false
			case !d.Approved && known && !charged:
				// A tool that lost its approval counts again. It stays recorded
				// even past the limit, because its record already exists, but
				// it fills the limit so new tools without approval are not.
				next.unapproved[proxy]++
				charged = true
			case !d.Approved && !known:
				if next.unapproved[proxy] >= maxUnapproved || len(d.Tool) > maxToolName {
					next.incomplete[proxy] = true
					continue
				}
				next.unapproved[proxy]++
				charged = true
			}
			seenAt := now
			if known && old.sequence > received {
				seenAt = old.seenAt
			}
			next.latest[key] = entry{fingerprint: fingerprint, sequence: sequence, charged: charged, seenAt: seenAt}
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
	seen, ok := current.latest[observationKey(proxy, tool)]
	return seen.fingerprint, ok
}

// LatestAt returns the fingerprint the upstream last declared for a tool and
// when this gateway recorded it.
func (o *Observations) LatestAt(proxy, tool string) (string, time.Time, bool) {
	current := o.current.Load()
	if current == nil {
		return "", time.Time{}, false
	}
	seen, ok := current.latest[observationKey(proxy, tool)]
	return seen.fingerprint, seen.seenAt, ok
}

// Complete reports whether every tool the proxy's upstream declared to this
// gateway was recorded.
func (o *Observations) Complete(proxy string) bool {
	current := o.current.Load()
	return current == nil || !current.incomplete[proxy]
}
