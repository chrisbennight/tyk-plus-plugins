package drift

import "sync/atomic"

// Observations records, for each proxy and tool, the fingerprint of the
// definition the upstream last declared. Readers never take a lock: each
// update publishes a new copy of the map.
type Observations struct {
	latest atomic.Pointer[map[string]string]
}

func observationKey(proxy, tool string) string { return proxy + "\x00" + tool }

// Record stores the fingerprints one reply declared.
func (o *Observations) Record(proxy string, fingerprints map[string]string) {
	if len(fingerprints) == 0 {
		return
	}
	for {
		current := o.latest.Load()
		next := make(map[string]string, len(fingerprints))
		if current != nil {
			for key, value := range *current {
				next[key] = value
			}
		}
		for tool, fingerprint := range fingerprints {
			next[observationKey(proxy, tool)] = fingerprint
		}
		if o.latest.CompareAndSwap(current, &next) {
			return
		}
	}
}

// Latest returns the fingerprint the upstream last declared for a tool.
func (o *Observations) Latest(proxy, tool string) (string, bool) {
	current := o.latest.Load()
	if current == nil {
		return "", false
	}
	fingerprint, ok := (*current)[observationKey(proxy, tool)]
	return fingerprint, ok
}
