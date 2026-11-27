package identity

import "net/http"

// Credentials counts the distinct credential headers a request carries,
// given the header names of the proxy's security schemes. A header counts
// when any of its values is non-empty, not only its first. A request may
// carry at most one: with two, it has no single caller.
func Credentials(h http.Header, names []string) int {
	seen := map[string]bool{}
	for _, name := range names {
		name = http.CanonicalHeaderKey(name)
		if name == "" || seen[name] {
			continue
		}
		for _, v := range h.Values(name) {
			if v != "" {
				seen[name] = true
				break
			}
		}
	}
	return len(seen)
}
