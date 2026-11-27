package identity

import "net/http"

// Credentials counts the distinct credential headers a request carries,
// given the header names of the proxy's security schemes. A request may
// carry at most one: with two, it has no single caller.
func Credentials(h http.Header, names []string) int {
	seen := map[string]bool{}
	for _, name := range names {
		name = http.CanonicalHeaderKey(name)
		if name != "" && !seen[name] && h.Get(name) != "" {
			seen[name] = true
		}
	}
	return len(seen)
}
