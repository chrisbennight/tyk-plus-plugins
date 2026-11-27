package identity

import (
	"net/http"
	"testing"
)

func TestCredentials(t *testing.T) {
	names := []string{"X-API-Key", "Authorization", "authorization"}
	for _, c := range []struct {
		headers map[string]string
		want    int
	}{
		{nil, 0},
		{map[string]string{"X-Api-Key": "k"}, 1},
		{map[string]string{"Authorization": "Bearer t"}, 1},
		{map[string]string{"X-Api-Key": "k", "Authorization": "Bearer t"}, 2},
		// Header names are case-insensitive, and an empty value is no credential.
		{map[string]string{"x-api-key": "k", "authorization": ""}, 1},
		// Headers no security scheme reads are not credentials.
		{map[string]string{"X-Other": "k", "Authorization": "Bearer t"}, 1},
	} {
		h := http.Header{}
		for k, v := range c.headers {
			h.Set(k, v)
		}
		if got := Credentials(h, names); got != c.want {
			t.Errorf("%v: got %d, want %d", c.headers, got, c.want)
		}
	}
	// An empty first value does not hide a later one.
	h := http.Header{}
	h.Add("X-API-Key", "")
	h.Add("X-API-Key", "k")
	h.Set("Authorization", "Bearer t")
	if got := Credentials(h, names); got != 2 {
		t.Errorf("repeated key header: got %d, want 2", got)
	}
}
