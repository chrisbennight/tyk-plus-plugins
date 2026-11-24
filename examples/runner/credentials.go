package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// credential is the set of request headers that identify a caller.
type credential map[string]string

func (c credential) with(other credential) credential {
	out := credential{}
	for k, v := range c {
		out[k] = v
	}
	for k, v := range other {
		out[k] = v
	}
	return out
}

type credentials struct {
	e     *examples
	known map[string]credential
}

func newCredentials(e *examples) (*credentials, error) {
	return &credentials{e: e, known: map[string]credential{}}, nil
}

// proxies lists the example gateway's proxies, one per mock server.
func (e *examples) proxies() []string {
	var out []string
	for proxy := range e.tools {
		out = append(out, proxy)
	}
	return out
}

// of returns the credential for a named caller: a fresh token from the issuer
// for a person, or a key for a service.
func (c *credentials) of(name string) (credential, error) {
	if cred, ok := c.known[name]; ok {
		return cred, nil
	}
	var cred credential
	if id, ok := c.e.keys[name]; ok {
		key := os.Getenv("EXAMPLE_" + envName(name) + "_KEY")
		if key == "" {
			var err error
			if key, err = createKey(c.e.proxies(), map[string]any{"cedar": id}); err != nil {
				return nil, fmt.Errorf("creating a key for %s: %w", name, err)
			}
		}
		cred = credential{"X-API-Key": key}
	} else {
		token, err := get(setting("ISSUER_URL", "http://issuer:8000") + "/token/" + name)
		if err != nil {
			return nil, fmt.Errorf("token for %s: %w", name, err)
		}
		cred = credential{"Authorization": "Bearer " + token}
	}
	c.known[name] = cred
	return cred, nil
}

// signed asks the issuer to sign exactly these claims, for tokens the gateway must refuse.
func signed(claims map[string]any, unpublished bool) (credential, error) {
	body, _ := json.Marshal(claims)
	url := setting("ISSUER_URL", "http://issuer:8000") + "/token"
	if unpublished {
		url += "?key=unpublished"
	}
	res, err := httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	token, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer answered %s: %s", res.Status, token)
	}
	return credential{"Authorization": "Bearer " + string(token)}, nil
}

// createKey creates a Tyk key with access to the given proxies.
func createKey(proxies []string, metadata map[string]any) (string, error) {
	secret := os.Getenv("TYK_GW_SECRET")
	if secret == "" {
		return "", fmt.Errorf("TYK_GW_SECRET is not set, so keys cannot be created")
	}
	rights := map[string]any{}
	for _, proxy := range proxies {
		rights[proxy] = map[string]any{"api_id": proxy, "versions": []string{"Default"}}
	}
	body, _ := json.Marshal(map[string]any{"access_rights": rights, "quota_max": -1, "rate": 1000, "per": 1, "meta_data": metadata})
	req, _ := http.NewRequest(http.MethodPost, setting("CONTROL_URL", "http://gateway:9696")+"/tyk/keys/create", bytes.NewReader(body))
	req.Header.Set("X-Tyk-Authorization", secret)
	req.Header.Set("Content-Type", "application/json")
	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var created struct{ Key string }
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&created) != nil || created.Key == "" {
		return "", fmt.Errorf("control API answered %s", res.Status)
	}
	return created.Key, nil
}

func get(url string) (string, error) {
	res, err := httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s answered %s: %s", url, res.Status, body)
	}
	return string(body), nil
}
