package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// notifyWait is how long a client may wait for a tool-list-changed
// notification after the server changes.
const notifyWait = 15 * time.Second

// drift walks the changing server through each step of expected.json's drift
// walk. At every step it confirms that a client already connected is told the
// tool list changed, and that a client connecting afresh is shown, given and
// refused what the step states. The run starts the server at version 0, and
// the walk leaves it there.
func (r *runner) drift() {
	d := r.e.expected.Drift
	if d == nil {
		return
	}
	cred, err := r.creds.of(d.Caller)
	if err != nil {
		fail(err)
	}
	defer func() {
		if err := setVersion(d.Server, 0); err != nil {
			r.fail("leave "+d.Server+" at version 0", err.Error())
		}
	}()

	// One client of each protocol version stays connected throughout, to
	// receive the notifications.
	notified := map[string]chan struct{}{}
	for _, version := range versions {
		ch := make(chan struct{}, 16)
		opts := &mcp.ClientOptions{ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
			select {
			case ch <- struct{}{}:
			default:
			}
		}}
		s, err := connect(cred, version, d.Server, opts)
		if err != nil {
			r.fail(fmt.Sprintf("connect a %s client to listen to %s", version, d.Server), err.Error())
			return
		}
		defer s.Close()
		// The older protocol's session is known to the server once it has
		// been used.
		if _, err := toolNames(s); err != nil {
			r.fail(fmt.Sprintf("list %s's tools with a %s client", d.Server, version), err.Error())
			return
		}
		notified[version] = ch
	}

	for _, step := range d.Steps {
		for _, ch := range notified {
			drain(ch)
		}
		if err := setVersion(d.Server, step.Version); err != nil {
			r.fail(fmt.Sprintf("switch %s to version %d", d.Server, step.Version), err.Error())
			continue
		}
		for _, version := range versions {
			what := fmt.Sprintf("%s version %d: a connected %s client is told the tool list changed", d.Server, step.Version, version)
			select {
			case <-notified[version]:
				r.pass(what)
			case <-time.After(notifyWait):
				r.fail(what, "no notification arrived")
			}
		}
		for _, version := range versions {
			r.driftStep(d, step, cred, version)
		}
	}
}

// driftStep connects afresh, as a client would to a server that had already
// changed, and checks what the step states.
func (r *runner) driftStep(d *driftWalk, step driftStep, cred credential, version string) {
	prefix := fmt.Sprintf("%s version %d (%s) with a %s client", d.Server, step.Version, step.Why, version)
	s, err := connect(cred, version, d.Server, nil)
	if err != nil {
		r.fail(prefix, "could not connect: "+err.Error())
		return
	}
	defer s.Close()
	if got := s.InitializeResult().Instructions; got != d.Instructions {
		r.fail(prefix+": given the approved instructions", fmt.Sprintf("given %q", got))
	} else {
		r.pass(prefix + ": given the approved instructions")
	}
	want := slices.Sorted(slices.Values(step.Listed))
	what := fmt.Sprintf("%s: lists %v", prefix, want)
	switch got, err := toolNames(s); {
	case err != nil:
		r.fail(what, "listing failed: "+err.Error())
	case !slices.Equal(got, want):
		r.fail(what, fmt.Sprintf("listed %v", got))
	default:
		r.pass(what)
	}
	for _, tool := range step.Permitted {
		r.checkCall(fmt.Sprintf("%s: %s works", prefix, tool), s, version, d.Server, tool, d.Arguments[tool], "permitted")
	}
	for _, tool := range step.Refused {
		r.checkCall(fmt.Sprintf("%s: %s is refused", prefix, tool), s, version, d.Server, tool, d.Arguments[tool], "refused")
	}
}

func drain(ch chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// setVersion switches a changing server to a version through its control
// path, outside MCP and so outside the gateway.
func setVersion(server string, version int) error {
	body, _ := json.Marshal(map[string]int{"version": version})
	res, err := httpClient.Post(fmt.Sprintf(setting("SERVER_URL", "http://%s:8000"), server)+"/version", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		text, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
		return fmt.Errorf("the server answered %s: %s", res.Status, text)
	}
	return nil
}
