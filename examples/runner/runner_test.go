package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// The policy's activation checks are generated from expected.json, so the
// policy cannot be published while it disagrees with the expected outcomes.
// Regenerate with: docker compose run --rm runner checks > policy/checks.json
func TestCommittedChecksMatchExpected(t *testing.T) {
	e, err := load("..")
	if err != nil {
		t.Fatal(err)
	}
	want, err := e.checks()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../policy/checks.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("policy/checks.json is out of date; regenerate it from expected.json")
	}
}

func TestChecksLeaveOutCallsThePolicyNeverSees(t *testing.T) {
	e, err := load("..")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := e.checks()
	var checks []activationCheck
	if err := json.Unmarshal(out, &checks); err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Tool == "archive" || c.Tool == "no_such_tool" {
			t.Errorf("a check for the unapproved tool %s", c.Tool)
		}
		if amount, ok := c.Arguments["amount"].(string); ok {
			t.Errorf("a check with a mistyped amount %q", amount)
		}
	}
	if len(checks) == 0 {
		t.Fatal("no checks generated")
	}
}

func TestIdentityOfTokenAndKeyCallers(t *testing.T) {
	e, err := load("..")
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := e.identity("scoped")
	if err != nil || scoped.Issuer != e.deck.Issuer || scoped.Subject != "scoped" || len(scoped.Scopes) == 0 {
		t.Fatalf("scoped = %+v, %v", scoped, err)
	}
	indexer, err := e.identity("indexer")
	if err != nil || indexer.Issuer != "examples" || indexer.Subject != "indexer" {
		t.Fatalf("indexer = %+v, %v", indexer, err)
	}
	if _, err := e.identity("nobody"); err == nil {
		t.Fatal("an unknown caller was accepted")
	}
}

func TestListAcceptsTheGatewaysClaimShapes(t *testing.T) {
	if got := list("a b"); len(got) != 2 {
		t.Errorf("space-separated: %v", got)
	}
	if got := list([]any{"a", "b"}); len(got) != 2 {
		t.Errorf("list: %v", got)
	}
	if got := list(map[string]any{"a": true}); got != nil {
		t.Errorf("object: %v", got)
	}
}
