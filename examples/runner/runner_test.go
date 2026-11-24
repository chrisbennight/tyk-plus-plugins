package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// The policy's activation checks are generated from expected.json, so the
// policy cannot be published while it disagrees with the expected outcomes.
// Regenerate as examples/README.md describes.
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

// A row expecting a call to be permitted that the policy never evaluates
// contradicts the approved tools, so generating checks must fail.
func TestPermittedRowForUnapprovedToolIsAnError(t *testing.T) {
	e, err := load("..")
	if err != nil {
		t.Fatal(err)
	}
	e.expected.Calls = append(e.expected.Calls, call{Caller: "admin", Server: "notes", Tool: "archive", Arguments: map[string]any{"id": "1"}, Expect: "permitted"})
	if _, err := e.checks(); err == nil {
		t.Fatal("a permitted call to an unapproved tool was accepted")
	}
}

func TestRefusalOfReadsBothErrorShapes(t *testing.T) {
	transport := errors.New(`Error POSTing to endpoint: {"error":{"code":-32002,"message":"Tool call denied"},"id":4,"jsonrpc":"2.0"}`)
	if r, ok := refusalOf(transport); !ok || *r != (rpcError{-32002, "Tool call denied"}) {
		t.Fatalf("transport error: %v %v", r, ok)
	}
	if _, ok := refusalOf(errors.New("context deadline exceeded")); ok {
		t.Fatal("a timeout counted as a refusal")
	}
	if _, ok := refusalOf(fmt.Errorf("wrapped: %w", &jsonrpc.Error{Code: -32002, Message: "Tool call denied"})); !ok {
		t.Fatal("a JSON-RPC error was not read")
	}
}

func TestCredentialTextRejectsShellSyntax(t *testing.T) {
	for _, bad := range []string{"a'b", "a;b", "$(x)", "a b", "", "a\nb"} {
		if credentialText.MatchString(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	if !credentialText.MatchString("eyJhbGciOi.eyJzdWIi.c2ln-_") {
		t.Error("rejected a JWT")
	}
}
