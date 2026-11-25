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

// An unapproved tool is never listed, so expecting a caller to see one
// contradicts the approved tools.
func TestListedUnapprovedToolIsAnError(t *testing.T) {
	e, err := load("..")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.expected.Listed) == 0 {
		t.Fatal("expected.json lists no tools")
	}
	e.expected.Listed["admin"]["notes"] = append(e.expected.Listed["admin"]["notes"], "archive")
	if err := e.checkListed(); err == nil {
		t.Fatal("a listed unapproved tool was accepted")
	}
	e.expected.Listed["admin"]["nowhere"] = nil
	if err := e.checkListed(); err == nil {
		t.Fatal("a listed unknown proxy was accepted")
	}
}

// The drift walk may expect only approved tools to be listed or to work, and
// must give arguments for every tool it calls.
func TestDriftWalkIsChecked(t *testing.T) {
	e, err := load("..")
	if err != nil {
		t.Fatal(err)
	}
	if e.expected.Drift == nil || len(e.expected.Drift.Steps) == 0 {
		t.Fatal("expected.json has no drift walk")
	}
	step := &e.expected.Drift.Steps[0]
	step.Permitted = append(step.Permitted, "delete")
	if err := e.checkDrift(); err == nil {
		t.Fatal("an unapproved tool expected to work was accepted")
	}
	e, _ = load("..")
	delete(e.expected.Drift.Arguments, e.expected.Drift.Steps[0].Refused[0])
	if err := e.checkDrift(); err == nil {
		t.Fatal("a refused call without arguments was accepted")
	}
}

// Deleting a row of listed must not silently drop its checks.
func TestListedMustCoverEveryCallerAndProxy(t *testing.T) {
	e, err := load("..")
	if err != nil {
		t.Fatal(err)
	}
	delete(e.expected.Listed["analyst"], "notes")
	if err := e.checkListed(); err == nil {
		t.Fatal("a caller missing a proxy was accepted")
	}
	e, _ = load("..")
	delete(e.expected.Listed, "analyst")
	if err := e.checkListed(); err == nil {
		t.Fatal("a caller that makes calls but has no tool list was accepted")
	}
}

func TestRefusalOfReadsBothErrorShapes(t *testing.T) {
	transport := errors.New(`Error POSTing to endpoint: {"error":{"code":-32002,"message":"Tool call denied"},"id":4,"jsonrpc":"2.0"}`)
	if r, ok := refusalOf(transport); !ok || *r != (rpcError{-32002, "Tool call denied", ""}) {
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

func TestCallerNamesMustBeSafeShellNames(t *testing.T) {
	for _, bad := range []string{"a;b", "$(id)", "A", "-x", "a b"} {
		if callerName.MatchString(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRefusalsDifferingOnlyInDataDiffer(t *testing.T) {
	a, _ := refusalOf(errors.New(`x: {"jsonrpc":"2.0","error":{"code":-32002,"message":"Tool call denied","data":{"reason":"unknown"}}}`))
	b, _ := refusalOf(errors.New(`x: {"jsonrpc":"2.0","error":{"code":-32002,"message":"Tool call denied"}}`))
	if a == nil || b == nil || *a == *b {
		t.Fatalf("%v and %v compare equal", a, b)
	}
}

func TestSameJSONComparesNumbersByValue(t *testing.T) {
	if !sameJSON(map[string]any{"amount": json.Number("5"), "environment": "test"}, map[string]any{"environment": "test", "amount": float64(5)}) {
		t.Fatal("equal arguments compared unequal")
	}
	if sameJSON(map[string]any{"environment": "test"}, map[string]any{"environment": "production"}) {
		t.Fatal("different arguments compared equal")
	}
}

func TestBareHTTPErrorBodyIsNotARefusal(t *testing.T) {
	for _, text := range []string{`x: {"error":{}}`, `x: {"error":{"code":-32002,"message":"denied"}}`, `x: {"jsonrpc":"2.0","error":{"code":0,"message":"denied"}}`} {
		if _, ok := refusalOf(errors.New(text)); ok {
			t.Errorf("accepted %s", text)
		}
	}
}
