package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Example rules for one convention: callers with the support role may call tools
// the operator marked read-only, and only operators may call anything else.
// The gateway ships none of these; the test installs them.
const exampleRules = `
@id("support-read")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("support") && resource.reviewed.flags.contains({name: "readOnly", value: true}) };

@id("operator-call")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("operator") };

@id("operator-required-for-changes")
forbid (principal, action == Action::"tools/call", resource)
when { !resource.reviewed.flags.contains({name: "readOnly", value: true}) && !principal.roles.contains("operator") };
`

const exampleChecks = `[
 {"caller": {"issuer": "local", "subject": "support", "roles": ["support"]},
  "proxy": "governed", "upstream": "http://upstream.invalid/mcp", "tool": "lookup",
  "hypotheticalTool": {"facts": {"readOnly": true}}, "expect": "permitted"},
 {"caller": {"issuer": "local", "subject": "support", "roles": ["support"]},
  "proxy": "governed", "upstream": "http://upstream.invalid/mcp", "tool": "update",
  "hypotheticalTool": {}, "expect": "policy_denied"}]`

type keys struct{ support, operator, guest credential }

// catalogOf lists the upstream's tools through the gateway, keyed by name,
// leaving out the Code Mode tools the gateway adds on Code Mode proxies.
func catalogOf(c *conn, cred credential) map[string]map[string]any {
	r := c.rpc(cred, "tools/list", map[string]any{})
	var listing struct {
		Tools []map[string]any `json:"tools"`
	}
	check(r.Status == http.StatusOK && json.Unmarshal(r.Result, &listing) == nil, "tools/list: %v", r)
	catalog := map[string]map[string]any{}
	for _, tool := range listing.Tools {
		if name := tool["name"].(string); !codeModeTools[name] {
			catalog[name] = tool
		}
	}
	return catalog
}

func args(pairs ...any) map[string]any {
	out := map[string]any{}
	for i := 0; i < len(pairs); i += 2 {
		out[pairs[i].(string)] = pairs[i+1]
	}
	return out
}

// policySuite checks Cedar enforcement in detail with the older protocol.
func policySuite(k keys) {
	c := connect(k.operator, olderProtocol)
	catalog := catalogOf(c, k.operator)
	annotations := catalog["change"]["annotations"].(map[string]any)
	check(annotations["readOnlyHint"] == true, "change should claim to be read-only: %v", annotations)

	// The gateway ships a store whose active set has no rules, tools, or checks,
	// and it reports enforcing that set.
	pointer := readJSON(filepath.Join(policyDir, "active"))
	shipped := pointer["set"].(string)
	entries, _ := os.ReadDir(policyDir)
	var names []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	check(slices.Equal(names, []string{"active", "sets"}), "store contents %v", names)
	setEntries, _ := os.ReadDir(filepath.Join(policyDir, "sets", shipped))
	var setFiles []string
	for _, e := range setEntries {
		setFiles = append(setFiles, e.Name())
	}
	check(slices.Equal(setFiles, []string{"approved_instructions.json", "approved_tools.json", "checks.json", "manifest.json", "rules.cedar"}), "shipped set contents %v", setFiles)
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(policyDir, "sets", shipped, name))
		must(err)
		staged[name] = string(data)
	}
	check(strings.TrimSpace(staged["rules.cedar"]) == "", "the gateway must ship without rules")
	var shippedTools, shippedInstructions map[string]any
	var shippedChecks []any
	check(json.Unmarshal([]byte(staged["approved_tools.json"]), &shippedTools) == nil && shippedTools != nil && len(shippedTools) == 0 &&
		json.Unmarshal([]byte(staged["approved_instructions.json"]), &shippedInstructions) == nil && shippedInstructions != nil && len(shippedInstructions) == 0 &&
		json.Unmarshal([]byte(staged["checks.json"]), &shippedChecks) == nil && shippedChecks != nil && len(shippedChecks) == 0,
		"the gateway must ship no approved tools, instructions or checks: %v", staged)
	// The shipped pointer is checked as shipped, without rewriting it.
	awaitReport(shipped, "activated")
	call(c, k.operator, "lookup", args())

	// A denial alone cannot show that an empty file was accepted, because an
	// unavailable evaluator also denies. Each empty file is swapped in while a
	// permitting configuration is active instead: a rejected file would leave that
	// configuration in force. The first permit relies on the shipped empty checks.
	inventory := map[string]any{"lookup": map[string]any{"facts": args("readOnly", true), "definition": catalog["lookup"],
		"arguments": args("count", "long")}}
	publishInventory(inventory, upstream, "activated")
	publish("activated", map[string]string{"rules.cedar": exampleRules})
	call(c, k.support, "lookup", args(), "found")
	publish("activated", map[string]string{"rules.cedar": ""})
	call(c, k.operator, "lookup", args())
	publish("activated", map[string]string{"rules.cedar": exampleRules})
	call(c, k.operator, "lookup", args(), "found")
	publish("activated", map[string]string{"approved_tools.json": "{}"})
	call(c, k.operator, "lookup", args())
	publishInventory(inventory, upstream, "activated")
	call(c, k.operator, "lookup", args(), "found")
	// A null tool entry is rejected rather than treated as a reviewed tool.
	publishInventory(with(inventory, "change", nil), upstream, "rejected")
	call(c, k.operator, "change", args("count", 2))

	// A rejected candidate keeps the last good configuration.
	publishInventory(inventory, upstream, "activated")
	publish("activated", map[string]string{"checks.json": exampleChecks})
	publish("rejected", map[string]string{"rules.cedar": "invalid"})
	call(c, k.operator, "lookup", args(), "found")
	publish("activated", map[string]string{"rules.cedar": exampleRules})
	call(c, k.support, "lookup", args(), "found")
	// Null checks are not an empty list: alongside empty rules they are rejected.
	publish("rejected", map[string]string{"checks.json": "null", "rules.cedar": ""})
	call(c, k.operator, "lookup", args(), "found")
	publish("activated", map[string]string{"checks.json": exampleChecks, "rules.cedar": exampleRules})
	call(c, k.support, "lookup", args(), "found")

	// The guest permit applies across tools for count=3. An upstream hint alone cannot
	// grant the same guest access, and an operator still cannot call an unreviewed tool.
	updated := exampleRules + `
permit (principal, action, resource) when {
  context.numbers.contains({name: "count", value: 3}) ||
  (resource.upstreamAnnotations has readOnlyHint && resource.upstreamAnnotations.readOnlyHint)
};
forbid (principal, action, resource) when {
  resource.upstreamAnnotations.flags.contains({name: "vendor.batchSafe", value: false}) &&
  context.numbers.contains({name: "count", value: 2})
};
`
	publish("activated", map[string]string{"rules.cedar": updated})
	call(c, k.guest, "lookup", args("count", 3), "found")
	call(c, k.guest, "lookup", args())
	call(c, k.operator, "change", args("count", 3))

	// Onboard the real tool without facts. Under the example rules a tool not marked
	// read-only is reserved for operators whatever the upstream declares, and the
	// upstream declaration can further restrict the operator's call.
	change := map[string]any{"arguments": args("count", "long")}
	inventory["change"] = change
	publishInventory(inventory, upstream, "activated")
	call(c, k.operator, "change", args("count", 2), "updated")
	denied := call(c, k.support, "change", args("count", 3))
	// Include a custom upstream annotation in the copied definition.
	annotations["vendor.batchSafe"] = false
	change["definition"] = catalog["change"]
	publishInventory(inventory, upstream, "activated")
	call(c, k.guest, "change", args("count", 3))
	call(c, k.operator, "change", args("count", 2))
	call(c, k.operator, "change", args("count", 3), "updated")
	hidden := call(c, k.support, "change", args("count", "wrong"))
	unknown := call(c, k.support, "unknown", args("count", "wrong"))
	check(sameRefusal(hidden, denied) && sameRefusal(unknown, denied), "hidden %+v, unknown %+v, denied %+v", hidden, unknown, denied)

	// Retargeting requires a fresh review. A rejected inventory or policy edit keeps
	// the working decisions. A forbid that errors during execution blocks dispatch.
	publishInventory(inventory, "http://replacement.invalid/mcp", "activated")
	call(c, k.operator, "lookup", args())
	publishInventory(inventory, upstream, "activated")
	call(c, k.operator, "lookup", args(), "found")
	publishInventory(with(inventory, "change", args("argumants", args("count", "long"))), upstream, "rejected")
	call(c, k.operator, "change", args("count", 2))
	publishInventory(inventory, upstream, "activated")
	publish("rejected", map[string]string{"rules.cedar": "forbid(principal, action, resource);"})
	call(c, k.guest, "lookup", args("count", 3), "found")
	publish("rejected", map[string]string{"rules.cedar": exampleRules + `permit(principal, action, resource) when {principal.missing == "yes"};`})
	call(c, k.operator, "change", args("count", 2))
	// The operator can delegate a reviewed mutation to the same guest denied above.
	delegated := `
permit (principal, action, resource) when {
  (principal.roles.contains("support") && resource.reviewed.flags.contains({name: "readOnly", value: true})) ||
  (principal.roles.contains("guest") && resource.name == "change" &&
   context.numbers.contains({name: "count", value: 3}))
};
`
	publish("activated", map[string]string{"rules.cedar": delegated})
	call(c, k.guest, "change", args("count", 3), "updated")
	publish("activated", map[string]string{"rules.cedar": delegated + `
forbid (principal, action, resource)
when { resource.name == "change" && (9223372036854775807 + 1 > 0) };
`})
	call(c, k.guest, "change", args("count", 3))

	// Rules can match each kind of operator-defined fact. An invalid fact value
	// rejects the whole inventory and keeps the last good configuration.
	lookup := inventory["lookup"].(map[string]any)
	facts := lookup["facts"].(map[string]any)
	facts["risk"], facts["tier"] = "low", 1
	lookup["tags"] = []string{"directory"}
	publishInventory(inventory, upstream, "activated")
	publish("activated", map[string]string{"rules.cedar": delegated + `
permit (principal, action, resource) when {
  principal.roles.contains("guest") &&
  resource.reviewed.strings.contains({name: "risk", value: "low"}) &&
  resource.reviewed.numbers.contains({name: "tier", value: 1}) &&
  resource.reviewed.tags.contains("directory")
};
`})
	call(c, k.guest, "lookup", args(), "found")
	call(c, k.guest, "change", args())
	publishInventory(map[string]any{"lookup": map[string]any{"facts": args("readOnly", true)}, "change": map[string]any{"facts": args("weight", 1.5)}}, upstream, "rejected")
	call(c, k.guest, "lookup", args(), "found")
	// A set whose files do not match its manifest is still being published: the
	// gateway reports it as not ready and keeps enforcing the current set.
	mismatched := copyStaged()
	mismatched["rules.cedar"] = "permit (principal, action, resource);"
	manifest := map[string]string{}
	for _, name := range files {
		manifest[name] = digest(staged[name])
	}
	pointTo(writeSet(mismatched, manifest), "not_ready")
	call(c, k.guest, "lookup", args(), "found")
	call(c, k.guest, "change", args())
	// A format-1 set from an earlier build, with tools.json and no approved
	// instructions, is still enforced with the same decisions.
	// The legacy set copies the set the gateway is enforcing, not the staged
	// files, which still hold a candidate rejected above.
	enforcing := readReport()["enforcing"].(string)
	good := map[string]string{}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(policyDir, "sets", enforcing, name))
		must(err)
		good[name] = string(data)
	}
	legacy := map[string]string{"rules.cedar": good["rules.cedar"], "tools.json": good["approved_tools.json"], "checks.json": good["checks.json"]}
	pointTo(writeSetFormat(1, legacyFiles, legacy, nil), "activated")
	call(c, k.guest, "lookup", args(), "found")
	call(c, k.guest, "change", args())
	pointTo(enforcing, "activated")

	// Callers can present a token instead of a key. Its issuer and subject identify
	// the caller, and the claim the gateway is configured to read carries roles.
	tok := func(claims map[string]any) credential { return bearerCred(token("published", claims)) }
	call(c, tok(args("app_roles", []string{"support"})), "lookup", args(), "found")
	call(c, tok(args("app_roles", "support")), "lookup", args(), "found")
	call(c, tok(args("app_roles", []string{"support"})), "change", args())
	// Only the configured claim grants roles, and a malformed one is refused.
	call(c, tok(args("roles", []string{"support"})), "lookup", args())
	call(c, tok(args("app_roles", []int{7})), "lookup", args())
	// Dropping a malformed claim would leave a valid role that permits this call.
	call(c, tok(args("app_roles", []string{"support"}, "groups", []int{7})), "lookup", args())
	// The gateway refuses tokens it cannot trust before the plug-in sees them.
	refused(c, bearerCred(token("unpublished", args("app_roles", []string{"support"}))))
	refused(c, tok(args("app_roles", []string{"support"}, "iss", "https://other.test")))
	refused(c, tok(args("app_roles", []string{"support"}, "aud", "other")))
	refused(c, tok(args("app_roles", []string{"support"}, "exp", time.Now().Add(-5*time.Minute).Unix())))
	refused(c, bearerCred("not-a-token"))
	// A token without an expiry would never lapse, so it is refused for every
	// method, not only tool calls.
	noExpiry := tok(args("app_roles", []string{"support"}, "exp", nil))
	refused(c, noExpiry)
	r := c.rpc(noExpiry, "tools/list", map[string]any{})
	check(r.Status == http.StatusForbidden && r.Error != nil && len(r.ID) > 0, "tools/list with no expiry: %v", r)
	// With a valid key and a valid token, the key is tried first and identifies the
	// caller. Neither credential reaches the upstream, which rejects any it sees.
	// The token's guest role would permit this change, so a denial shows that the
	// token adds nothing to the key's identity.
	call(c, tok(args("app_roles", []string{"guest"})), "change", args("count", 3), "updated")
	both := k.support.with(tok(args("app_roles", []string{"guest"})))
	call(c, both, "lookup", args(), "found")
	call(c, both, "change", args("count", 3))
	refused(c, keyCred("not-a-key"))
	fmt.Println("Verified Cedar access and upstream dispatch with the older protocol.")
}

// leaveRejectedSet points `active` at a set that fails validation. The running
// gateway keeps its last good set; the workflow then restarts it to check
// fail-closed startup.
func leaveRejectedSet(k keys) {
	// The last good set lets a guest look things up, so the restarted phase can
	// tell a missing evaluator from an ordinary policy denial.
	publish("activated", map[string]string{"rules.cedar": exampleRules + `
permit (principal, action, resource) when { principal.roles.contains("guest") && resource.reviewed.flags.contains({name: "readOnly", value: true}) };
`})
	rejected := copyStaged()
	rejected["rules.cedar"] = "permit (principal, action, resource) when { invalid };"
	pointTo(writeSet(rejected, nil), "rejected")
	call(connect(k.operator, olderProtocol), k.guest, "lookup", args(), "found")
}

// restarted runs after the workflow restarts the gateway. The restarted
// gateway has never loaded a valid set, so it must refuse every tool call
// before dispatch.
func restarted() {
	rejected := readJSON(filepath.Join(policyDir, "active"))["set"]
	deadline := time.Now().Add(30 * time.Second)
	for {
		// The report from before the restart still names the last good set.
		report := readReport()
		if enforcing, present := report["enforcing"]; report["active"] == rejected && report["outcome"] == "rejected" && present && enforcing == "" {
			break
		}
		check(time.Now().Before(deadline), "restarted gateway did not report the rejection: %v", report)
		time.Sleep(200 * time.Millisecond)
	}
	// The last good set permits this guest call, so its refusal comes from the
	// missing evaluator, not from a policy decision or a credential check.
	guest := keyCred(key("guest"))
	r := call(connect(guest, olderProtocol), guest, "lookup", args())
	check(r.Error != nil && r.Error.Message == "Tool call denied", "refusal %+v", r)
	// Without a valid set the gateway withholds every list with its own error.
	// That error must answer the list request: rpc checks the reply echoes
	// the request's ID, which the response hook learns from the request hook.
	c := connect(guest, olderProtocol)
	listed := c.rpc(guest, "tools/list", map[string]any{})
	check(listed.Error != nil && listed.Error.Message == "Upstream reply could not be checked", "list with no valid set: %v", listed)
	fmt.Println("Verified that a gateway with no valid set refuses tool calls before dispatch.")
}

func with(m map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for key, value := range m {
		out[key] = value
	}
	out[k] = v
	return out
}

func copyStaged() map[string]string {
	out := map[string]string{}
	for k, v := range staged {
		out[k] = v
	}
	return out
}

func readJSON(path string) map[string]any {
	data, err := os.ReadFile(path)
	must(err)
	out := map[string]any{}
	must(json.Unmarshal(data, &out))
	return out
}
