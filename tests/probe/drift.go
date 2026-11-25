package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// driftSuite checks drift enforcement for one client version: only tools
// whose upstream definition matches the approved one are listed or callable,
// and only approved instructions reach the client.
// upstreamInstructions are the instructions the test upstream declares.
const upstreamInstructions = "Use lookup for records."

func driftSuite(k keys, version string) {
	c := connect(k.operator, version)
	// Later checks build on the staged set, so it is restored at the end.
	before := copyStaged()
	defer func() { publish("activated", before) }()
	// Without drift enforcement the upstream's list passes through unchanged.
	publish("activated", map[string]string{"rules.cedar": exampleRules, "approved_instructions.json": "{}", "checks.json": "[]"})
	publishInventory(map[string]any{}, upstream, "activated")
	catalog := catalogOf(c, k.operator)
	check(catalog["lookup"] != nil && catalog["change"] != nil, "%s: upstream listed %v", version, slices.Collect(maps.Keys(catalog)))
	// So do its instructions.
	declared := connect(k.operator, version)
	check(declared.hasInstructions && declared.instructions == upstreamInstructions, "%s: upstream instructions %q", version, declared.instructions)

	// The approved definition of change differs from what the upstream declares.
	approvedChange := with(catalog["change"], "description", "An approved description the upstream no longer declares")
	inventory := func(drift map[string]any, tools map[string]any) {
		data, _ := json.Marshal(map[string]any{"governed": map[string]any{"upstream": upstream, "drift": drift, "tools": tools}})
		publish("activated", map[string]string{"approved_tools.json": string(data)})
	}
	tools := map[string]any{
		"lookup": map[string]any{"facts": args("readOnly", true), "definition": catalog["lookup"], "arguments": args("count", "long")},
		"change": map[string]any{"definition": approvedChange, "arguments": args("count", "long")},
	}
	inventory(map[string]any{}, tools)
	listedAt := time.Now()
	listed := catalogOf(c, k.operator)
	check(slices.Equal(slices.Sorted(maps.Keys(listed)), []string{"lookup"}), "%s: hide listed %v", version, slices.Collect(maps.Keys(listed)))
	// Code Mode's search applies the same check: a tool waiting for review
	// is not offered to programs.
	found := searchNames(c, k.operator, "")
	check(slices.Equal(found, []string{"governed/lookup"}), "%s: search offered %v while change waits for review", version, found)
	// The gateway shares what it saw: a gateway that never listed the tool,
	// enforcing the same set, refuses calls to it within its refresh
	// interval, and the change waits for review.
	awaitPeerSet(readReport()["active"])
	// Each list is shared again with its own time, so each client version
	// must produce a declaration of its own.
	awaitSharedDeclaration("governed", "change", listedAt)
	time.Sleep(time.Second)
	call(connectAt(peerGateway, k.operator, version), k.operator, "change", args("count", 2))
	// The peer never listed either tool, so it allows lookup only on the
	// approved declaration it read from the shared directory.
	awaitSharedDeclaration("governed", "lookup", listedAt)
	call(connectAt(peerGateway, k.support, version), k.support, "lookup", args("count", 1), "found")
	queued := checkPendingChange("governed", "change", catalog["change"])
	check(sameJSON(listed["lookup"], catalog["lookup"]), "%s: lookup listed as %v", version, listed["lookup"])
	call(c, k.support, "lookup", args("count", 1), "found")
	changed := call(c, k.operator, "change", args("count", 2))
	unknown := call(c, k.operator, "unknown", args("count", 2))
	check(sameRefusal(changed, unknown), "%s: changed %v, unknown %v", version, changed, unknown)

	// serve-approved shows the approved definition, and calls stay refused
	// because the upstream still declares a different one.
	inventory(map[string]any{"changedTools": "serve-approved"}, tools)
	listed = catalogOf(c, k.operator)
	check(slices.Equal(slices.Sorted(maps.Keys(listed)), []string{"change", "lookup"}), "%s: serve-approved listed %v", version, slices.Collect(maps.Keys(listed)))
	check(sameJSON(listed["change"], approvedChange), "%s: change listed as %v", version, listed["change"])
	call(c, k.operator, "change", args("count", 2))

	// A reviewer finds the change the gateways queued, rejects it, and then
	// approves it, with cedar-policy drift.
	reviewDrift(c, k.operator, version, queued)
	tools["change"] = map[string]any{"definition": catalog["change"], "arguments": args("count", "long")}
	inventory(map[string]any{}, tools)
	call(c, k.operator, "change", args("count", 2), "updated")

	// Each caller is listed only the tools it could call: support may call
	// only read-only tools, and guest no tool at all.
	for _, want := range []struct {
		cred  credential
		tools []string
	}{{k.operator, []string{"change", "lookup"}}, {k.support, []string{"lookup"}}, {k.guest, []string{}}} {
		listed := catalogOf(c, want.cred)
		check(slices.Equal(slices.Sorted(maps.Keys(listed)), want.tools), "%s: listed %v, want %v", version, slices.Collect(maps.Keys(listed)), want.tools)
	}

	// A tool that is no longer approved is hidden and refused.
	delete(tools, "lookup")
	inventory(map[string]any{}, tools)
	listed = catalogOf(c, k.operator)
	check(slices.Equal(slices.Sorted(maps.Keys(listed)), []string{"change"}), "%s: listed %v after removing lookup", version, slices.Collect(maps.Keys(listed)))
	call(c, k.operator, "lookup", args("count", 1))

	// Instructions that differ from the approved text are replaced with it,
	// or removed when the proxy strips changed instructions.
	publish("activated", map[string]string{"approved_instructions.json": `{"governed":"Approved instructions."}`})
	inventory(map[string]any{}, tools)
	handshake := connect(k.operator, version)
	check(handshake.hasInstructions && handshake.instructions == "Approved instructions.", "%s: replaced instructions %q", version, handshake.instructions)
	inventory(map[string]any{"changedInstructions": "strip"}, tools)
	handshake = connect(k.operator, version)
	check(!handshake.hasInstructions, "%s: stripped instructions %q", version, handshake.instructions)
	// Approving what the upstream declares passes it on again.
	publish("activated", map[string]string{"approved_instructions.json": `{"governed":"` + upstreamInstructions + `"}`})
	handshake = connect(k.operator, version)
	check(handshake.hasInstructions && handshake.instructions == upstreamInstructions, "%s: approved instructions %q", version, handshake.instructions)
	fmt.Printf("Verified drift enforcement for a %s client.\n", version)
}

// checkPendingChange checks that the drift review directory holds an entry
// for a changed tool, holding exactly the definition the upstream declared,
// filed under its fingerprint, and returns that fingerprint.
func checkPendingChange(proxy, tool string, declared map[string]any) string {
	encode := func(name string) string { return base64.RawURLEncoding.EncodeToString([]byte(name)) }
	files, _ := filepath.Glob(filepath.Join("/pending", encode(proxy), "tools", encode(tool), "*.json"))
	check(len(files) > 0, "no review entry for %s on %s", tool, proxy)
	for _, file := range files {
		data, err := os.ReadFile(file)
		var entry struct {
			Proxy, Tool, Fingerprint string
			Definition               map[string]any
		}
		check(err == nil && json.Unmarshal(data, &entry) == nil, "review entry %s: %v", file, err)
		check(entry.Proxy == proxy && entry.Tool == tool && sameJSON(entry.Definition, declared) &&
			regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(entry.Fingerprint) &&
			filepath.Base(file) == entry.Fingerprint+".json", "review entry %s: %s", file, data)
	}
	var entry struct{ Fingerprint string }
	data, _ := os.ReadFile(files[0])
	json.Unmarshal(data, &entry)
	return entry.Fingerprint
}

// reviewDrift reviews the queued change of the change tool with the real
// cedar-policy drift commands, against the store and directory the gateways
// use. Rejecting it keeps calls refused on both gateways; approving it, which
// also lifts the rejection, lets calls through on both.
func reviewDrift(c *conn, cred credential, version, fingerprint string) {
	listed := reviewCommand("list")
	check(strings.Contains(listed, "governed\tchanged\ttool change\t"+fingerprint+"\tlatest"), "%s: drift list:\n%s", version, listed)
	shown := reviewCommand("show", "-proxy", "governed", "-tool", "change", fingerprint)
	check(strings.Contains(shown, "Changed tool change on governed") && strings.Contains(shown, "Fingerprint: "+fingerprint) &&
		strings.Contains(shown, "Description changed:\n- An approved description the upstream no longer declares\n+ "), "%s: drift show:\n%s", version, shown)

	checkDashboardReads(version, fingerprint)

	rejected := activeAfter(reviewCommand("reject", "-proxy", "governed", "-tool", "change", "-label", "probe reject", fingerprint))
	listed = reviewCommand("list")
	check(!strings.Contains(listed, fingerprint), "%s: a rejected change was listed:\n%s", version, listed)
	call(c, cred, "change", args("count", 2))
	call(connectAt(peerGateway, cred, version), cred, "change", args("count", 2))

	// One protocol version approves through the dashboard, the other with
	// the command; both write the same store the same way.
	var approved string
	if version == newerProtocol {
		approved = approveInDashboard(version, fingerprint)
		awaitReport(approved, "activated")
		awaitPeerSet(approved)
	} else {
		approved = activeAfter(reviewCommand("approve", "-proxy", "governed", "-tool", "change", "-label", "probe approve", fingerprint))
	}
	check(approved != rejected, "%s: approval did not publish a new set", version)
	// Approving lifts the rejection, so the definition is reviewed again if
	// the upstream returns to it after another is approved.
	inventory, err := os.ReadFile(filepath.Join(policyDir, "sets", approved, "approved_tools.json"))
	check(err == nil && !strings.Contains(string(inventory), fingerprint), "%s: the approved set still rejects %s: %v\n%s", version, fingerprint, err, inventory)
	listed = reviewCommand("list")
	check(!strings.Contains(listed, fingerprint), "%s: an approved change was listed:\n%s", version, listed)
	call(c, cred, "change", args("count", 2), "updated")
	call(connectAt(peerGateway, cred, version), cred, "change", args("count", 2), "updated")

	if version == newerProtocol {
		// Revoking the approval in the dashboard refuses calls again, and
		// rolling back restores it.
		revoked := revokeInDashboard(version, approved)
		awaitReport(revoked, "activated")
		awaitPeerSet(revoked)
		call(c, cred, "change", args("count", 2))
		rollBackInDashboard(version, revoked, approved)
		awaitReport(approved, "activated")
		awaitPeerSet(approved)
		call(c, cred, "change", args("count", 2), "updated")
	}
}

// reviewCommand runs a cedar-policy drift command against the shared store and
// directory and returns its output; the command must succeed.
func reviewCommand(command string, arguments ...string) string {
	full := append([]string{"drift", command, "-store", policyDir, "-pending", "/pending"}, arguments...)
	out, err := exec.Command("/cedar-policy", full...).CombinedOutput()
	check(err == nil, "cedar-policy %v: %v\n%s", full, err, out)
	return string(out)
}

// activeAfter waits until both gateways enforce the set a drift decision
// printed, and returns it.
func activeAfter(output string) string {
	set := strings.TrimSpace(output)
	check(regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(set), "drift decision printed %q", output)
	awaitReport(set, "activated")
	awaitPeerSet(set)
	return set
}

// awaitPeerSet waits until the peer gateway enforces a set.
func awaitPeerSet(set any) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var report map[string]any
		if data, err := os.ReadFile("/peer-status/status.json"); err == nil && json.Unmarshal(data, &report) == nil && report["enforcing"] == set {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	panic(fmt.Sprintf("peer gateway did not enforce set %v", set))
}

// awaitSharedDeclaration waits until a gateway shares a declaration of a
// tool seen after a time.
func awaitSharedDeclaration(proxy, tool string, after time.Time) {
	encode := func(name string) string { return base64.RawURLEncoding.EncodeToString([]byte(name)) }
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		files, _ := filepath.Glob(filepath.Join("/pending", encode(proxy), "latest", encode(tool), "*.json"))
		for _, file := range files {
			var declared struct{ SeenAt time.Time }
			if data, err := os.ReadFile(file); err == nil && json.Unmarshal(data, &declared) == nil && !declared.SeenAt.Before(after) {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	panic(fmt.Sprintf("no declaration of %s on %s was shared after %v", tool, proxy, after))
}
