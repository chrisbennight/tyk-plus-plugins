package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	// The gateway shares what it saw: a gateway that never listed the tool,
	// enforcing the same set, refuses calls to it within its refresh
	// interval, and the change waits for review.
	awaitPeerSet(readReport()["active"])
	// Each list is shared again with its own time, so each client version
	// must produce a declaration of its own.
	awaitSharedDeclaration("governed", "change", listedAt)
	time.Sleep(time.Second)
	call(connectAt(peerGateway, k.operator, version), k.operator, "change", args("count", 2))
	checkPendingChange("governed", "change", catalog["change"])
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

	// Approving what the upstream declares lets the call through again.
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
// filed under its fingerprint.
func checkPendingChange(proxy, tool string, declared map[string]any) {
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
