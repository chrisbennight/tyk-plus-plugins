package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// driftSuite checks drift enforcement for one client version: only tools
// whose upstream definition matches the approved one are listed or callable.
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
	listed := catalogOf(c, k.operator)
	check(slices.Equal(slices.Sorted(maps.Keys(listed)), []string{"lookup"}), "%s: hide listed %v", version, slices.Collect(maps.Keys(listed)))
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

	// A tool that is no longer approved is hidden and refused.
	delete(tools, "lookup")
	inventory(map[string]any{}, tools)
	listed = catalogOf(c, k.operator)
	check(slices.Equal(slices.Sorted(maps.Keys(listed)), []string{"change"}), "%s: listed %v after removing lookup", version, slices.Collect(maps.Keys(listed)))
	call(c, k.operator, "lookup", args("count", 1))
	fmt.Printf("Verified drift enforcement for a %s client.\n", version)
}
