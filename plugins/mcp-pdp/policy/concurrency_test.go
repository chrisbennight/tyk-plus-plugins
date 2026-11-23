package policy

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// promoteFiles publishes a set from the given file contents.
func promoteFiles(t *testing.T, store, label string, files map[string]string) string {
	t.Helper()
	source := t.TempDir()
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(source, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set, err := Promote(store, source, label, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// Decisions read the active set while the reloader replaces it. Run under the
// race detector, this fails if a decision and a swap ever touch shared state
// without synchronization.
func TestDecisionsDuringSetSwapsAreRaceFree(t *testing.T) {
	store := t.TempDir()
	tools := `{"p": {"upstream": "https://u.example/mcp", "tools": {"t": {"facts": {"readOnly": true}, "arguments": {"n": "long"}}}}}`
	permit := promoteFiles(t, store, "permit", map[string]string{"tools.json": tools, "checks.json": "[]",
		"rules.cedar": `permit (principal, action, resource) when { principal.roles.contains("r") && resource.reviewed.flags.contains({name: "readOnly", value: true}) };`})
	deny := promoteFiles(t, store, "deny", map[string]string{"tools.json": tools, "checks.json": "[]",
		"rules.cedar": `forbid (principal, action, resource) when { context.numbers.contains({name: "n", value: 1}) };`})

	var active atomic.Pointer[Snapshot]
	reloader := NewReloader(store, "", &active)
	reloader.Load()
	if active.Load() == nil {
		t.Fatal("no set loaded")
	}

	// Deciders keep going until the reloader has published several new sets,
	// so the run cannot pass on the initially loaded set alone.
	const publications = 20
	var published atomic.Int64
	var swapper sync.WaitGroup
	swapper.Add(1)
	go func() {
		defer swapper.Done()
		for i := 0; published.Load() < publications; i++ {
			target := [2]string{permit, deny}[i%2]
			if err := Activate(store, target, time.Now); err != nil {
				t.Error(err)
				return
			}
			before := active.Load()
			reloader.Load()
			if after := active.Load(); after != before && after.Version == target {
				published.Add(1)
			}
		}
	}()

	caller := Caller{Issuer: "i", Subject: "s", Roles: []string{"r"}}
	var deciders sync.WaitGroup
	outcomes := make([]map[string]int, 8)
	for g := range outcomes {
		outcomes[g] = map[string]int{}
		deciders.Add(1)
		go func(seen map[string]int) {
			defer deciders.Done()
			for published.Load() < publications {
				reason, _ := active.Load().Decide(caller, "p", "https://u.example/mcp", "t", []byte(`{"n": 1}`))
				seen[reason]++
			}
		}(outcomes[g])
	}
	swapper.Wait()
	deciders.Wait()

	total := map[string]int{}
	for _, seen := range outcomes {
		for reason, count := range seen {
			total[reason] += count
		}
	}
	// Both sets must have decided calls, and no decision may have any other outcome.
	if total["permitted"] == 0 || total["policy_denied"] == 0 || len(total) != 2 {
		t.Fatalf("outcomes across %d publications: %v", published.Load(), total)
	}
}
