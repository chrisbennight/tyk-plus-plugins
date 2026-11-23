package bench

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

var small = Sizes{Proxies: 2, ToolsPerProxy: 10, Callers: 50, Rules: 120, Requests: 400, PermitRatio: 0.3}

func TestSyntheticWorkloadsCompileAndRepeat(t *testing.T) {
	for seed := range int64(5) {
		rules, tools, vocab := Synthetic(seed, small)
		snapshot, err := policy.Compile(rules, tools, []byte("[]"), "test")
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		againRules, againTools, againVocab := Synthetic(seed, small)
		if !bytes.Equal(rules, againRules) || !bytes.Equal(tools, againTools) {
			t.Fatalf("seed %d produced a different set", seed)
		}
		if !reflect.DeepEqual(Requests(seed, snapshot, vocab, small), Requests(seed, snapshot, againVocab, small)) {
			t.Fatalf("seed %d produced a different request mix", seed)
		}
	}
}

func TestSyntheticRulesUseEveryTemplate(t *testing.T) {
	rules, _, _ := Synthetic(1, Sizes{Proxies: 1, ToolsPerProxy: 5, Callers: 5, Rules: 400})
	for _, want := range []string{`{name: "readOnly", value: true}`, "principal.groups.contains", "resource.name ==",
		`{name: "team", value:`, "permit (principal, action, resource) when { principal.scopes.contains", "principal.subject ==",
		"upstreamAnnotations has readOnlyHint", "unless", `{name: "vendor.batchSafe", value: false}`,
		`{name: "risk", value: "high"}`, `context.flags.contains`} {
		if !bytes.Contains(rules, []byte(want)) {
			t.Errorf("no rule uses %q", want)
		}
	}
}

func TestRunReachesTargetPermitShare(t *testing.T) {
	rules, tools, vocab := Synthetic(3, small)
	report, err := Run(Files{rules, tools, []byte("[]")}, "test", vocab, 3, small, 1)
	if err != nil {
		t.Fatal(err)
	}
	if report.Decisions.Count != small.Requests || math.Abs(report.Decisions.PermitRatio-small.PermitRatio) > 0.01 {
		t.Fatalf("got %d decisions with permitted share %.3f", report.Decisions.Count, report.Decisions.PermitRatio)
	}
	if report.Set.Rules != small.Rules || report.Set.Tools != 20 || report.Decisions.Median <= 0 || report.Decisions.Max < report.Decisions.P99 {
		t.Fatalf("unexpected report %+v", report)
	}
}

func TestHarvestedValuesLetRequestsMatchRules(t *testing.T) {
	rules := []byte(`@id("only")
permit (principal, action == Action::"tools/call", resource) when {
  principal.roles.containsAny(["auditor", "billing-admin"]) &&
  context.strings.contains({name: "team", value: "billing"}) &&
  context.numbers.contains({name: "limit", value: 100})
};`)
	tools := []byte(`{"p": {"upstream": "https://u.example/mcp", "tools": {"t": {"arguments": {"team": "string", "limit": "long"}}}}}`)
	snapshot, err := policy.Compile(rules, tools, []byte("[]"), "test")
	if err != nil {
		t.Fatal(err)
	}
	vocab := Harvest(rules, 20)
	if slices.Contains(vocab.roles, "only") {
		t.Fatalf("annotation values leaked into the vocabulary: %v", vocab.roles[:4])
	}
	sizes := Sizes{Callers: 20, Requests: 200, PermitRatio: 0.5}
	outcomes := map[string]int{}
	for _, r := range Requests(1, snapshot, vocab, sizes) {
		outcome, _ := snapshot.Decide(r.Caller, r.Tool.Proxy, r.Tool.Upstream, r.Tool.Name, r.Arguments)
		outcomes[outcome]++
	}
	// The permit needs a rare combination of role and argument values, so the
	// draws may fall short of the target; what matters is that it is reached.
	if outcomes["permitted"] == 0 || outcomes["permitted"]+outcomes["policy_denied"] != 200 {
		t.Fatalf("got %v", outcomes)
	}
}

func TestOneSidedSetStillGivesAFullRun(t *testing.T) {
	rules, tools, vocab := []byte(""), []byte(`{"p": {"upstream": "https://u.example/mcp", "tools": {"t": {}}}}`), genericVocabulary(5)
	report, err := Run(Files{rules, tools, []byte("[]")}, "test", vocab, 1, Sizes{Callers: 5, Requests: 50, PermitRatio: 1}, 1)
	if err != nil || report.Decisions.Count != 50 || report.Decisions.Outcomes["policy_denied"] != 50 {
		t.Fatalf("got %+v %v", report.Decisions, err)
	}
}

func TestStoreModeMeasuresTheActiveSet(t *testing.T) {
	rules, tools, _ := Synthetic(2, small)
	source, root := t.TempDir(), t.TempDir()
	for name, data := range map[string][]byte{"rules.cedar": rules, "tools.json": tools, "checks.json": []byte("[]")} {
		if err := os.WriteFile(filepath.Join(source, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set, err := policy.Promote(root, source, "bench", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	files, vocab, version, label, err := FromStore(root, small.Callers)
	if err != nil || version != set || label != "bench" || files.Fingerprint() != set {
		t.Fatalf("got %q %q %v", version, label, err)
	}
	report, err := Run(files, version, vocab, 2, small, 1)
	if err != nil || report.Decisions.Count != small.Requests || report.Decisions.Outcomes["permitted"] == 0 {
		t.Fatalf("got %+v %v", report.Decisions, err)
	}
}

func TestSummarizePercentiles(t *testing.T) {
	var samples []time.Duration
	for i := 100; i >= 1; i-- {
		samples = append(samples, time.Duration(i))
	}
	if got := summarize(samples); got != (Durations{Count: 100, Median: 50, P99: 99, Max: 100}) {
		t.Fatalf("got %+v", got)
	}
}

// A gateway validates a new set in the background while calls keep using the
// current one. While the reloader compiles a large candidate, decisions read
// through the active pointer must not wait for it.
func TestDecisionsDoNotWaitForValidation(t *testing.T) {
	rules, tools, vocab := Synthetic(4, small)
	bigRules, bigTools, _ := Synthetic(5, Sizes{Proxies: 10, ToolsPerProxy: 500, Callers: 10, Rules: 1000})
	store := t.TempDir()
	publish := func(label string, rules, tools []byte) string {
		source := t.TempDir()
		for name, data := range map[string][]byte{"rules.cedar": rules, "tools.json": tools, "checks.json": []byte("[]")} {
			if err := os.WriteFile(filepath.Join(source, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		set, err := policy.Promote(store, source, label, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	candidate := publish("candidate", bigRules, bigTools)
	current := publish("current", rules, tools)
	var active atomic.Pointer[policy.Snapshot]
	reloader := policy.NewReloader(store, "", &active)
	reloader.Load()
	if active.Load() == nil || active.Load().Version != current {
		t.Fatal("current set not loaded")
	}
	requests := Requests(4, active.Load(), vocab, small)
	if err := policy.Activate(store, candidate, time.Now); err != nil {
		t.Fatal(err)
	}

	started, done := make(chan struct{}), make(chan time.Duration)
	go func() {
		close(started)
		begin := time.Now()
		reloader.Load()
		done <- time.Since(begin)
	}()
	<-started
	var samples []time.Duration
	for compiling := true; compiling; {
		select {
		case compile := <-done:
			compiling = false
			if active.Load().Version != candidate {
				t.Fatal("the candidate was not activated")
			}
			if len(samples) == 0 {
				t.Fatalf("no decision completed during a %s reload", compile)
			}
			// The median ignores a single scheduler or collector pause.
			if median := summarize(samples).Median; time.Duration(median) > compile/20 {
				t.Fatalf("median decision %s during a %s reload", time.Duration(median), compile)
			}
		default:
			r := requests[len(samples)%len(requests)]
			begin := time.Now()
			active.Load().Decide(r.Caller, r.Tool.Proxy, r.Tool.Upstream, r.Tool.Name, r.Arguments)
			samples = append(samples, time.Since(begin))
		}
	}
}
