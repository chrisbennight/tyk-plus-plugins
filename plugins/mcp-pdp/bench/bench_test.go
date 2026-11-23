package bench

import (
	"bytes"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

var small = Sizes{Proxies: 2, ToolsPerProxy: 10, Callers: 50, Rules: 120, Requests: 400, PermitRatio: 0.3}

func TestSyntheticSetsCompileAndRepeat(t *testing.T) {
	for seed := range int64(5) {
		rules, tools, _ := Synthetic(seed, small)
		if _, err := policy.Compile(rules, tools, []byte("[]"), "test"); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		again, _, _ := Synthetic(seed, small)
		if !bytes.Equal(rules, again) {
			t.Fatalf("seed %d produced different rules", seed)
		}
	}
}

func TestSyntheticRulesUseEveryTemplate(t *testing.T) {
	rules, _, _ := Synthetic(1, Sizes{Proxies: 1, ToolsPerProxy: 5, Callers: 5, Rules: 400})
	for _, want := range []string{"principal.groups.contains", "resource.name ==", "context.numbers", "principal.subject ==",
		"upstreamAnnotations has readOnlyHint", "unless", "forbid", "context.flags"} {
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

func TestHarvestFindsCallerNames(t *testing.T) {
	v := Harvest([]byte(`permit (principal, action, resource) when { principal.roles.contains("auditor") && principal.subject == "svc" };`), 3)
	if !slices.Equal(v.roles, []string{"auditor"}) || !slices.Equal(v.subjects, []string{"svc"}) || len(v.groups) == 0 {
		t.Fatalf("got %+v", v)
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
