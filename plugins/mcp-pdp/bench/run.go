package bench

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"runtime"
	"runtime/debug"
	"slices"
	"syscall"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

// Files are a set's policy files. Format is the store format the files come
// from; zero means the current format.
type Files struct {
	Rules, Tools, Instructions, Checks []byte
	Format                             int
}

// inputs returns the files in the roles the compiler reads them. A current
// set without instructions approves none.
func (f Files) inputs() policy.Inputs {
	in := policy.Inputs{Rules: f.Rules, Tools: f.Tools, Instructions: f.Instructions, Checks: f.Checks, Format: f.Format}
	if f.Format != 1 && in.Instructions == nil {
		in.Instructions = []byte("{}\n")
	}
	return in
}

// Fingerprint identifies the files as the store would name their set.
func (f Files) Fingerprint() string {
	in := f.inputs()
	format, named := policy.FormatVersion, map[string][]byte{
		"rules.cedar": in.Rules, "approved_tools.json": in.Tools, "approved_instructions.json": in.Instructions, "checks.json": in.Checks}
	if f.Format == 1 {
		format, named = 1, map[string][]byte{"rules.cedar": in.Rules, "tools.json": in.Tools, "checks.json": in.Checks}
	}
	hashes := map[string]string{}
	for name, data := range named {
		sum := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	return policy.Fingerprint(format, hashes)
}

// FromStore reads the active set of a policy store, with a vocabulary drawn
// from its rules.
func FromStore(root string, callers int) (files Files, vocab Vocabulary, version, label string, err error) {
	pointer, err := policy.ReadPointer(root)
	if err != nil {
		return files, vocab, "", "", err
	}
	manifest, contents, err := policy.ReadSet(root, pointer.Set)
	if err != nil {
		return files, vocab, "", "", err
	}
	in := policy.InputsOf(manifest.Format, contents)
	files = Files{Rules: in.Rules, Tools: in.Tools, Instructions: in.Instructions, Checks: in.Checks, Format: manifest.Format}
	return files, Harvest(files.Rules, callers), pointer.Set, manifest.Label, nil
}

// Report is the result of one benchmark run. Durations are in nanoseconds.
type Report struct {
	Source  string `json:"source"`
	Seed    int64  `json:"seed"`
	Version string `json:"version"`
	Label   string `json:"label,omitempty"`
	Set     struct {
		Rules   int `json:"rules"`
		Proxies int `json:"proxies"`
		Tools   int `json:"tools"`
		Callers int `json:"callers"`
		Bytes   int `json:"bytes"`
	} `json:"set"`
	// Compile is the time to parse and validate the set and run its
	// activation checks, which the gateway does on every change.
	Compile   Durations `json:"compile"`
	Decisions struct {
		Durations
		Outcomes    map[string]int `json:"outcomes"`
		PermitRatio float64        `json:"permitRatio"`
		// TargetPermitRatio is the share requested; sets that rarely permit
		// or deny can fall short of it.
		TargetPermitRatio float64 `json:"targetPermitRatio"`
	} `json:"decisions"`
	// Visibility is the time to decide which of one proxy's tools a caller
	// may see in its list: First for the caller's first list after a set
	// change, Cached for a later one. The proxy is the one with the most
	// tools.
	Visibility struct {
		Proxy  string    `json:"proxy"`
		Tools  int       `json:"tools"`
		First  Durations `json:"first"`
		Cached Durations `json:"cached"`
	} `json:"visibility"`
	Memory struct {
		// SetHeapBytes is the heap retained by the compiled set.
		SetHeapBytes uint64 `json:"setHeapBytes"`
		// AllocBytesPerDecision is the memory allocated by each decision.
		AllocBytesPerDecision uint64 `json:"allocBytesPerDecision"`
		// PeakRSSBytes is the largest resident memory of the whole process.
		PeakRSSBytes uint64 `json:"peakRssBytes"`
	} `json:"memory"`
	Build struct {
		Go       string `json:"go"`
		CedarGo  string `json:"cedarGo"`
		Platform string `json:"platform"`
	} `json:"build"`
}

// Durations summarizes timings.
type Durations struct {
	Count  int   `json:"count"`
	Median int64 `json:"medianNs"`
	P99    int64 `json:"p99Ns"`
	Max    int64 `json:"maxNs"`
}

func summarize(samples []time.Duration) Durations {
	if len(samples) == 0 {
		return Durations{}
	}
	slices.Sort(samples)
	at := func(q float64) int64 {
		return int64(samples[int(math.Ceil(q*float64(len(samples))))-1])
	}
	return Durations{Count: len(samples), Median: at(0.5), P99: at(0.99), Max: int64(samples[len(samples)-1])}
}

func heap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// Run compiles the set compileRuns times, then decides the generated
// requests one at a time and reports the distribution of decision times.
func Run(files Files, version string, vocab Vocabulary, seed int64, sizes Sizes, compileRuns int) (Report, error) {
	var report Report
	report.Seed, report.Version = seed, version
	report.Set.Rules = countRules(files.Rules)
	in := files.inputs()
	report.Set.Bytes = len(in.Rules) + len(in.Tools) + len(in.Instructions) + len(in.Checks)

	before := heap()
	var snapshot *policy.Snapshot
	var compiles []time.Duration
	for range max(compileRuns, 1) {
		snapshot = nil
		runtime.GC()
		start := time.Now()
		compiled, err := policy.Compile(files.inputs(), version)
		compiles = append(compiles, time.Since(start))
		if err != nil {
			return report, err
		}
		snapshot = compiled
	}
	report.Compile = summarize(compiles)
	if after := heap(); after > before {
		report.Memory.SetHeapBytes = after - before
	}
	// The input files were live for the first measurement, so they must stay
	// live for the second; otherwise their bytes would be subtracted.
	runtime.KeepAlive(files)

	tools := snapshot.Tools()
	proxies := map[string]bool{}
	for _, t := range tools {
		proxies[t.Proxy] = true
	}
	requests := Requests(seed, snapshot, vocab, sizes)
	report.Set.Proxies, report.Set.Tools = len(proxies), len(tools)
	report.Decisions.TargetPermitRatio = sizes.PermitRatio
	if len(requests) > 0 {
		report.Set.Callers = max(sizes.Callers, 1)
	}

	// A short warm-up keeps one-time costs out of the measured decisions.
	for _, r := range requests[:min(len(requests), 200)] {
		snapshot.Decide(r.Caller, r.Tool.Proxy, r.Tool.Upstream, r.Tool.Name, r.Arguments)
	}
	samples := make([]time.Duration, len(requests))
	outcomes := map[string]int{}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	allocated := m.TotalAlloc
	for i, r := range requests {
		start := time.Now()
		outcome, _ := snapshot.Decide(r.Caller, r.Tool.Proxy, r.Tool.Upstream, r.Tool.Name, r.Arguments)
		samples[i] = time.Since(start)
		outcomes[outcome]++
	}
	runtime.ReadMemStats(&m)
	if len(requests) > 0 {
		report.Memory.AllocBytesPerDecision = (m.TotalAlloc - allocated) / uint64(len(requests))
		report.Decisions.PermitRatio = float64(outcomes["permitted"]) / float64(len(requests))
	}
	report.Decisions.Durations = summarize(samples)
	report.Decisions.Outcomes = outcomes
	measureVisibility(&report, snapshot, tools, requests)
	report.Memory.PeakRSSBytes = peakRSS()

	report.Build.Go = runtime.Version()
	report.Build.Platform = runtime.GOOS + "/" + runtime.GOARCH
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/cedar-policy/cedar-go" {
				report.Build.CedarGo = dep.Version
			}
		}
	}
	return report, nil
}

func countRules(rules []byte) int {
	list, err := cedar.NewPolicyListFromBytes("rules.cedar", rules)
	if err != nil {
		return 0
	}
	return len(list)
}

func peakRSS() uint64 {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		return 0
	}
	// Linux reports kibibytes; macOS reports bytes.
	if runtime.GOOS == "darwin" {
		return uint64(usage.Maxrss)
	}
	return uint64(usage.Maxrss) * 1024
}

// measureVisibility times the first and a cached visibility check of the
// largest proxy for up to 50 of the requests' distinct callers.
func measureVisibility(report *Report, snapshot *policy.Snapshot, tools []policy.ToolRef, requests []Request) {
	perProxy := map[string]int{}
	for _, t := range tools {
		perProxy[t.Proxy]++
	}
	for proxy, count := range perProxy {
		if count > report.Visibility.Tools || count == report.Visibility.Tools && proxy < report.Visibility.Proxy {
			report.Visibility.Proxy, report.Visibility.Tools = proxy, count
		}
	}
	if report.Visibility.Tools == 0 {
		return
	}
	seen := map[string]bool{}
	var first, cached []time.Duration
	for _, r := range requests {
		key := fmt.Sprint(r.Caller)
		if seen[key] || len(seen) == 50 {
			continue
		}
		seen[key] = true
		start := time.Now()
		snapshot.VisibleTools(r.Caller, report.Visibility.Proxy)
		first = append(first, time.Since(start))
		start = time.Now()
		snapshot.VisibleTools(r.Caller, report.Visibility.Proxy)
		cached = append(cached, time.Since(start))
	}
	report.Visibility.First, report.Visibility.Cached = summarize(first), summarize(cached)
}
