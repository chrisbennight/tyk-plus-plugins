package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/bench"
)

func runBench(args []string) error {
	flags := flag.NewFlagSet("bench", flag.ExitOnError)
	sizes := bench.DefaultSizes
	store := flags.String("store", "", "measure the active set in this policy store")
	synthetic := flags.Bool("synthetic", false, "measure a generated deployment instead of a store")
	seed := flags.Int64("seed", 1, "seed for generated sets, callers, and requests")
	flags.IntVar(&sizes.Proxies, "proxies", sizes.Proxies, "generated proxies")
	flags.IntVar(&sizes.ToolsPerProxy, "tools", sizes.ToolsPerProxy, "generated tools per proxy")
	flags.IntVar(&sizes.Rules, "rules", sizes.Rules, "generated rules")
	flags.IntVar(&sizes.Callers, "callers", sizes.Callers, "distinct callers in the request mix")
	flags.IntVar(&sizes.Requests, "requests", sizes.Requests, "decisions to measure")
	flags.Float64Var(&sizes.PermitRatio, "permit-ratio", sizes.PermitRatio, "target share of permitted requests")
	compileRuns := flags.Int("compile-runs", 5, "times to compile the set")
	format := flags.String("format", "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	switch {
	case flags.NArg() != 0:
		return errors.New("bench takes no arguments")
	case (*store == "") == !*synthetic:
		return errors.New("bench needs exactly one of -store or -synthetic")
	case *format != "text" && *format != "json":
		return fmt.Errorf("unknown format %q", *format)
	case sizes.Proxies < 1 || sizes.ToolsPerProxy < 1 || sizes.Rules < 0 || sizes.Callers < 1 || sizes.Requests < 1:
		return errors.New("sizes must be positive")
	case !(sizes.PermitRatio >= 0 && sizes.PermitRatio <= 1):
		return errors.New("-permit-ratio must be between 0 and 1")
	}

	var files bench.Files
	var vocab bench.Vocabulary
	var version, label, source string
	if *synthetic {
		source = "synthetic"
		files.Rules, files.Tools, vocab = bench.Synthetic(*seed, sizes)
		files.Checks = []byte("[]")
		version = files.Fingerprint()
	} else {
		source = "store"
		var err error
		if files, vocab, version, label, err = bench.FromStore(*store, sizes.Callers); err != nil {
			return err
		}
	}
	report, err := bench.Run(files, version, vocab, *seed, sizes, *compileRuns)
	if err != nil {
		return err
	}
	report.Source, report.Label = source, label
	if *format == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	d := func(ns int64) string { return time.Duration(ns).String() }
	fmt.Printf("Set %s (%s, seed %d): %d rules, %d tools on %d proxies, %d bytes\n",
		report.Version, report.Source, report.Seed, report.Set.Rules, report.Set.Tools, report.Set.Proxies, report.Set.Bytes)
	fmt.Printf("Compile:   median %s, p99 %s, max %s over %d runs\n", d(report.Compile.Median), d(report.Compile.P99), d(report.Compile.Max), report.Compile.Count)
	if report.Decisions.Count == 0 {
		fmt.Println("Decisions: none measured; the set has no reviewed tools")
	} else {
		fmt.Printf("Decisions: median %s, p99 %s, max %s over %d calls from %d callers\n",
			d(report.Decisions.Median), d(report.Decisions.P99), d(report.Decisions.Max), report.Decisions.Count, report.Set.Callers)
		fmt.Printf("Outcomes:  %v (permitted share %.2f, target %.2f)\n", report.Decisions.Outcomes, report.Decisions.PermitRatio, report.Decisions.TargetPermitRatio)
	}
	if v := report.Visibility; v.Tools > 0 {
		fmt.Printf("Visibility: %d tools on %s: first list median %s, p99 %s; cached list median %s, p99 %s over %d callers\n",
			v.Tools, v.Proxy, d(v.First.Median), d(v.First.P99), d(v.Cached.Median), d(v.Cached.P99), v.First.Count)
	}
	fmt.Printf("Memory:    set heap %d bytes, %d bytes allocated per decision, peak resident %d bytes\n",
		report.Memory.SetHeapBytes, report.Memory.AllocBytesPerDecision, report.Memory.PeakRSSBytes)
	fmt.Printf("Build:     %s, cedar-go %s, %s\n", report.Build.Go, report.Build.CedarGo, report.Build.Platform)
	return nil
}
