// Command cedar-policy publishes and activates policy sets in a policy store.
// It validates with the same code the gateway uses, so a set it activates is
// one the gateway accepts.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

const usage = `Usage:
  cedar-policy promote -store DIR [-label TEXT] SOURCE_DIR
      Validate rules.cedar, approved_tools.json, approved_instructions.json
      (optional) and checks.json in SOURCE_DIR, store
      them as a set, and make that set active. A directory from an earlier
      build with tools.json instead of approved_tools.json is also accepted.
      A set keeps the label it was first published with.
  cedar-policy activate -store DIR SET
      Validate an existing set again and make it active, for example to roll
      back to the set the active pointer records as previous.
  cedar-policy show -store DIR
      Print the active pointer.
  cedar-policy bench (-store DIR | -synthetic) [options]
      Measure how long the active set, or a generated one, takes to compile
      and to decide tool calls. Run "cedar-policy bench -h" for options.
  cedar-policy drift COMMAND [options]
      Review upstream changes gateways queued in CEDAR_PENDING_DIR. Run
      "cedar-policy drift help" for the commands.
`

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("a command is required"))
	}
	if os.Args[1] == "drift" {
		if len(os.Args) > 2 && (os.Args[2] == "help" || os.Args[2] == "-h") {
			fmt.Print(driftUsage)
			return
		}
		if err := runDrift(os.Args[2:], os.Stdout, time.Now); err != nil {
			// Messages can name files and tools from the shared directory,
			// so hidden characters are written out.
			fmt.Fprintf(os.Stderr, "cedar-policy drift: %s\n\n%s", shownName(err.Error()), driftUsage)
			os.Exit(1)
		}
		return
	}
	if os.Args[1] == "bench" {
		if err := runBench(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "cedar-policy: %v\n", err)
			os.Exit(1)
		}
		return
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	flags.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	store := flags.String("store", "", "policy store directory")
	label := flags.String("label", "", "human-readable label for the set")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fail(err)
	}
	if *store == "" {
		fail(fmt.Errorf("-store is required"))
	}
	switch os.Args[1] {
	case "promote":
		requireArgs(flags, 1)
		set, err := policy.Promote(*store, flags.Arg(0), *label, time.Now)
		if err != nil {
			fail(err)
		}
		fmt.Println(set)
	case "activate":
		requireArgs(flags, 1)
		if err := policy.Activate(*store, flags.Arg(0), time.Now); err != nil {
			fail(err)
		}
		fmt.Println(flags.Arg(0))
	case "show":
		requireArgs(flags, 0)
		pointer, err := policy.ReadPointer(*store)
		if err != nil {
			fail(err)
		}
		// Print the pointer even when its set cannot be loaded, so the previous
		// fingerprint is available for a rollback.
		view := struct {
			policy.Pointer
			Label string `json:"label,omitempty"`
			Error string `json:"error,omitempty"`
		}{Pointer: pointer}
		if _, manifest, err := policy.LoadSet(*store, pointer.Set); err != nil {
			view.Error = err.Error()
		} else {
			view.Label = manifest.Label
		}
		data, _ := json.MarshalIndent(view, "", "  ")
		fmt.Println(string(data))
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}

func requireArgs(flags *flag.FlagSet, count int) {
	if flags.NArg() != count {
		fail(fmt.Errorf("%s expects %d argument(s)", flags.Name(), count))
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "cedar-policy: %v\n\n%s", err, usage)
	os.Exit(1)
}
