//go:build dev

package launcher

import (
	"os"
	"strings"
)

// RuncBuilt reports whether this launcher includes the runc backend. Only
// development builds do: runc runs sandboxes without gVisor, privileged, and
// is meant for machines where gVisor is unavailable.
const RuncBuilt = true

func runcCommand(op, id string) (string, []string) {
	args := []string{"--root=" + stateDir + "/runc"}
	switch op {
	case "run":
		return "runc", append(args, "run", "--bundle", bundleDir(id), id)
	case "kill":
		return "runc", append(args, "kill", id, "KILL")
	case "delete":
		return "runc", append(args, "delete", "--force", id)
	default:
		return "runc", append(args, "list", "-q")
	}
}

// delegateCgroups moves the launcher out of its container's root cgroup so
// the root can delegate memory, CPU and process controllers to sandboxes.
func delegateCgroups() error {
	if err := os.MkdirAll("/sys/fs/cgroup/launcher", 0o755); err != nil {
		return err
	}
	procs, err := os.ReadFile("/sys/fs/cgroup/cgroup.procs")
	if err != nil {
		return err
	}
	for _, pid := range strings.Fields(string(procs)) {
		// A process may exit between reading and moving it.
		_ = os.WriteFile("/sys/fs/cgroup/launcher/cgroup.procs", []byte(pid), 0o644)
	}
	return os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0o644)
}
