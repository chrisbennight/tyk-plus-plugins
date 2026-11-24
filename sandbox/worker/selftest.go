package worker

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// SelfTest is what a worker reports when started in self-test mode inside a
// fresh sandbox. It stands in for a program that has already escaped the
// JavaScript engine, and records for each boundary whether the sandbox
// enforced it. Each check needs evidence of the boundary itself, so a mere
// permission error does not count.
func SelfTest(hostFile, scratchDir string) map[string]string {
	outcome := func(blocked bool, detail string) string {
		if blocked {
			return "blocked"
		}
		return "allowed: " + detail
	}
	results := map[string]string{}

	// A sandbox network namespace has no interface but loopback.
	ifaces, err := net.Interfaces()
	var names []string
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback == 0 {
			names = append(names, i.Name)
		}
	}
	results["network"] = outcome(err == nil && len(names) == 0, strings.Join(names, ","))

	// The host file is readable by everyone; only its absence from the
	// sandbox's file system blocks it.
	_, err = os.Stat(hostFile)
	results["host file"] = outcome(errors.Is(err, fs.ErrNotExist), "the file is visible")

	// The scratch directory is writable by the sandbox user; only a read-only
	// file system blocks the write.
	err = os.WriteFile(scratchDir+"/self-test", []byte("x"), 0o600)
	results["write"] = outcome(errors.Is(err, syscall.EROFS), "the file system is writable")

	// A sandbox has its own process namespace, so /proc shows this process
	// and no other. An empty or missing /proc proves nothing.
	entries, err := os.ReadDir("/proc")
	var pids []string
	for _, e := range entries {
		if e.Name()[0] >= '0' && e.Name()[0] <= '9' {
			pids = append(pids, e.Name())
		}
	}
	self := strconv.Itoa(os.Getpid())
	results["processes"] = outcome(err == nil && len(pids) == 1 && pids[0] == self, "/proc shows "+strings.Join(pids, ","))
	return results
}
