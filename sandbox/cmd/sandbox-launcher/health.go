package main

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/launcher"
)

// healthcheck asks the launcher in this container whether it can start
// sandboxes. The launcher answers only the sandbox service's user, health
// queries included, and a container health check runs as the container's
// user, root. So the check first becomes the service's user, which root in
// this container can already do, rather than the launcher trusting root.
func healthcheck() error {
	uid := uint32(number("SANDBOX_SERVICE_UID", 10001))
	if err := becomeUser(uid); err != nil {
		return err
	}
	return launcher.Healthcheck(env("SANDBOX_LAUNCHER_SOCKET", "/run/sandbox-launcher/launcher.sock"), 5*time.Second)
}

// becomeUser switches this process to uid, with a group of the same number
// and no supplementary groups. The launcher checks only the user. A process
// already running as uid stays as it is; any other user but root cannot
// switch, and the check fails rather than connecting as that user.
func becomeUser(uid uint32) error {
	current := os.Getuid()
	if current == int(uid) {
		return nil
	}
	if current != 0 {
		return fmt.Errorf("running as user %d; the health check must run as root or as the sandbox service's user %d", current, uid)
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("dropping supplementary groups: %w", err)
	}
	if err := syscall.Setgid(int(uid)); err != nil {
		return fmt.Errorf("switching to group %d: %w", uid, err)
	}
	if err := syscall.Setuid(int(uid)); err != nil {
		return fmt.Errorf("switching to user %d: %w", uid, err)
	}
	if os.Getuid() != int(uid) || os.Geteuid() != int(uid) {
		return fmt.Errorf("still running as user %d after switching to %d", os.Geteuid(), uid)
	}
	return nil
}
