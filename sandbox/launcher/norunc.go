//go:build !dev

package launcher

import "errors"

// RuncBuilt reports whether this launcher includes the runc backend. Release
// builds do not, so they run sandboxes only under gVisor.
const RuncBuilt = false

// runcCommand is never reached in a release build: New refuses the runc
// backend before any sandbox runs. It names no binary, so a mistaken call
// fails rather than running anything.
func runcCommand(op, id string) (string, []string) { return "", nil }

func delegateCgroups() error { return errors.New("the runc backend is not built in") }
