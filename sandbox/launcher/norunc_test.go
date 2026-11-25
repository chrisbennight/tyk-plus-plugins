//go:build !dev

package launcher

import (
	"testing"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

// A release build carries no runc backend: it never names a runtime for it.
func TestReleaseBuildsHaveNoRuncBackend(t *testing.T) {
	if RuncBuilt {
		t.Fatal("a release build includes the runc backend")
	}
	if name, args := RuntimeCommand(protocol.BackendRunc, "run", "run-0011"); name != "" || args != nil {
		t.Fatalf("a release build would run %s %v", name, args)
	}
}
