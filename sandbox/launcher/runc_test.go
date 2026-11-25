//go:build dev

package launcher

import (
	"strings"
	"testing"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

func TestRuncCommandsUseOnlyFixedValues(t *testing.T) {
	if !RuncBuilt {
		t.Fatal("a development build lacks the runc backend")
	}
	name, args := RuntimeCommand(protocol.BackendRunc, "delete", "run-0011")
	if got := name + " " + strings.Join(args, " "); got != "runc --root=/run/sandbox/runc delete --force run-0011" {
		t.Errorf("runc delete command: %s", got)
	}
}
