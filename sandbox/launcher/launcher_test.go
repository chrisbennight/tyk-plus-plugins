package launcher

import (
	"strings"
	"testing"

	"github.com/chrisbennight/tyk-plus-plugins/sandbox/protocol"
)

func TestRequestsAreTypedAndBounded(t *testing.T) {
	for _, c := range []struct {
		line string
		ok   bool
	}{
		{`{"op":"start","run_ms":30000}`, true},
		{`{"op":"health"}`, true},
		{`{"op":"start","run_ms":0}`, false},
		{`{"op":"start","run_ms":120001}`, false},
		{`{"op":"start","run_ms":1000,"image":"evil"}`, false},
		{`{"op":"exec","run_ms":1000}`, false},
		{`{"op":"health","run_ms":5}`, false},
		{`{"op":"health"} {"op":"start"}`, false},
	} {
		req, err := DecodeRequest([]byte(c.line))
		if err == nil {
			err = req.Validate(120_000)
		}
		if (err == nil) != c.ok {
			t.Errorf("%s: accepted %v, want %v (%v)", c.line, err == nil, c.ok, err)
		}
	}
}

func TestRuntimeCommandsUseOnlyFixedValues(t *testing.T) {
	name, args := RuntimeCommand(protocol.BackendGVisor, "run", "run-0011")
	got := name + " " + strings.Join(args, " ")
	want := "runsc --root=/run/sandbox/runsc --network=none --platform=systrap --ignore-cgroups run --bundle /run/sandbox/bundles/run-0011 run-0011"
	if got != want {
		t.Errorf("gVisor run command\n got %s\nwant %s", got, want)
	}
	name, args = RuntimeCommand(protocol.BackendRunc, "delete", "run-0011")
	if got := name + " " + strings.Join(args, " "); got != "runc --root=/run/sandbox/runc delete --force run-0011" {
		t.Errorf("runc delete command: %s", got)
	}
}

func TestSpecIsolatesTheSandbox(t *testing.T) {
	spec := Spec([]string{"/worker"}, 256<<20)
	process := spec["process"].(map[string]any)
	if process["noNewPrivileges"] != true || process["user"].(map[string]any)["uid"] != sandboxUser {
		t.Errorf("process is not unprivileged: %v", process)
	}
	if root := spec["root"].(map[string]any); root["readonly"] != true || root["path"] != RootFS {
		t.Errorf("root is not the read-only worker image: %v", root)
	}
	var types []string
	for _, ns := range spec["linux"].(map[string]any)["namespaces"].([]map[string]any) {
		types = append(types, ns["type"].(string))
	}
	if !strings.Contains(strings.Join(types, ","), "network") {
		t.Errorf("no network namespace: %v", types)
	}
}

func TestSelfTestProblem(t *testing.T) {
	if p := SelfTestProblem(map[string]string{"network": "blocked", "host file": "blocked"}); p != "" {
		t.Errorf("all blocked reported %q", p)
	}
	if p := SelfTestProblem(map[string]string{"network": "allowed", "host file": "blocked"}); !strings.Contains(p, "network") {
		t.Errorf("allowed network reported %q", p)
	}
	if p := SelfTestProblem(nil); p == "" {
		t.Error("no results reported no problem")
	}
}
