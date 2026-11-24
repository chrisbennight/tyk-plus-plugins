package drift

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
)

const (
	fingerprintA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fingerprintB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func openTestPending(t *testing.T, dir string) *Pending {
	t.Helper()
	p, err := OpenPending(dir, "gateway-1", Limits{MaxDefinitionBytes: 1 << 10, MaxUnapprovedPerProxy: 2})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSharedDeclarationsAreReadByEveryGateway(t *testing.T) {
	dir := t.TempDir()
	writer, reader := openTestPending(t, dir), openTestPending(t, dir)
	seen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := writer.writeLatest(&latestWrite{proxy: "governed", tool: "lookup", declared: Declared{Fingerprint: fingerprintA, SeenAt: seen, Gateway: "gateway-1"}}); err != nil {
		t.Fatal(err)
	}
	reader.Refresh(10)
	d, ok := reader.Latest("governed", "lookup")
	if !ok || d.Fingerprint != fingerprintA || !d.SeenAt.Equal(seen) {
		t.Fatalf("read %+v, %v", d, ok)
	}
	// A newer declaration replaces it.
	if err := writer.writeLatest(&latestWrite{proxy: "governed", tool: "lookup", declared: Declared{Fingerprint: fingerprintB, SeenAt: seen.Add(time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	reader.Refresh(10)
	if d, _ := reader.Latest("governed", "lookup"); d.Fingerprint != fingerprintB {
		t.Fatalf("read %+v", d)
	}
}

func TestReviewEntriesAreWrittenOncePerFingerprint(t *testing.T) {
	dir := t.TempDir()
	p := openTestPending(t, dir)
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, at := range []time.Time{first, first.Add(time.Hour)} {
		e := &ToolEntry{Proxy: "governed", Tool: "lookup", Fingerprint: fingerprintA, Definition: []byte(`{"name":"lookup"}`), FirstSeen: at, Gateway: "gateway-1"}
		if err := p.writeTool(e); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, encodeName("governed"), "tools", encodeName("lookup"), fingerprintA+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var e ToolEntry
	if err := jsonv2.Unmarshal(data, &e); err != nil || !e.FirstSeen.Equal(first) || string(e.Definition) != `{"name":"lookup"}` {
		t.Fatalf("entry %s: %v", data, err)
	}
	// No temporary files are left behind.
	leftovers, _ := filepath.Glob(filepath.Join(dir, "*", "*", "*", ".*"))
	if len(leftovers) != 0 {
		t.Fatalf("left %v", leftovers)
	}
}

func TestReviewEntriesStopAtTheLimit(t *testing.T) {
	dir := t.TempDir()
	p := openTestPending(t, dir)
	for _, fp := range []string{fingerprintA, fingerprintB} {
		if err := p.writeInstructions(&InstructionsEntry{Proxy: "governed", Fingerprint: fp, Instructions: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	p.Refresh(10)
	if err := p.writeTool(&ToolEntry{Proxy: "governed", Tool: "lookup", Fingerprint: fingerprintA, Definition: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, encodeName("governed"), "tools")); !os.IsNotExist(err) {
		t.Fatalf("an entry past the limit was written: %v", err)
	}
}

func TestNamesCannotLeaveTheDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "pending")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := openTestPending(t, dir)
	if err := p.writeTool(&ToolEntry{Proxy: "../..", Tool: "../../escape", Fingerprint: fingerprintA, Definition: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 {
		t.Fatalf("wrote outside the directory: %v", entries)
	}
	if strings.ContainsAny(encodeName("../a/b"), "./") {
		t.Fatal("an encoded name contains a path separator or dot")
	}
}

func TestUnreadableDeclarationsAreSkipped(t *testing.T) {
	dir := t.TempDir()
	latest := filepath.Join(dir, encodeName("governed"), "latest")
	if err := os.MkdirAll(latest, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		encodeName("garbled") + ".json":   `{`,
		encodeName("oversized") + ".json": `{"fingerprint":"` + fingerprintA + `","pad":"` + strings.Repeat("x", maxLatestFile) + `"}`,
		encodeName("notahash") + ".json":  `{"fingerprint":"nope"}`,
		"not-base64!.json":                `{"fingerprint":"` + fingerprintA + `"}`,
	} {
		if err := os.WriteFile(filepath.Join(latest, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := openTestPending(t, dir)
	p.Refresh(10)
	if n := len(*p.latest.Load()); n != 0 {
		t.Fatalf("read %d declarations", n)
	}
}

func TestWithoutADirectoryNothingIsShared(t *testing.T) {
	p := openTestPending(t, "")
	p.Changed("governed", "lookup", fingerprintA, []byte(`{}`))
	p.Saw("governed", "lookup", fingerprintA, time.Now())
	p.Refresh(10)
	if _, ok := p.Latest("governed", "lookup"); ok {
		t.Fatal("a declaration was shared without a directory")
	}
}

func TestMatchingSharedDeclarationsAreNotWrittenAgain(t *testing.T) {
	// No writer drains this queue, so what was offered stays in it.
	p := &Pending{queue: make(chan pendingWrite, 4)}
	declared := map[string]Declared{observationKey("governed", "lookup"): {Fingerprint: fingerprintA}}
	p.latest.Store(&declared)
	p.Saw("governed", "lookup", fingerprintA, time.Now())
	if len(p.queue) != 0 {
		t.Fatal("a matching declaration was queued")
	}
	p.Saw("governed", "lookup", fingerprintB, time.Now())
	if len(p.queue) != 1 {
		t.Fatal("a different declaration was not queued")
	}
}
