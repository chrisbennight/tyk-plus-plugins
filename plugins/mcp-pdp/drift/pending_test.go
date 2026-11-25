package drift

import (
	"fmt"
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
	testUpstream = "https://u.example/mcp"
)

func every(string, string) bool { return true }

func openTestPending(t *testing.T, dir, gateway string) *Pending {
	t.Helper()
	return OpenPending(dir, gateway, Limits{MaxDefinitionBytes: 1 << 10, MaxUnapprovedPerProxy: 2})
}

func newWriter() *writer {
	return &writer{own: map[string]Declared{}, unapproved: map[string]int{}, written: map[string]int{}}
}

func declare(fingerprint string, at time.Time, approved bool) declaration {
	return declaration{proxy: "governed", tool: "lookup", approved: approved,
		declared: Declared{Fingerprint: fingerprint, SeenAt: at, Upstream: testUpstream}}
}

func TestTheNewestDeclarationOfAnyGatewayWins(t *testing.T) {
	dir := t.TempDir()
	one, two, reader := openTestPending(t, dir, "one"), openTestPending(t, dir, "two"), openTestPending(t, dir, "reader")
	w1, w2 := newWriter(), newWriter()
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	// Gateway two's newer declaration is written first; gateway one's older
	// one arrives late, in its own file, and does not replace it.
	if err := two.writeDeclaration(w2, declare(fingerprintB, start.Add(time.Minute), true)); err != nil {
		t.Fatal(err)
	}
	if err := one.writeDeclaration(w1, declare(fingerprintA, start, true)); err != nil {
		t.Fatal(err)
	}
	reader.Refresh("v", every)
	d, ok := reader.Latest("governed", "lookup", testUpstream)
	if !ok || d.Fingerprint != fingerprintB || d.Upstream != testUpstream {
		t.Fatalf("read %+v, %v", d, ok)
	}
}

func TestDeclarationsFromAnotherUpstreamAreKeptApart(t *testing.T) {
	dir := t.TempDir()
	reader := openTestPending(t, dir, "reader")
	one, two := openTestPending(t, dir, "one"), openTestPending(t, dir, "two")
	start := time.Now()
	if err := one.writeDeclaration(newWriter(), declare(fingerprintA, start, true)); err != nil {
		t.Fatal(err)
	}
	// A newer declaration from a gateway still on another upstream does not
	// hide the reviewed upstream's.
	other := declare(fingerprintB, start.Add(time.Minute), true)
	other.declared.Upstream = "https://old.example/mcp"
	if err := two.writeDeclaration(newWriter(), other); err != nil {
		t.Fatal(err)
	}
	reader.Refresh("v", every)
	if d, _ := reader.Latest("governed", "lookup", testUpstream); d.Fingerprint != fingerprintA {
		t.Fatalf("read %+v", d)
	}
}

func TestAnOlderSightingProcessedLateIsNotWritten(t *testing.T) {
	dir := t.TempDir()
	reader := openTestPending(t, dir, "reader")
	p := openTestPending(t, dir, "one")
	w := newWriter()
	start := time.Now()
	if err := p.writeDeclaration(w, declare(fingerprintB, start.Add(time.Second), true)); err != nil {
		t.Fatal(err)
	}
	if err := p.writeDeclaration(w, declare(fingerprintA, start, true)); err != nil {
		t.Fatal(err)
	}
	reader.Refresh("v", every)
	if d, _ := reader.Latest("governed", "lookup", testUpstream); d.Fingerprint != fingerprintB {
		t.Fatalf("read %+v", d)
	}
}

func TestARepeatedSightingOverridesANewerDifferentOne(t *testing.T) {
	dir := t.TempDir()
	reader := openTestPending(t, dir, "reader")
	one, two := openTestPending(t, dir, "one"), openTestPending(t, dir, "two")
	w1, w2 := newWriter(), newWriter()
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := one.writeDeclaration(w1, declare(fingerprintA, start, true)); err != nil {
		t.Fatal(err)
	}
	if err := two.writeDeclaration(w2, declare(fingerprintB, start.Add(time.Minute), true)); err != nil {
		t.Fatal(err)
	}
	// Gateway one sees A again after two saw B, before it has read B: it
	// writes again, so its sighting is the newest.
	if err := one.writeDeclaration(w1, declare(fingerprintA, start.Add(2*time.Minute), true)); err != nil {
		t.Fatal(err)
	}
	reader.Refresh("v", every)
	if d, _ := reader.Latest("governed", "lookup", testUpstream); d.Fingerprint != fingerprintA {
		t.Fatalf("read %+v", d)
	}
}

func TestUnidentifiedDefinitionsAreShared(t *testing.T) {
	dir := t.TempDir()
	reader := openTestPending(t, dir, "reader")
	p := openTestPending(t, dir, "one")
	if err := p.writeDeclaration(newWriter(), declare("", time.Now(), true)); err != nil {
		t.Fatal(err)
	}
	reader.Refresh("v", every)
	if d, ok := reader.Latest("governed", "lookup", testUpstream); !ok || d.Fingerprint != "" {
		t.Fatalf("read %+v, %v", d, ok)
	}
}

func TestOnlyReviewedToolsAreRead(t *testing.T) {
	dir := t.TempDir()
	p := openTestPending(t, dir, "one")
	if err := p.writeDeclaration(newWriter(), declare(fingerprintA, time.Now(), true)); err != nil {
		t.Fatal(err)
	}
	p.Refresh("v", func(_, tool string) bool { return tool != "lookup" })
	if _, ok := p.Latest("governed", "lookup", testUpstream); ok {
		t.Fatal("read a declaration of a tool the set does not review")
	}
}

func TestToolsWithoutApprovalAreSharedUpToTheLimit(t *testing.T) {
	dir := t.TempDir()
	reader := openTestPending(t, dir, "reader")
	p := openTestPending(t, dir, "one")
	w := newWriter()
	for _, tool := range []string{"a", "b", "c"} {
		d := declaration{proxy: "governed", tool: tool, declared: Declared{Fingerprint: fingerprintA, SeenAt: time.Now(), Upstream: testUpstream}}
		if err := p.writeDeclaration(w, d); err != nil {
			t.Fatal(err)
		}
	}
	reader.Refresh("v", every)
	_, a := reader.Latest("governed", "a", testUpstream)
	_, c := reader.Latest("governed", "c", testUpstream)
	if !a || c {
		t.Fatalf("shared a=%v c=%v past a limit of two", a, c)
	}
}

func TestReviewEntriesAreWrittenOncePerFingerprint(t *testing.T) {
	dir := t.TempDir()
	p := openTestPending(t, dir, "one")
	w := newWriter()
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, at := range []time.Time{first, first.Add(time.Hour)} {
		e := &ToolEntry{Proxy: "governed", Tool: "lookup", Fingerprint: fingerprintA, Definition: []byte(`{"name":"lookup"}`), FirstSeen: at}
		if err := p.writeReview(w, review{tool: e}); err != nil {
			t.Fatal(err)
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
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "*", "*", "*", ".*")); len(leftovers) != 0 {
		t.Fatalf("left %v", leftovers)
	}
}

func TestReviewEntriesStopAtTheLimitBetweenRefreshes(t *testing.T) {
	dir := t.TempDir()
	p := openTestPending(t, dir, "one")
	w := newWriter()
	for _, fp := range []string{fingerprintA, fingerprintB} {
		if err := p.writeReview(w, review{instructions: &InstructionsEntry{Proxy: "governed", Fingerprint: fp}}); err != nil {
			t.Fatal(err)
		}
	}
	// No refresh has counted the two entries; the writer counts them itself.
	if err := p.writeReview(w, review{tool: &ToolEntry{Proxy: "governed", Tool: "lookup", Fingerprint: fingerprintA, Definition: []byte(`{}`)}}); err != nil {
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
	p := openTestPending(t, dir, "../../gateway")
	if err := p.writeReview(newWriter(), review{tool: &ToolEntry{Proxy: "../..", Tool: "../../escape", Fingerprint: fingerprintA, Definition: []byte(`{}`)}}); err != nil {
		t.Fatal(err)
	}
	if err := p.writeDeclaration(newWriter(), declaration{proxy: "../..", tool: "../x", approved: true, declared: Declared{Fingerprint: fingerprintA}}); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 1 {
		t.Fatalf("wrote outside the directory: %v", entries)
	}
	if strings.ContainsAny(encodeName("../a/b"), "./") {
		t.Fatal("an encoded name contains a path separator or dot")
	}
}

func TestInvalidDeclarationsHoldCalls(t *testing.T) {
	for name, content := range map[string]string{
		"garbled":   `{`,
		"oversized": `{"fingerprint":"` + fingerprintA + `","pad":"` + strings.Repeat("x", maxDeclarationFile) + `"}`,
		"notahash":  `{"fingerprint":"nope"}`,
		"empty":     `{}`,
		"misnamed":  `{"fingerprint":"` + fingerprintA + `","seenAt":"2026-01-01T00:00:00Z","gateway":"two","upstream":"` + testUpstream + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			tool := filepath.Join(dir, encodeName("governed"), "latest", encodeName("lookup"))
			if err := os.MkdirAll(tool, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tool, name+".json"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			p := openTestPending(t, dir, "one")
			p.Refresh("v", every)
			if p.Current("v") {
				t.Fatal("declarations were current with an invalid file")
			}
		})
	}
}

func TestAGatewayReadsItsOwnDeclarationsOnlyForToolsWithoutRecords(t *testing.T) {
	dir := t.TempDir()
	p := openTestPending(t, dir, "one")
	if err := p.writeDeclaration(newWriter(), declare(fingerprintA, time.Now(), true)); err != nil {
		t.Fatal(err)
	}
	p.Refresh("v", every)
	// Its own records order its replies as received, and override its file.
	if _, d, ok := p.Lookup("v", "governed", "lookup", testUpstream, true); ok {
		t.Fatalf("read its own declaration over its records: %+v", d)
	}
	// Without records, as after a restart, its file still holds calls.
	if _, d, ok := p.Lookup("v", "governed", "lookup", testUpstream, false); !ok || d.Fingerprint != fingerprintA {
		t.Fatalf("a restarted gateway lost its own declaration: %+v, %v", d, ok)
	}
	other := openTestPending(t, dir, "two")
	other.Refresh("v", every)
	if d, ok := other.Latest("governed", "lookup", testUpstream); !ok || d.Fingerprint != fingerprintA {
		t.Fatalf("another gateway read %+v, %v", d, ok)
	}
}

func TestWithoutADirectoryNothingIsShared(t *testing.T) {
	p := openTestPending(t, "", "one")
	p.Changed("governed", "lookup", fingerprintA, []byte(`{}`))
	p.Saw("governed", testUpstream, "lookup", fingerprintA, true, time.Now())
	p.Refresh("v", every)
	if _, ok := p.Latest("governed", "lookup", testUpstream); ok {
		t.Fatal("a declaration was shared without a directory")
	}
}

func TestSightingsAreQueuedInOrderWithoutDropping(t *testing.T) {
	// No writer drains these queues, so what was offered stays in them.
	p := &Pending{declarations: make(chan declaration, 4), reviews: make(chan review, 4)}
	p.latest.Store(&sharedSnapshot{declared: map[string]Declared{declarationKey("governed", "lookup", testUpstream): {Fingerprint: fingerprintB}}})
	// Even a sighting that matches the shared copy is queued, so a change
	// queued before it cannot be the last word.
	p.Saw("governed", testUpstream, "lookup", fingerprintA, true, time.Now())
	p.Saw("governed", testUpstream, "lookup", fingerprintB, true, time.Now())
	if len(p.declarations) != 2 {
		t.Fatalf("queued %d sightings", len(p.declarations))
	}
}

func TestReviewEntriesAlreadyWrittenAreNotQueuedAgain(t *testing.T) {
	p := &Pending{reviews: make(chan review, 4), limits: Limits{MaxDefinitionBytes: 1 << 10}, now: time.Now}
	written := map[string]bool{reviewKey("governed", "lookup", fingerprintA): true}
	p.reviewed.Store(&written)
	p.Changed("governed", "lookup", fingerprintA, []byte(`{}`))
	if len(p.reviews) != 0 {
		t.Fatal("an entry already written was queued")
	}
	p.Changed("governed", "lookup", fingerprintB, []byte(`{}`))
	if len(p.reviews) != 1 {
		t.Fatal("a new entry was not queued")
	}
}

func TestAFailedReadKeepsThePreviousDeclarations(t *testing.T) {
	dir := t.TempDir()
	reader := openTestPending(t, dir, "reader")
	p := openTestPending(t, dir, "one")
	if err := p.writeDeclaration(newWriter(), declare(fingerprintA, time.Now(), true)); err != nil {
		t.Fatal(err)
	}
	reader.Refresh("v1", every)
	// A directory where a declaration file should be cannot be read, even
	// by the superuser the tests may run as.
	if err := os.Mkdir(filepath.Join(dir, encodeName("governed"), "latest", encodeName("lookup"), "unreadable.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	reader.Refresh("v2", every)
	if _, ok := reader.Latest("governed", "lookup", testUpstream); !ok || reader.Current("v2") || reader.Current("v1") {
		t.Fatal("a failed read dropped a declaration or left them current")
	}
}

func TestDeclarationsAreCurrentOnlyForTheSetTheyWereReadFor(t *testing.T) {
	p := openTestPending(t, t.TempDir(), "one")
	p.Refresh("v1", every)
	if !p.Current("v1") || p.Current("v2") {
		t.Fatal("declarations were not tied to the set they were read for")
	}
	if !openTestPending(t, "", "one").Current("anything") {
		t.Fatal("without a directory, declarations must never hold calls back")
	}
}

func TestADirectoryThatCannotOpenHoldsCallsUntilItDoes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "later")
	p := openTestPending(t, dir, "one")
	p.Refresh("v1", every)
	if p.Current("v1") {
		t.Fatal("declarations were current without the directory")
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p.Refresh("v1", every)
	if !p.Current("v1") {
		t.Fatal("the directory was not opened once it existed")
	}
}

func TestAGatewayKeepsWhatEachUpstreamDeclared(t *testing.T) {
	dir := t.TempDir()
	reader := openTestPending(t, dir, "reader")
	p := openTestPending(t, dir, "one")
	w := newWriter()
	start := time.Now()
	if err := p.writeDeclaration(w, declare(fingerprintA, start, true)); err != nil {
		t.Fatal(err)
	}
	moved := declare(fingerprintB, start.Add(time.Minute), true)
	moved.declared.Upstream = "https://new.example/mcp"
	if err := p.writeDeclaration(w, moved); err != nil {
		t.Fatal(err)
	}
	reader.Refresh("v", every)
	if d, ok := reader.Latest("governed", "lookup", testUpstream); !ok || d.Fingerprint != fingerprintA {
		t.Fatalf("lost what the first upstream declared: %+v", d)
	}
}

func TestTooManyDeclarationFilesHoldCalls(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, encodeName("governed"), "latest", encodeName("lookup"))
	if err := os.MkdirAll(tool, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range maxGatewaysPerTool + 1 {
		data := `{"fingerprint":"` + fingerprintA + `","seenAt":"2026-01-01T00:00:00Z","upstream":"` + testUpstream + `"}`
		if err := os.WriteFile(filepath.Join(tool, fmt.Sprintf("g%d.json", i)), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := openTestPending(t, dir, "one")
	p.Refresh("v", every)
	if p.Current("v") {
		t.Fatal("declarations read in part were current")
	}
}

func TestALateSightingFromOneUpstreamIsWrittenAfterAnotherUpstreams(t *testing.T) {
	dir := t.TempDir()
	reader := openTestPending(t, dir, "reader")
	p := openTestPending(t, dir, "one")
	w := newWriter()
	start := time.Now()
	if err := p.writeDeclaration(w, declare(fingerprintA, start, true)); err != nil {
		t.Fatal(err)
	}
	// While the proxy moves between upstreams, a newer reply from the other
	// one is written before a delayed reply from the reviewed one.
	other := declare(fingerprintA, start.Add(time.Minute), true)
	other.declared.Upstream = "https://new.example/mcp"
	if err := p.writeDeclaration(w, other); err != nil {
		t.Fatal(err)
	}
	if err := p.writeDeclaration(w, declare(fingerprintB, start.Add(time.Second), true)); err != nil {
		t.Fatal(err)
	}
	reader.Refresh("v", every)
	if d, _ := reader.Latest("governed", "lookup", testUpstream); d.Fingerprint != fingerprintB {
		t.Fatalf("the reviewed upstream's change was not shared: %+v", d)
	}
}

func TestCallsToToolsThatCannotBeSharedAreHeld(t *testing.T) {
	p := openTestPending(t, t.TempDir(), "one")
	p.Refresh("v", every)
	if current, _, _ := p.Lookup("v", "governed", "lookup", testUpstream, false); !current {
		t.Fatal("an ordinary tool was not current")
	}
	if current, _, _ := p.Lookup("v", "governed", strings.Repeat("x", maxSharedName+1), testUpstream, false); current {
		t.Fatal("a tool whose name cannot be shared was current")
	}
	if current, _, _ := p.Lookup("v", "governed", "lookup", testUpstream+strings.Repeat("x", maxSharedUpstream), false); current {
		t.Fatal("a tool on an upstream whose URL cannot be shared was current")
	}
	if !OpenPending("", "one", Limits{}).Current("v") {
		t.Fatal("without sharing, declarations were not current")
	}
}
