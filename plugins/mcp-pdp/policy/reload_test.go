package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// publishRaw stores a set without validating it and points active at it, as a
// gateway would see after a pointer edit or a validation change.
func publishRaw(t *testing.T, store, rules, previous string) string {
	t.Helper()
	contents := map[string][]byte{"rules.cedar": []byte(rules), "approved_tools.json": []byte("{}"),
		"approved_instructions.json": []byte("{}"), "checks.json": []byte("[]")}
	hashes := hashFiles(Files, contents)
	set := Fingerprint(FormatVersion, hashes)
	s, err := openStore(store)
	if err != nil {
		t.Fatal(err)
	}
	defer s.unlock()
	if err := s.writeSet(set, Manifest{Format: FormatVersion, Files: hashes}, contents); err != nil {
		t.Fatal(err)
	}
	pointTo(t, store, Pointer{Set: set, Previous: previous})
	return set
}

func pointTo(t *testing.T, store string, pointer Pointer) {
	t.Helper()
	data, _ := json.Marshal(pointer)
	if err := writeAtomically(filepath.Join(store, pointerFile), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readStatus(t *testing.T, path string) Status {
	t.Helper()
	var status Status
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestReloaderKeepsTheLastGoodSetWhenACandidateIsRejected(t *testing.T) {
	store, statusFile := t.TempDir(), filepath.Join(t.TempDir(), "status.json")
	good, err := Promote(store, writeSource(t, permitAll, "{}", "[]"), "good", epoch)
	if err != nil {
		t.Fatal(err)
	}
	var active atomic.Pointer[Snapshot]
	r := NewReloader(store, statusFile, &active)
	r.Load()
	if status := readStatus(t, statusFile); status.Enforcing != good || status.Outcome != "activated" || status.EnforcingLabel != "good" {
		t.Fatalf("status %+v", status)
	}
	bad := publishRaw(t, store, "invalid", good)
	r.Load()
	if status := readStatus(t, statusFile); status.Enforcing != good || status.Active != bad || status.Outcome != "rejected" {
		t.Fatalf("status %+v", status)
	}
}

func TestReloaderDeniesAfterARestartWhenTheActiveSetIsRejected(t *testing.T) {
	store, statusFile := t.TempDir(), filepath.Join(t.TempDir(), "status.json")
	good, err := Promote(store, writeSource(t, permitAll, "{}", "[]"), "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	var first atomic.Pointer[Snapshot]
	NewReloader(store, statusFile, &first).Load()
	// A pointer edited to name a set this gateway rejects fails closed after
	// a restart. The previous set is not restored, because it could grant
	// access a later set revoked.
	bad := publishRaw(t, store, "invalid", good)
	var restarted atomic.Pointer[Snapshot]
	NewReloader(store, statusFile, &restarted).Load()
	if snapshot := restarted.Load(); snapshot != nil {
		t.Fatalf("restart enforced %s", snapshot.Version)
	}
	if status := readStatus(t, statusFile); status.Enforcing != "" || status.Active != bad || status.Outcome != "rejected" {
		t.Fatalf("status %+v", status)
	}
}

func TestReloaderReportsARollbackFromAnIncompleteSet(t *testing.T) {
	store, statusFile := t.TempDir(), filepath.Join(t.TempDir(), "status.json")
	good, err := Promote(store, writeSource(t, permitAll, "{}", "[]"), "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	var active atomic.Pointer[Snapshot]
	r := NewReloader(store, statusFile, &active)
	r.Load()
	incomplete := publishRaw(t, store, "", good)
	if err := os.Remove(filepath.Join(store, setsDir, incomplete, "rules.cedar")); err != nil {
		t.Fatal(err)
	}
	r.Load()
	if status := readStatus(t, statusFile); status.Outcome != "not_ready" || status.Active != incomplete {
		t.Fatalf("status %+v", status)
	}
	pointTo(t, store, Pointer{Set: good})
	r.Load()
	if status := readStatus(t, statusFile); status.Outcome != "activated" || status.Active != good {
		t.Fatalf("status after rollback %+v", status)
	}
}

func TestReloaderRetriesAFailedStatusWrite(t *testing.T) {
	store := t.TempDir()
	statusFile := filepath.Join(t.TempDir(), "missing", "status.json")
	if _, err := Promote(store, writeSource(t, permitAll, "{}", "[]"), "", epoch); err != nil {
		t.Fatal(err)
	}
	var active atomic.Pointer[Snapshot]
	r := NewReloader(store, statusFile, &active)
	r.Load()
	if err := os.MkdirAll(filepath.Dir(statusFile), 0o755); err != nil {
		t.Fatal(err)
	}
	r.Load()
	if status := readStatus(t, statusFile); status.Outcome != "activated" {
		t.Fatalf("status %+v", status)
	}
}

func TestActivateReplacesAnUnreadablePointer(t *testing.T) {
	store := t.TempDir()
	set, err := Promote(store, writeSource(t, "", "{}", "[]"), "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, pointerFile), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Activate(store, set, epoch); err != nil {
		t.Fatal(err)
	}
	if pointer, err := ReadPointer(store); err != nil || pointer.Set != set || pointer.Previous != "" {
		t.Fatalf("pointer %+v, %v", pointer, err)
	}
}
