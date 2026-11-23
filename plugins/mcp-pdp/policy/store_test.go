package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSource(t *testing.T, rules, tools, checks string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range map[string]string{"rules.cedar": rules, "tools.json": tools, "checks.json": checks} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const permitAll = `permit (principal, action, resource);`

func TestPromoteActivatesAValidSetAndRecordsThePrevious(t *testing.T) {
	store := t.TempDir()
	now := time.Unix(0, 0)
	first, err := Promote(store, writeSource(t, "", "{}", "[]"), "empty", now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Promote(store, writeSource(t, permitAll, "{}", "[]"), "open", now)
	if err != nil {
		t.Fatal(err)
	}
	pointer, err := ReadPointer(store)
	if err != nil {
		t.Fatal(err)
	}
	if pointer.Set != second || pointer.Previous != first || pointer.Label != "open" {
		t.Fatalf("unexpected pointer %+v", pointer)
	}
	snapshot, manifest, err := LoadSet(store, second)
	if err != nil || snapshot.Version != second || manifest.Label != "open" {
		t.Fatalf("LoadSet = %v, %+v, %v", snapshot, manifest, err)
	}
	if err := Activate(store, first, "rollback", now); err != nil {
		t.Fatal(err)
	}
	if pointer, _ = ReadPointer(store); pointer.Set != first || pointer.Previous != second {
		t.Fatalf("rollback pointer %+v", pointer)
	}
}

func TestPromoteRejectsAnInvalidSetWithoutMovingThePointer(t *testing.T) {
	store := t.TempDir()
	good, err := Promote(store, writeSource(t, "", "{}", "[]"), "", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"rules":  writeSource(t, "invalid", "{}", "[]"),
		"tools":  writeSource(t, "", `{"proxy": null}`, "[]"),
		"checks": writeSource(t, "", "{}", "null"),
	} {
		if _, err := Promote(store, source, "", time.Unix(0, 0)); err == nil {
			t.Fatalf("%s: invalid set was promoted", name)
		}
	}
	if pointer, _ := ReadPointer(store); pointer.Set != good {
		t.Fatalf("pointer moved to %s", pointer.Set)
	}
}

func TestLoadSetReportsATamperedSetAsNotReady(t *testing.T) {
	store := t.TempDir()
	set, err := Promote(store, writeSource(t, "", "{}", "[]"), "", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(store, setsDir, set, "rules.cedar")
	if err := os.Chmod(rules, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rules, []byte(permitAll), 0o644); err != nil {
		t.Fatal(err)
	}
	var notReady *NotReadyError
	if _, _, err := LoadSet(store, set); !errors.As(err, &notReady) {
		t.Fatalf("tampered set: %v", err)
	}
	if err := Activate(store, set, "", time.Unix(0, 0)); err == nil {
		t.Fatal("a tampered set was activated")
	}
}

func TestReadPointerRejectsAnInvalidSetName(t *testing.T) {
	store := t.TempDir()
	if err := os.WriteFile(filepath.Join(store, pointerFile), []byte(`{"set": "../escape"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPointer(store); err == nil {
		t.Fatal("an invalid set name was accepted")
	}
}
