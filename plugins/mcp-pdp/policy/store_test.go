package policy

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeSource(t *testing.T, rules, tools, checks string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range map[string]string{"rules.cedar": rules, "approved_tools.json": tools, "checks.json": checks} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func epoch() time.Time { return time.Unix(0, 0) }

const permitAll = `permit (principal, action, resource);`

func TestPromoteActivatesAValidSetAndRecordsThePrevious(t *testing.T) {
	store := t.TempDir()
	now := epoch
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
	if pointer.Set != second || pointer.Previous != first {
		t.Fatalf("unexpected pointer %+v", pointer)
	}
	snapshot, manifest, err := LoadSet(store, second)
	if err != nil || snapshot.Version != second || manifest.Label != "open" {
		t.Fatalf("LoadSet = %v, %+v, %v", snapshot, manifest, err)
	}
	if err := Activate(store, first, now); err != nil {
		t.Fatal(err)
	}
	if pointer, _ = ReadPointer(store); pointer.Set != first || pointer.Previous != second {
		t.Fatalf("rollback pointer %+v", pointer)
	}
}

func TestPromoteRejectsAnInvalidSetWithoutMovingThePointer(t *testing.T) {
	store := t.TempDir()
	good, err := Promote(store, writeSource(t, "", "{}", "[]"), "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"rules":  writeSource(t, "invalid", "{}", "[]"),
		"tools":  writeSource(t, "", `{"proxy": null}`, "[]"),
		"checks": writeSource(t, "", "{}", "null"),
	} {
		if _, err := Promote(store, source, "", epoch); err == nil {
			t.Fatalf("%s: invalid set was promoted", name)
		}
	}
	if pointer, _ := ReadPointer(store); pointer.Set != good {
		t.Fatalf("pointer moved to %s", pointer.Set)
	}
}

func TestLoadSetReportsATamperedSetAsNotReady(t *testing.T) {
	store := t.TempDir()
	set, err := Promote(store, writeSource(t, "", "{}", "[]"), "", epoch)
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
	if err := Activate(store, set, epoch); err == nil {
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

func TestPromoteRepairsADamagedSet(t *testing.T) {
	store := t.TempDir()
	source := writeSource(t, permitAll, "{}", "[]")
	set, err := Promote(store, source, "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store, setsDir, set, "rules.cedar")); err != nil {
		t.Fatal(err)
	}
	if again, err := Promote(store, source, "", epoch); err != nil || again != set {
		t.Fatalf("re-promotion = %s, %v", again, err)
	}
	if _, _, err := LoadSet(store, set); err != nil {
		t.Fatalf("repaired set: %v", err)
	}
}

func TestPromoteWritesReadableFilesUnderARestrictiveUmask(t *testing.T) {
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)
	// The store does not exist yet, as when converting an older layout.
	store := filepath.Join(t.TempDir(), "store")
	set, err := Promote(store, writeSource(t, "", "{}", "[]"), "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		store,
		filepath.Join(store, setsDir),
		filepath.Join(store, setsDir, set),
		filepath.Join(store, setsDir, set, "rules.cedar"),
		filepath.Join(store, setsDir, set, manifestFile),
		filepath.Join(store, pointerFile),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o044 != 0o044 {
			t.Fatalf("%s is not readable by other users: %v", path, info.Mode())
		}
	}
}

func TestPromoteRepairsADamagedManifestAndKeepsTheFirstLabel(t *testing.T) {
	store := t.TempDir()
	source := writeSource(t, permitAll, "{}", "[]")
	set, err := Promote(store, source, "first", epoch)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(store, setsDir, set, manifestFile)
	if err := os.WriteFile(manifest, []byte(`{"format": 1, "label": "first", "files": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(store, source, "second", epoch); err != nil {
		t.Fatal(err)
	}
	_, repaired, err := LoadSet(store, set)
	if err != nil || repaired.Label != "first" {
		t.Fatalf("repaired set: %+v, %v", repaired, err)
	}
}

func TestPublishedFilesInheritARestrictedStoreRoot(t *testing.T) {
	store := t.TempDir()
	if err := os.Chmod(store, 0o750); err != nil {
		t.Fatal(err)
	}
	set, err := Promote(store, writeSource(t, "", "{}", "[]"), "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		store:                              0o750,
		filepath.Join(store, setsDir):      0o750,
		filepath.Join(store, setsDir, set): 0o750,
		filepath.Join(store, setsDir, set, "rules.cedar"): 0o640,
		filepath.Join(store, pointerFile):                 0o640,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s has mode %v, want %v", path, info.Mode().Perm(), want)
		}
	}
}

func TestAFailedRepairKeepsTheDamagedSet(t *testing.T) {
	store := t.TempDir()
	source := writeSource(t, permitAll, "{}", "[]")
	set, err := Promote(store, source, "first", epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store, setsDir, set, "rules.cedar")); err != nil {
		t.Fatal(err)
	}
	renameSet = func(*os.Root, string, string) error { return errors.New("injected failure") }
	defer func() { renameSet = (*os.Root).Rename }()
	if _, err := Promote(store, source, "", epoch); err == nil {
		t.Fatal("the replacement did not fail")
	}
	// The damaged set is back in place with its label and readable files.
	manifest, err := readManifest(filepath.Join(store, setsDir, set))
	if err != nil || manifest.Label != "first" {
		t.Fatalf("damaged set not restored: %+v, %v", manifest, err)
	}
	entries, err := os.ReadDir(filepath.Join(store, setsDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != set {
			t.Fatalf("left behind %s", e.Name())
		}
	}
}

func TestANewStoreIsSyncedIntoItsParent(t *testing.T) {
	parent := t.TempDir()
	store := filepath.Join(parent, "a", "store")
	var synced []string
	syncDir = func(dir string) error {
		synced = append(synced, dir)
		handle, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer handle.Close()
		return handle.Sync()
	}
	defer func() { syncDir = syncDirectory }()
	if _, err := Promote(store, writeSource(t, "", "{}", "[]"), "", epoch); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{parent, filepath.Join(parent, "a"), store} {
		if !slices.Contains(synced, want) {
			t.Fatalf("%s was not synced; synced %v", want, synced)
		}
	}
}

func TestASharedStoreKeepsItsGroupAndLock(t *testing.T) {
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)
	store := t.TempDir()
	if err := os.Chmod(store, 0o770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	set, err := Promote(store, writeSource(t, "", "{}", "[]"), "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(store, setsDir), filepath.Join(store, setsDir, set)} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSetgid == 0 || info.Mode().Perm() != 0o770 {
			t.Fatalf("%s has mode %v, want setgid and 0770", dir, info.Mode())
		}
	}
	info, err := os.Stat(filepath.Join(store, ".lock"))
	if err != nil || info.Mode().Perm() != 0o660 {
		t.Fatalf("lock file: %v, %v", info.Mode(), err)
	}
}

func TestAnExistingSetsDirectoryIsLeftAsItIs(t *testing.T) {
	// Another publisher created sets with its own mode; only its owner may
	// change that, so publishing must not try.
	store := t.TempDir()
	if err := os.Mkdir(filepath.Join(store, setsDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(store, setsDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(store, writeSource(t, "", "{}", "[]"), "", epoch); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(filepath.Join(store, setsDir)); info.Mode().Perm() != 0o700 {
		t.Fatalf("sets mode changed to %v", info.Mode().Perm())
	}
}

func TestPublishingNeverWritesOutsideTheStore(t *testing.T) {
	// A member of a shared store replaces sets with a link to a directory
	// elsewhere; another publisher must not write there.
	store, elsewhere := t.TempDir(), t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(store, setsDir)); err != nil {
		t.Fatal(err)
	}
	source := writeSource(t, "", "{}", "[]")
	if _, err := Promote(store, source, "", epoch); err == nil {
		t.Fatal("published through a link leading outside the store")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("wrote outside the store: %v", entries)
	}
	// Even a matching set outside the store is not reused and activated.
	real := t.TempDir()
	set, err := Promote(real, source, "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(real, setsDir, set), filepath.Join(elsewhere, set)); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(store, source, "", epoch); err == nil {
		t.Fatal("activated a set kept outside the store")
	}
	if _, err := ReadPointer(store); err == nil {
		t.Fatal("active names a set outside the store")
	}
}

func TestARepairThatMayNotBeDurableKeepsTheDamagedSet(t *testing.T) {
	store := t.TempDir()
	source := writeSource(t, permitAll, "{}", "[]")
	set, err := Promote(store, source, "first", epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store, setsDir, set, "rules.cedar")); err != nil {
		t.Fatal(err)
	}
	renamed := false
	renameSet = func(dir *os.Root, from, to string) error { renamed = true; return dir.Rename(from, to) }
	syncDir = func(dir string) error {
		if renamed && dir == filepath.Join(store, setsDir) {
			return errors.New("injected sync failure")
		}
		return syncDirectory(dir)
	}
	defer func() { renameSet, syncDir = (*os.Root).Rename, syncDirectory }()
	if _, err := Promote(store, source, "", epoch); err == nil {
		t.Fatal("the sync failure was not reported")
	}
	entries, err := os.ReadDir(filepath.Join(store, setsDir))
	if err != nil {
		t.Fatal(err)
	}
	var damaged int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".damaged-") {
			damaged++
		}
	}
	if damaged != 1 {
		t.Fatalf("damaged copies kept: %d", damaged)
	}
}

func TestReviseConvertsTheActiveSetAndLeavesTheStoreUnchangedOnError(t *testing.T) {
	store := t.TempDir()
	legacy := writeLegacySet(t, store)
	if err := Activate(store, legacy, epoch); err != nil {
		t.Fatal(err)
	}
	if _, err := Revise(store, "refused", Actor{Issuer: "local", Subject: "test"}, epoch, func(string, *Snapshot, map[string][]byte) ([]LogEntry, error) { return nil, errors.New("no") }); err == nil {
		t.Fatal("a failed change was published")
	}
	if pointer, _ := ReadPointer(store); pointer.Set != legacy {
		t.Fatalf("a failed change moved the pointer to %s", pointer.Set)
	}
	set, err := Revise(store, "revised", Actor{Issuer: "local", Subject: "test"}, epoch, func(base string, active *Snapshot, files map[string][]byte) ([]LogEntry, error) {
		if base != legacy || active.Version != legacy || files["approved_instructions.json"] == nil || files["tools.json"] != nil {
			t.Fatalf("change received base %s and files %v", base, slices.Collect(maps.Keys(files)))
		}
		files["approved_instructions.json"] = []byte(`{"governed":"Be brief."}`)
		return []LogEntry{{Action: "approve", Proxy: "governed", Instructions: true}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pointer, _ := ReadPointer(store)
	snapshot, manifest, err := LoadSet(store, set)
	if err != nil || pointer.Set != set || pointer.Previous != legacy || manifest.Format != FormatVersion || manifest.Label != "revised" {
		t.Fatalf("revised set %s: pointer %+v, manifest %+v, %v", set, pointer, manifest, err)
	}
	if text, _ := snapshot.Instructions("governed"); text != "Be brief." {
		t.Fatalf("instructions %q", text)
	}
	log, err := ReadLog(store)
	if err != nil || len(log) != 1 || log[0].Base != legacy || log[0].Set != set || log[0].Label != "revised" ||
		log[0].Actor.Subject != "test" || log[0].Time == "" {
		t.Fatalf("decision log %+v, %v", log, err)
	}
}

func TestTheDecisionLogKeepsTheStoresModeAndRecoversFromACutLine(t *testing.T) {
	store := t.TempDir()
	if err := os.Chmod(store, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(store, writeSource(t, permitAll, "{}", "[]"), "first", epoch); err != nil {
		t.Fatal(err)
	}
	// A publisher with a restrictive umask still creates the log with the
	// store's mode, so other members of a shared store can append to it.
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	revise := func(label string) {
		t.Helper()
		_, err := Revise(store, label, Actor{Issuer: "local", Subject: "test"}, epoch, func(_ string, _ *Snapshot, files map[string][]byte) ([]LogEntry, error) {
			files["approved_instructions.json"] = []byte(`{"governed":"` + label + `"}`)
			return []LogEntry{{Action: "approve", Proxy: "governed", Instructions: true}}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	revise("one")
	info, err := os.Stat(filepath.Join(store, logFile))
	if err != nil || info.Mode().Perm() != 0o660 {
		t.Fatalf("log mode %v, %v", info.Mode().Perm(), err)
	}
	// An earlier write cut short leaves a partial line; the next entry still
	// starts on its own line, and reading skips only the partial one.
	f, err := os.OpenFile(filepath.Join(store, logFile), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"time":"2026`)
	f.Close()
	revise("two")
	log, err := ReadLog(store)
	if err == nil || len(log) != 2 || log[0].Label != "one" || log[1].Label != "two" {
		t.Fatalf("log %+v, %v", log, err)
	}
}
