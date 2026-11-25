package policy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
)

// A policy store holds immutable policy sets under sets/<fingerprint>/ and an
// active pointer file naming the set gateways enforce. A set contains its
// policy files and a manifest of their hashes. Its fingerprint is derived
// from those hashes, so the name proves which content it holds.
const (
	setsDir      = "sets"
	lockFile     = ".lock"
	pointerFile  = "active"
	manifestFile = "manifest.json"
	// FormatVersion is the set layout Promote writes. Gateways also load
	// format 1, which predates approved instructions.
	FormatVersion = 2
	legacyFormat  = 1
)

// Files lists the files of a format-2 policy set in fingerprint order.
var Files = []string{"rules.cedar", "approved_tools.json", "approved_instructions.json", "checks.json"}

// legacyFiles lists the files of a format-1 policy set in fingerprint order.
var legacyFiles = []string{"rules.cedar", "tools.json", "checks.json"}

// filesFor returns the files a set of the given format contains.
func filesFor(format int) ([]string, bool) {
	switch format {
	case FormatVersion:
		return Files, true
	case legacyFormat:
		return legacyFiles, true
	}
	return nil, false
}

// Inputs are a set's policy files in the roles Compile reads them. Format is
// the set's format; zero means the current one. Instructions is nil for a
// format-1 set, which has no approved instructions.
type Inputs struct {
	Rules, Tools, Instructions, Checks []byte
	Format                             int
}

// InputsOf maps a set's files to their roles according to its format.
func InputsOf(format int, contents map[string][]byte) Inputs {
	if format == legacyFormat {
		return Inputs{Rules: contents["rules.cedar"], Tools: contents["tools.json"], Checks: contents["checks.json"], Format: legacyFormat}
	}
	return Inputs{Rules: contents["rules.cedar"], Tools: contents["approved_tools.json"],
		Instructions: contents["approved_instructions.json"], Checks: contents["checks.json"]}
}

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Manifest records the content a policy set was published with.
type Manifest struct {
	Format int               `json:"format"`
	Label  string            `json:"label,omitempty"`
	Files  map[string]string `json:"files"`
}

// Pointer names the active policy set and the set it replaced. A set's label
// lives in its manifest and is fixed when the set is first published.
type Pointer struct {
	Set        string `json:"set"`
	Previous   string `json:"previous,omitempty"`
	PromotedAt string `json:"promotedAt,omitempty"`
}

// NotReadyError reports a set whose files do not yet match its manifest, as
// while it is still being published. It is not a rejection.
type NotReadyError struct{ Reason string }

func (e *NotReadyError) Error() string { return "policy set not ready: " + e.Reason }

// Fingerprint derives a set's identity from the SHA-256 hashes of the files
// its format contains. Format-1 sets keep the names they were published with.
func Fingerprint(format int, hashes map[string]string) string {
	files, _ := filesFor(format)
	sum := sha256.New()
	for _, name := range files {
		fmt.Fprintf(sum, "%s\n%s\n", name, hashes[name])
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func hashFiles(files []string, contents map[string][]byte) map[string]string {
	hashes := make(map[string]string, len(files))
	for _, name := range files {
		sum := sha256.Sum256(contents[name])
		hashes[name] = hex.EncodeToString(sum[:])
	}
	return hashes
}

// ReadPointer reads the active pointer of the store at root.
func ReadPointer(root string) (Pointer, error) {
	var p Pointer
	data, err := os.ReadFile(filepath.Join(root, pointerFile))
	if err != nil {
		return p, err
	}
	if err := jsonv2.Unmarshal(data, &p, jsonv2.RejectUnknownMembers(true)); err != nil {
		return p, fmt.Errorf("invalid active pointer: %w", err)
	}
	if !fingerprintPattern.MatchString(p.Set) {
		return p, fmt.Errorf("active pointer names an invalid set %q", p.Set)
	}
	return p, nil
}

// ReadSet returns a set's manifest and files after verifying that the files
// match the manifest and the set name. It is the single definition of an
// intact set, used both by gateways loading a set and by publishers deciding
// whether an existing set can be reused. A mismatch returns a NotReadyError.
func ReadSet(root, set string) (Manifest, map[string][]byte, error) {
	if !fingerprintPattern.MatchString(set) {
		return Manifest{}, nil, fmt.Errorf("invalid set name %q", set)
	}
	dir := filepath.Join(root, setsDir, set)
	manifest, err := readManifest(dir)
	if err != nil {
		return manifest, nil, &NotReadyError{Reason: err.Error()}
	}
	// An unexpected format, including a manifest still missing its fields, is
	// retried rather than cached as a rejection.
	files, known := filesFor(manifest.Format)
	if !known {
		return manifest, nil, &NotReadyError{Reason: fmt.Sprintf("unsupported policy set format %d", manifest.Format)}
	}
	contents := make(map[string][]byte, len(files))
	for _, name := range files {
		if contents[name], err = os.ReadFile(filepath.Join(dir, name)); err != nil {
			return manifest, nil, &NotReadyError{Reason: err.Error()}
		}
	}
	hashes := hashFiles(files, contents)
	for _, name := range files {
		if manifest.Files[name] != hashes[name] {
			return manifest, nil, &NotReadyError{Reason: name + " does not match the manifest"}
		}
	}
	if Fingerprint(manifest.Format, hashes) != set {
		return manifest, nil, &NotReadyError{Reason: "content does not match the set name"}
	}
	return manifest, contents, nil
}

func readManifest(dir string) (Manifest, error) {
	var manifest Manifest
	data, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		return manifest, err
	}
	if err := jsonv2.Unmarshal(data, &manifest, jsonv2.RejectUnknownMembers(true)); err != nil {
		return manifest, fmt.Errorf("unreadable manifest: %w", err)
	}
	return manifest, nil
}

// LoadSet verifies a set with ReadSet, then validates it. A validation failure
// returns the validation error.
func LoadSet(root, set string) (*Snapshot, Manifest, error) {
	manifest, contents, err := ReadSet(root, set)
	if err != nil {
		return nil, manifest, err
	}
	snapshot, err := Compile(InputsOf(manifest.Format, contents), set)
	if err != nil {
		return nil, manifest, err
	}
	snapshot.Label = manifest.Label
	return snapshot, manifest, nil
}

// Promote validates the policy files in source, stores them as an immutable
// format-2 set, and makes it active. A file that fails validation leaves the
// store's active pointer unchanged. Publishing content that already exists
// keeps the label it was first published with.
func Promote(root, source, label string, now func() time.Time) (string, error) {
	contents, err := readSource(source)
	if err != nil {
		return "", err
	}
	hashes := hashFiles(Files, contents)
	set := Fingerprint(FormatVersion, hashes)
	if _, err := Compile(InputsOf(FormatVersion, contents), set); err != nil {
		return "", fmt.Errorf("policy set rejected: %w", err)
	}
	store, err := openStore(root)
	if err != nil {
		return "", err
	}
	defer store.unlock()
	if err := store.writeSet(set, Manifest{Format: FormatVersion, Label: label, Files: hashes}, contents); err != nil {
		return "", err
	}
	return set, store.activate(set, now)
}

// Locked calls fn with the active set's name and compiled form while holding
// the store's lock, so no set becomes active while fn runs.
func Locked(root string, fn func(set string, active *Snapshot) error) error {
	store, err := openStore(root)
	if err != nil {
		return err
	}
	defer store.unlock()
	pointer, err := ReadPointer(root)
	if err != nil {
		return err
	}
	active, _, err := LoadSet(root, pointer.Set)
	if err != nil {
		return fmt.Errorf("active policy set %s: %w", pointer.Set, err)
	}
	return fn(pointer.Set, active)
}

// Revise changes the active set and makes the result active, all under the
// store's lock, so a publish made meanwhile is never overwritten unseen.
// change receives the active set's name, its compiled form, and its files
// laid out as format 2, which it edits in place, and returns the decisions it
// made; an error from change leaves the store unchanged. The result is
// validated like any promoted set. Once it is active, the decisions are
// appended to the decision log with the actor, the time, and both sets.
func Revise(root, label string, actor Actor, now func() time.Time, change func(set string, active *Snapshot, files map[string][]byte) ([]LogEntry, error)) (string, error) {
	store, err := openStore(root)
	if err != nil {
		return "", err
	}
	defer store.unlock()
	pointer, err := ReadPointer(root)
	if err != nil {
		return "", err
	}
	manifest, contents, err := ReadSet(root, pointer.Set)
	if err != nil {
		return "", fmt.Errorf("active policy set %s: %w", pointer.Set, err)
	}
	active, err := Compile(InputsOf(manifest.Format, contents), pointer.Set)
	if err != nil {
		return "", fmt.Errorf("active policy set %s: %w", pointer.Set, err)
	}
	files := contents
	if manifest.Format == legacyFormat {
		files = map[string][]byte{"rules.cedar": contents["rules.cedar"], "approved_tools.json": contents["tools.json"],
			"approved_instructions.json": []byte("{}\n"), "checks.json": contents["checks.json"]}
	}
	entries, err := change(pointer.Set, active, files)
	if err != nil {
		return "", err
	}
	hashes := hashFiles(Files, files)
	set := Fingerprint(FormatVersion, hashes)
	if _, err := Compile(InputsOf(FormatVersion, files), set); err != nil {
		return "", fmt.Errorf("policy set rejected: %w", err)
	}
	if err := store.writeSet(set, Manifest{Format: FormatVersion, Label: label, Files: hashes}, files); err != nil {
		return "", err
	}
	if err := store.activate(set, now); err != nil {
		return "", err
	}
	at := now().UTC().Format(time.RFC3339Nano)
	for i := range entries {
		entries[i].Time, entries[i].Actor, entries[i].Base, entries[i].Set, entries[i].Label = at, actor, pointer.Set, set, label
	}
	if err := store.appendLog(entries); err != nil {
		return set, fmt.Errorf("set %s is active, but the decision log could not be written: %w", set, err)
	}
	return set, nil
}

// readSource reads policy files laid out as either format and returns them
// as format-2 files. A format-1 directory has tools.json and no approved
// instructions; approved_instructions.json is optional and defaults to none.
// Presence is decided by name, so a broken link counts as present and fails
// to read rather than being silently skipped.
func readSource(source string) (map[string][]byte, error) {
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(source, name)) }
	// Only "does not exist" means absent; any other lookup failure stops the
	// publish rather than dropping a file the operator provided.
	present := map[string]bool{}
	for _, name := range []string{"approved_tools.json", "tools.json", "approved_instructions.json"} {
		_, err := os.Lstat(filepath.Join(source, name))
		switch {
		case err == nil:
			present[name] = true
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}
	toolsFile := "approved_tools.json"
	switch {
	case present["approved_tools.json"] && present["tools.json"]:
		return nil, errors.New("source has both tools.json and approved_tools.json; keep only approved_tools.json")
	case present["tools.json"]:
		toolsFile = "tools.json"
	}
	contents := map[string][]byte{}
	var err error
	for name, from := range map[string]string{"rules.cedar": "rules.cedar", "approved_tools.json": toolsFile, "checks.json": "checks.json"} {
		if contents[name], err = read(from); err != nil {
			return nil, err
		}
	}
	contents["approved_instructions.json"] = []byte("{}\n")
	if present["approved_instructions.json"] {
		if contents["approved_instructions.json"], err = read("approved_instructions.json"); err != nil {
			return nil, err
		}
	}
	return contents, nil
}

// Activate makes an existing set active after validating it again, for example
// to roll back to the set a pointer records as previous.
func Activate(root, set string, now func() time.Time) error {
	store, err := openStore(root)
	if err != nil {
		return err
	}
	defer store.unlock()
	return store.activate(set, now)
}

// store is a policy store held under its exclusive lock. Every change to a
// store happens under that lock, so concurrent publishers cannot interleave.
// The operator chooses the store root's permissions; everything published
// inside inherits them, so neither a publisher's umask nor this code widens
// or narrows who can read the policy. A new store root gets 0755.
//
// Several members of one group can share a store whose root is group-writable
// and has the setgid bit: published directories keep the bit, so new sets
// keep the store's group, and a publisher changes the mode only of what it
// created, since only an owner may.
type store struct {
	root string
	// dir confines every change to the store: names are resolved inside it
	// and never through a link that leads outside, so no member of a shared
	// store can redirect another publisher's writes to files elsewhere.
	dir      *os.Root
	dirMode  os.FileMode
	fileMode os.FileMode
	unlock   func()
}

func openStore(root string) (*store, error) {
	root = filepath.Clean(root)
	if err := createDir(root, 0o755); err != nil {
		return nil, err
	}
	// The root's own entry is synced on every publish, so a publish that
	// follows a failed or concurrent creation cannot report success before
	// the new store is durable. A parent the publisher may search but not
	// read is the operator's to make durable.
	if err := syncDir(filepath.Dir(root)); err != nil && !errors.Is(err, os.ErrPermission) {
		return nil, err
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	info, err := dir.Stat(".")
	if err != nil {
		dir.Close()
		return nil, err
	}
	s := &store{
		root:     root,
		dir:      dir,
		dirMode:  info.Mode().Perm() | info.Mode()&os.ModeSetgid,
		fileMode: info.Mode().Perm() &^ 0o111,
	}
	unlock, err := s.lock()
	if err != nil {
		dir.Close()
		return nil, err
	}
	s.unlock = func() {
		unlock()
		dir.Close()
	}
	return s, nil
}

// createDir creates dir and any missing parents, with dir given the mode
// whatever the umask, by renaming a prepared directory into place, so no one
// sees it with a mode the umask chose. An existing dir is left as it is. It
// creates the store root itself, outside any store.
func createDir(dir string, mode os.FileMode) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if err := makeParents(parent); err != nil {
		return err
	}
	prepared, err := os.MkdirTemp(parent, "."+filepath.Base(dir)+"-new-")
	if err != nil {
		return err
	}
	defer os.Remove(prepared)
	// The mode is changed through a descriptor that refuses a link, so if
	// someone else can write to the parent, they cannot redirect it.
	handle, err := os.OpenFile(prepared, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	err = handle.Chmod(mode)
	if closeErr := handle.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := renameNew(os.Rename(prepared, dir)); err != nil {
		return err
	}
	return syncDir(parent)
}

// makeParents creates dir and any missing parents, following the umask as
// mkdir -p does, and syncs the parent of each directory it creates, so a
// crash cannot lose them.
func makeParents(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := makeParents(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0o755); errors.Is(err, os.ErrExist) {
		return nil
	} else if err != nil {
		return err
	}
	return syncDir(parent)
}

// renameNew accepts a failed rename of a new, empty directory onto one
// another publisher created at the same moment: both are new and empty, so
// either one serves.
func renameNew(err error) error {
	if err != nil && !errors.Is(err, os.ErrExist) && !errors.Is(err, syscall.ENOTEMPTY) {
		return err
	}
	return nil
}

// tempName returns an unpredictable name for a file or directory being
// prepared in the store.
func tempName(prefix string) string {
	var random [8]byte
	rand.Read(random[:])
	return prefix + hex.EncodeToString(random[:])
}

// makeDir creates a directory in the store with the given mode by renaming a
// prepared directory into place, so no one, including a publisher after a
// crash, sees it with a mode the umask chose, then syncs its parent. An
// existing directory is left as it is, since only its owner may change it.
func (s *store) makeDir(name string, mode os.FileMode) error {
	if info, err := s.dir.Lstat(name); err == nil {
		// A link in its place could lead outside the store, where sets would
		// be read and published but never stored.
		if !info.IsDir() {
			return fmt.Errorf("%s in the policy store is not a directory", name)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	prepared := filepath.Join(filepath.Dir(name), tempName("."+filepath.Base(name)+"-new-"))
	if err := s.dir.Mkdir(prepared, 0o700); err != nil {
		return err
	}
	defer s.dir.Remove(prepared)
	if err := s.dir.Chmod(prepared, mode); err != nil {
		return err
	}
	if err := renameNew(s.dir.Rename(prepared, name)); err != nil {
		return err
	}
	return s.sync(filepath.Dir(name))
}

// sync makes a store directory's entries durable.
func (s *store) sync(name string) error { return syncDir(filepath.Join(s.root, name)) }

// writeFile creates a new file in the store, never opening an existing one,
// writes it, gives it the mode whatever the umask, and syncs it.
func (s *store) writeFile(name string, data []byte, mode os.FileMode) error {
	file, err := s.dir.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// activate validates a set and points active at it. The promotion time is
// read under the lock, so it orders switches the same way previous does.
func (s *store) activate(set string, now func() time.Time) error {
	if _, _, err := LoadSet(s.root, set); err != nil {
		return fmt.Errorf("policy set %s cannot be activated: %w", set, err)
	}
	pointer := Pointer{Set: set, PromotedAt: now().UTC().Format(time.RFC3339Nano)}
	// An unreadable pointer names no set to record as previous; replacing it is
	// how an operator repairs a corrupted pointer.
	if current, err := ReadPointer(s.root); err == nil {
		if current.Set == set {
			pointer.Previous = current.Previous
		} else {
			pointer.Previous = current.Set
		}
	}
	data, err := json.MarshalIndent(pointer, "", "  ")
	if err != nil {
		return err
	}
	// The pointer is replaced by renaming a completed, synced file over it.
	prepared := tempName("." + pointerFile + "-")
	defer s.dir.Remove(prepared)
	if err := s.writeFile(prepared, append(data, '\n'), s.fileMode); err != nil {
		return err
	}
	if err := s.dir.Rename(prepared, pointerFile); err != nil {
		return err
	}
	return s.sync(".")
}

// lock takes an exclusive lock on the store, released when the returned
// function is called or the process exits. The lock file is linked into
// place already carrying the store's file mode, so no publisher ever sees it
// with the creator's umask; if another publisher links one first, theirs is
// kept.
func (s *store) lock() (func(), error) {
	if _, err := s.dir.Lstat(lockFile); errors.Is(err, os.ErrNotExist) {
		prepared := tempName(".lock-new-")
		err := s.writeFile(prepared, nil, s.fileMode)
		if err == nil {
			err = s.dir.Link(prepared, lockFile)
		}
		s.dir.Remove(prepared)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	// Some file systems, such as NFS, grant an exclusive lock only on a
	// writable descriptor; a member with only read access can still lock on
	// a local file system.
	file, err := s.dir.OpenFile(lockFile, os.O_RDWR, 0)
	if errors.Is(err, os.ErrPermission) {
		file, err = s.dir.Open(lockFile)
	}
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
	}, nil
}

// writeSet stores a set by renaming a completed temporary directory into
// place, so readers never see a partial set. An intact set with the same
// fingerprint is reused. A damaged one is replaced, keeping the label it was
// first published with; because writeSet runs under the store lock, a set
// another publisher is writing can never be mistaken for a damaged one. The
// damaged set is deleted only once its replacement is durable; if no
// replacement is in place it is put back, and otherwise it is left beside
// the replacement, so its readable files and label are kept. The sets
// directory is synced on every path so a reused or new set survives a crash
// before the pointer names it.
func (s *store) writeSet(set string, manifest Manifest, contents map[string][]byte) (err error) {
	if err := s.makeDir(setsDir, s.dirMode); err != nil {
		return err
	}
	final := filepath.Join(setsDir, set)
	if _, _, readErr := ReadSet(s.root, set); readErr == nil {
		return s.sync(setsDir)
	}
	if _, statErr := s.dir.Lstat(final); statErr == nil {
		if previous, readErr := readManifest(filepath.Join(s.root, final)); readErr == nil {
			manifest.Label = previous.Label
		}
		damaged := filepath.Join(setsDir, fmt.Sprintf(".damaged-%s-%d", set, time.Now().UnixNano()))
		if err := s.dir.Rename(final, damaged); err != nil {
			return err
		}
		defer func() {
			if err == nil {
				s.dir.RemoveAll(damaged)
				return
			}
			if _, statErr := s.dir.Lstat(final); statErr == nil {
				return
			}
			if restoreErr := s.dir.Rename(damaged, final); restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("damaged set left at %s: %w", damaged, restoreErr))
			}
		}()
	}
	// Until the set is complete only the publisher may change the staging
	// directory, so no other member can place entries among the files being
	// written. This mode is set explicitly, so a umask that removes the
	// publisher's own search permission does not matter.
	staging := filepath.Join(setsDir, tempName(".staging-"))
	if err := s.dir.Mkdir(staging, 0o700); err != nil {
		return err
	}
	defer s.dir.RemoveAll(staging)
	if err := s.dir.Chmod(staging, 0o700|s.dirMode&os.ModeSetgid); err != nil {
		return err
	}
	files, _ := filesFor(manifest.Format)
	for _, name := range files {
		if err := s.writeFile(filepath.Join(staging, name), contents[name], s.fileMode); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := s.writeFile(filepath.Join(staging, manifestFile), append(data, '\n'), s.fileMode); err != nil {
		return err
	}
	if err := s.dir.Chmod(staging, s.dirMode); err != nil {
		return err
	}
	if err := s.sync(staging); err != nil {
		return err
	}
	if err := renameSet(s.dir, staging, final); err != nil {
		return err
	}
	return s.sync(setsDir)
}

// renameSet moves a completed set into place. Tests replace it to exercise a
// failed replacement.
var renameSet = (*os.Root).Rename

// syncDir makes a directory's entries durable. Tests replace it to observe
// which directories are synced.
var syncDir = syncDirectory

func syncDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = handle.Sync()
	if closeErr := handle.Close(); err == nil {
		err = closeErr
	}
	return err
}

// writeAtomically replaces path by renaming a completed, synced file over it
// and syncing its directory, so the replacement survives a crash.
func writeAtomically(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
