package policy

import (
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
// three policy files and a manifest of their hashes. Its fingerprint is
// derived from those hashes, so the name proves which content it holds.
const (
	setsDir      = "sets"
	pointerFile  = "active"
	manifestFile = "manifest.json"
	// FormatVersion identifies the manifest layout.
	FormatVersion = 1
)

// Files lists the files of a policy set in fingerprint order.
var Files = []string{"rules.cedar", "tools.json", "checks.json"}

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

// Fingerprint derives a set's identity from the SHA-256 hashes of its files.
func Fingerprint(hashes map[string]string) string {
	sum := sha256.New()
	for _, name := range Files {
		fmt.Fprintf(sum, "%s\n%s\n", name, hashes[name])
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func hashFiles(contents map[string][]byte) map[string]string {
	hashes := make(map[string]string, len(Files))
	for _, name := range Files {
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
	if manifest.Format != FormatVersion {
		return manifest, nil, &NotReadyError{Reason: fmt.Sprintf("unsupported policy set format %d", manifest.Format)}
	}
	contents := make(map[string][]byte, len(Files))
	for _, name := range Files {
		if contents[name], err = os.ReadFile(filepath.Join(dir, name)); err != nil {
			return manifest, nil, &NotReadyError{Reason: err.Error()}
		}
	}
	hashes := hashFiles(contents)
	for _, name := range Files {
		if manifest.Files[name] != hashes[name] {
			return manifest, nil, &NotReadyError{Reason: name + " does not match the manifest"}
		}
	}
	if Fingerprint(hashes) != set {
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
	snapshot, err := Compile(contents["rules.cedar"], contents["tools.json"], contents["checks.json"], set)
	if err != nil {
		return nil, manifest, err
	}
	snapshot.Label = manifest.Label
	return snapshot, manifest, nil
}

// Promote validates the policy files in source, stores them as an immutable
// set, and makes it active. A file that fails validation leaves the store's
// active pointer unchanged. Publishing content that already exists keeps the
// label it was first published with.
func Promote(root, source, label string, now func() time.Time) (string, error) {
	contents := make(map[string][]byte, len(Files))
	for _, name := range Files {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			return "", err
		}
		contents[name] = data
	}
	hashes := hashFiles(contents)
	set := Fingerprint(hashes)
	if _, err := Compile(contents["rules.cedar"], contents["tools.json"], contents["checks.json"], set); err != nil {
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
type store struct {
	root     string
	dirMode  os.FileMode
	fileMode os.FileMode
	unlock   func()
}

func openStore(root string) (*store, error) {
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return nil, err
		}
		if err := os.Chmod(root, 0o755); err != nil {
			return nil, err
		}
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	s := &store{root: root, dirMode: info.Mode().Perm(), fileMode: info.Mode().Perm() &^ 0o111}
	if s.unlock, err = lockStore(root, s.fileMode); err != nil {
		return nil, err
	}
	return s, nil
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
	return writeAtomically(filepath.Join(s.root, pointerFile), append(data, '\n'), s.fileMode)
}

// lockStore takes an exclusive lock on the store, released when the returned
// function is called or the process exits.
func lockStore(root string, mode os.FileMode) (func(), error) {
	file, err := os.OpenFile(filepath.Join(root, ".lock"), os.O_CREATE|os.O_RDWR, mode)
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
// sets directory is synced on every path so a reused or new set survives a
// crash before the pointer names it.
func (s *store) writeSet(set string, manifest Manifest, contents map[string][]byte) error {
	sets := filepath.Join(s.root, setsDir)
	if err := os.MkdirAll(sets, s.dirMode); err != nil {
		return err
	}
	if err := os.Chmod(sets, s.dirMode); err != nil {
		return err
	}
	final := filepath.Join(sets, set)
	if _, _, err := ReadSet(s.root, set); err == nil {
		return syncDir(sets)
	}
	if _, err := os.Stat(final); err == nil {
		if previous, err := readManifest(final); err == nil {
			manifest.Label = previous.Label
		}
		damaged := filepath.Join(sets, fmt.Sprintf(".damaged-%s-%d", set, time.Now().UnixNano()))
		if err := os.Rename(final, damaged); err != nil {
			return err
		}
		defer os.RemoveAll(damaged)
	}
	staging, err := os.MkdirTemp(sets, ".staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	for _, name := range Files {
		if err := writeFileSynced(filepath.Join(staging, name), contents[name], s.fileMode); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileSynced(filepath.Join(staging, manifestFile), append(data, '\n'), s.fileMode); err != nil {
		return err
	}
	if err := os.Chmod(staging, s.dirMode); err != nil {
		return err
	}
	if err := syncDir(staging); err != nil {
		return err
	}
	if err := os.Rename(staging, final); err != nil {
		return err
	}
	return syncDir(sets)
}

func writeFileSynced(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
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

func syncDir(dir string) error {
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
