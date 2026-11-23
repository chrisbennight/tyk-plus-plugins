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

// Pointer names the active policy set and the set it replaced.
type Pointer struct {
	Set        string `json:"set"`
	Label      string `json:"label,omitempty"`
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

// LoadSet verifies that a set's files match its manifest and fingerprint, then
// validates it. A mismatch returns a NotReadyError; a validation failure
// returns the validation error.
func LoadSet(root, set string) (*Snapshot, Manifest, error) {
	var manifest Manifest
	if !fingerprintPattern.MatchString(set) {
		return nil, manifest, fmt.Errorf("invalid set name %q", set)
	}
	dir := filepath.Join(root, setsDir, set)
	data, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		return nil, manifest, &NotReadyError{Reason: err.Error()}
	}
	if err := jsonv2.Unmarshal(data, &manifest, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, manifest, &NotReadyError{Reason: "unreadable manifest: " + err.Error()}
	}
	if manifest.Format != FormatVersion {
		return nil, manifest, fmt.Errorf("unsupported policy set format %d", manifest.Format)
	}
	contents := make(map[string][]byte, len(Files))
	for _, name := range Files {
		if contents[name], err = os.ReadFile(filepath.Join(dir, name)); err != nil {
			return nil, manifest, &NotReadyError{Reason: err.Error()}
		}
	}
	hashes := hashFiles(contents)
	for _, name := range Files {
		if manifest.Files[name] != hashes[name] {
			return nil, manifest, &NotReadyError{Reason: name + " does not match the manifest"}
		}
	}
	if Fingerprint(hashes) != set {
		return nil, manifest, &NotReadyError{Reason: "content does not match the set name"}
	}
	snapshot, err := Compile(contents["rules.cedar"], contents["tools.json"], contents["checks.json"], set)
	return snapshot, manifest, err
}

// Promote validates the policy files in source, stores them as an immutable
// set, and makes it active. A file that fails validation leaves the store's
// active pointer unchanged.
func Promote(root, source, label string, now time.Time) (string, error) {
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
	if err := writeSet(root, set, Manifest{Format: FormatVersion, Label: label, Files: hashes}, contents); err != nil {
		return "", err
	}
	return set, Activate(root, set, label, now)
}

// Activate makes an existing set active after validating it again, for example
// to roll back to the set a pointer records as previous.
func Activate(root, set, label string, now time.Time) error {
	if _, _, err := LoadSet(root, set); err != nil {
		return fmt.Errorf("policy set %s cannot be activated: %w", set, err)
	}
	pointer := Pointer{Set: set, Label: label, PromotedAt: now.UTC().Format(time.RFC3339)}
	if current, err := ReadPointer(root); err == nil {
		if current.Set == set {
			pointer.Previous = current.Previous
		} else {
			pointer.Previous = current.Set
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(pointer, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomically(filepath.Join(root, pointerFile), append(data, '\n'))
}

// writeSet stores a set by renaming a completed temporary directory into
// place, so readers never see a partial set. An existing set with the same
// fingerprint already holds the same content.
func writeSet(root, set string, manifest Manifest, contents map[string][]byte) error {
	sets := filepath.Join(root, setsDir)
	if err := os.MkdirAll(sets, 0o755); err != nil {
		return err
	}
	final := filepath.Join(sets, set)
	if _, err := os.Stat(final); err == nil {
		return nil
	}
	staging, err := os.MkdirTemp(sets, ".staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	for _, name := range Files {
		if err := os.WriteFile(filepath.Join(staging, name), contents[name], 0o644); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(staging, manifestFile), append(data, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(staging, 0o755); err != nil {
		return err
	}
	if err := os.Rename(staging, final); err != nil {
		if _, statErr := os.Stat(final); statErr == nil {
			return nil
		}
		return err
	}
	return nil
}

// writeAtomically replaces path by renaming a completed file over it.
func writeAtomically(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// WriteFileAtomically is exported for callers that publish status beside a
// store, such as the gateway's enforcement report.
func WriteFileAtomically(path string, data []byte) error { return writeAtomically(path, data) }
