package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// logFile is the store's decision log: one JSON object per line, appended
// under the store's lock each time a decision makes a new set active.
const logFile = "decisions.log"

// Actor is who made a decision: the issuer and subject that identify them,
// and a name to show. The command line records the local user, with the
// issuer "local".
type Actor struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Name    string `json:"name,omitempty"`
}

// LogEntry records one decision: what was decided, by whom and when, and the
// set it was made against and the set it made active.
type LogEntry struct {
	Time         string `json:"time"`
	Actor        Actor  `json:"actor"`
	Action       string `json:"action"`
	Proxy        string `json:"proxy,omitempty"`
	Tool         string `json:"tool,omitempty"`
	Instructions bool   `json:"instructions,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	Base         string `json:"base"`
	Set          string `json:"set"`
	Label        string `json:"label,omitempty"`
}

// appendLog adds entries to the decision log and makes them durable. The
// caller holds the store's lock.
func (s *store) appendLog(entries []LogEntry) error {
	var buf bytes.Buffer
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		buf.Write(append(line, '\n'))
	}
	// The log is created with the store's file mode whatever the umask, as
	// every file in the store is, so each member of a shared store can append.
	if _, err := s.dir.Lstat(logFile); errors.Is(err, fs.ErrNotExist) {
		prepared := tempName("." + logFile + "-")
		if err := s.writeFile(prepared, nil, s.fileMode); err != nil {
			return err
		}
		err := s.dir.Link(prepared, logFile)
		s.dir.Remove(prepared)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	} else if err != nil {
		return err
	}
	f, err := s.dir.OpenFile(logFile, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	// A line an earlier failed write cut short is ended first, so these
	// entries start on lines of their own.
	if info, statErr := f.Stat(); statErr == nil && info.Size() > 0 {
		last := make([]byte, 1)
		if _, readErr := f.ReadAt(last, info.Size()-1); readErr == nil && last[0] != '\n' {
			buf = *bytes.NewBuffer(append([]byte{'\n'}, buf.Bytes()...))
		}
	}
	_, err = f.Write(buf.Bytes())
	if syncErr := f.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return s.sync(".")
}

// ReadLog returns the store's decision log, oldest first. A store without
// decisions has an empty log. A line that is not a valid entry, such as one
// a failed write cut short, is skipped and reported in the error, while the
// entries around it are still returned.
func ReadLog(root string) ([]LogEntry, error) {
	data, err := os.ReadFile(filepath.Join(root, logFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []LogEntry
	var problems []error
	// Lines are split without a length limit, so no single long entry can
	// hide the ones after it.
	for line, text := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		if len(text) == 0 {
			continue
		}
		var e LogEntry
		if err := json.Unmarshal(text, &e); err != nil {
			problems = append(problems, fmt.Errorf("decision log line %d is not a valid entry", line+1))
			continue
		}
		entries = append(entries, e)
	}
	return entries, errors.Join(problems...)
}

// ErrMoved reports a change made against a set that is no longer active, or
// a rollback whose target is no longer the set the active one replaced.
var ErrMoved = errors.New("the active set has changed")

// Rollback makes target, the set active before base, active again, provided
// base is still the active set and target still the one it replaced, and
// records it in the decision log. It is how a
// reviewer undoes the last change; a rollback is itself undone by rolling
// back again.
func Rollback(root, base, target string, actor Actor, now func() time.Time) (string, error) {
	store, err := openStore(root)
	if err != nil {
		return "", err
	}
	defer store.unlock()
	pointer, err := ReadPointer(root)
	if err != nil {
		return "", err
	}
	if pointer.Set != base || pointer.Previous != target {
		return "", fmt.Errorf("%w: it is now %s, replacing %s; nothing was changed", ErrMoved, pointer.Set, pointer.Previous)
	}
	if pointer.Previous == "" {
		return "", errors.New("the active pointer records no previous set to roll back to")
	}
	if err := store.activate(pointer.Previous, now); err != nil {
		return "", err
	}
	entry := LogEntry{Time: now().UTC().Format(time.RFC3339Nano), Actor: actor, Action: "rollback", Base: base, Set: pointer.Previous}
	if err := store.appendLog([]LogEntry{entry}); err != nil {
		// As in Revise: in force and logged, or neither.
		if restoreErr := store.writePointer(pointer); restoreErr != nil {
			return pointer.Previous, fmt.Errorf("set %s is active, but the decision log could not be written (%w), and the previous pointer could not be restored: %w", pointer.Previous, err, restoreErr)
		}
		return "", fmt.Errorf("the decision log could not be written, so nothing was rolled back: %w", err)
	}
	return pointer.Previous, nil
}
