package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	f, err := s.dir.OpenFile(logFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, s.fileMode)
	if err != nil {
		return err
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
// decisions has an empty log.
func ReadLog(root string) ([]LogEntry, error) {
	data, err := os.ReadFile(filepath.Join(root, logFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []LogEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, 1<<20)
	for line := 1; scanner.Scan(); line++ {
		var e LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return entries, fmt.Errorf("decision log line %d: %w", line, err)
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}
