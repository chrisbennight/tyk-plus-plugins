package drift

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
	jsonv2 "github.com/go-json-experiment/json"
)

// Review reads and tidies the shared directory for reviewers. Any gateway can
// write the directory, so every entry is checked before it is returned: its
// file name, the names it is filed under, and the fingerprint of the content
// it holds must all agree. A reviewer therefore approves exactly the content
// a fingerprint names.
type Review struct {
	root *os.Root
}

// OpenReview opens a shared directory for review.
func OpenReview(dir string) (*Review, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Review{root: root}, nil
}

// Close releases the directory.
func (r *Review) Close() error { return r.root.Close() }

// maxEntryFile bounds a review entry the reviewer reads. Gateways write
// definitions up to their configured limit, so the bound is generous.
const maxEntryFile = 64 << 20

// Tools returns a proxy's tool review entries, and a problem for each entry
// that cannot be read or does not hold what it is filed under.
func (r *Review) Tools(proxy string) ([]ToolEntry, []error, error) {
	base := path.Join(encodeName(proxy), "tools")
	tools, err := r.names(base)
	if err != nil {
		return nil, nil, err
	}
	var entries []ToolEntry
	var problems []error
	for _, encodedTool := range tools {
		tool, ok := decodeName(encodedTool)
		if !ok {
			continue
		}
		files, err := r.names(path.Join(base, encodedTool))
		if err != nil {
			return nil, nil, err
		}
		for _, file := range files {
			fingerprint, _ := strings.CutSuffix(file, ".json")
			entry, err := r.Tool(proxy, tool, fingerprint)
			if err != nil {
				problems = append(problems, err)
				continue
			}
			entries = append(entries, entry)
		}
	}
	return entries, problems, nil
}

// Tool returns one tool review entry, after checking that its definition has
// the fingerprint it is filed under.
func (r *Review) Tool(proxy, tool, fingerprint string) (ToolEntry, error) {
	var entry ToolEntry
	if !fingerprintPattern.MatchString(fingerprint) {
		return entry, fmt.Errorf("%q is not a fingerprint", fingerprint)
	}
	name := path.Join(encodeName(proxy), "tools", encodeName(tool), fingerprint+".json")
	if err := r.read(name, &entry); err != nil {
		return entry, err
	}
	actual, err := policy.DefinitionFingerprint(entry.Definition)
	if err != nil || entry.Proxy != proxy || entry.Tool != tool || entry.Fingerprint != fingerprint || actual != fingerprint {
		return entry, fmt.Errorf("review entry %s/%s %s does not hold the definition it is filed under", proxy, tool, fingerprint)
	}
	return entry, nil
}

// Instructions returns a proxy's instructions review entries, and a problem
// for each entry that cannot be read or does not hold what it is filed under.
func (r *Review) Instructions(proxy string) ([]InstructionsEntry, []error, error) {
	files, err := r.names(path.Join(encodeName(proxy), "instructions"))
	if err != nil {
		return nil, nil, err
	}
	var entries []InstructionsEntry
	var problems []error
	for _, file := range files {
		fingerprint, _ := strings.CutSuffix(file, ".json")
		entry, err := r.InstructionsEntry(proxy, fingerprint)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		entries = append(entries, entry)
	}
	return entries, problems, nil
}

// InstructionsEntry returns one instructions review entry, after checking
// that its text has the fingerprint it is filed under.
func (r *Review) InstructionsEntry(proxy, fingerprint string) (InstructionsEntry, error) {
	var entry InstructionsEntry
	if !fingerprintPattern.MatchString(fingerprint) {
		return entry, fmt.Errorf("%q is not a fingerprint", fingerprint)
	}
	if err := r.read(path.Join(encodeName(proxy), "instructions", fingerprint+".json"), &entry); err != nil {
		return entry, err
	}
	if entry.Proxy != proxy || entry.Fingerprint != fingerprint || policy.InstructionsFingerprint(entry.Instructions) != fingerprint {
		return entry, fmt.Errorf("review entry for the instructions of %s %s does not hold the text it is filed under", proxy, fingerprint)
	}
	return entry, nil
}

// Declarations returns every gateway's latest declaration of a tool. Files
// that are not valid declarations are reported, as gateways refuse calls
// while one exists.
func (r *Review) Declarations(proxy, tool string) ([]Declared, error) {
	dir := path.Join(encodeName(proxy), "latest", encodeName(tool))
	files, err := r.names(dir)
	if err != nil {
		return nil, err
	}
	var declared []Declared
	for _, file := range files {
		var d Declared
		if err := r.read(path.Join(dir, file), &d); err != nil {
			return nil, err
		}
		if d.Gateway == "" || d.Upstream == "" || d.SeenAt.IsZero() || file != declarationFile(d.Gateway, d.Upstream) ||
			(d.Fingerprint != "" && !fingerprintPattern.MatchString(d.Fingerprint)) {
			return nil, fmt.Errorf("declaration file %s is not valid; gateways refuse calls on %s until it is removed", path.Join(proxy, "latest", tool, file), proxy)
		}
		declared = append(declared, d)
	}
	return declared, nil
}

// Newest returns the newest declaration of a tool from an upstream across
// gateways, as gateways decide calls on it.
func (r *Review) Newest(proxy, tool, upstream string) (Declared, bool, error) {
	all, err := r.Declarations(proxy, tool)
	if err != nil {
		return Declared{}, false, err
	}
	var newest Declared
	found := false
	for _, d := range all {
		if d.Upstream == upstream && (!found || d.SeenAt.After(newest.SeenAt)) {
			newest, found = d, true
		}
	}
	return newest, found, nil
}

// RemoveTool removes a tool review entry. A missing entry is not an error.
func (r *Review) RemoveTool(proxy, tool, fingerprint string) error {
	return r.remove(path.Join(encodeName(proxy), "tools", encodeName(tool), fingerprint+".json"))
}

// RemoveInstructions removes an instructions review entry.
func (r *Review) RemoveInstructions(proxy, fingerprint string) error {
	return r.remove(path.Join(encodeName(proxy), "instructions", fingerprint+".json"))
}

// Retire removes every declaration file a gateway wrote, for a gateway that
// will not run again, and returns how many it removed. Its files would
// otherwise count towards the limit of files per tool forever.
func (r *Review) Retire(gateway string) (int, error) {
	if gateway == "" {
		return 0, errors.New("a gateway name is required")
	}
	prefix := encodeName(gateway) + "."
	proxies, err := r.names(".")
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, proxy := range proxies {
		latest := path.Join(proxy, "latest")
		tools, err := r.names(latest)
		if err != nil {
			return removed, err
		}
		for _, tool := range tools {
			files, err := r.names(path.Join(latest, tool))
			if err != nil {
				return removed, err
			}
			for _, file := range files {
				if !strings.HasPrefix(file, prefix) {
					continue
				}
				if err := r.remove(path.Join(latest, tool, file)); err != nil {
					return removed, err
				}
				removed++
			}
		}
	}
	return removed, nil
}

// names lists a directory without temporary files. A missing directory has
// no names.
func (r *Review) names(dir string) ([]string, error) {
	f, err := r.root.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if name := e.Name(); name != "" && name[0] != '.' {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}

func (r *Review) read(name string, v any) error {
	f, err := r.root.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxEntryFile+1))
	if err != nil {
		return err
	}
	if len(data) > maxEntryFile {
		return fmt.Errorf("%s is larger than any entry a gateway writes", name)
	}
	if err := jsonv2.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func (r *Review) remove(name string) error {
	if err := r.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
