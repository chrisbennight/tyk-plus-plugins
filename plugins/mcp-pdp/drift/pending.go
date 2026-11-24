package drift

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"regexp"
	"sync/atomic"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// Pending shares what gateways see with each other and with reviewers,
// through a directory every gateway can write:
//
//   - <proxy>/latest/<tool>/<gateway>.json holds the definition, by
//     fingerprint, that one gateway last saw an upstream declare for a tool,
//     when, and from which upstream. Each gateway writes only its own file,
//     in the order it saw the declarations, so no gateway can overwrite
//     another's newer one; readers take the newest across gateways.
//   - <proxy>/tools/<tool>/<fingerprint>.json and
//     <proxy>/instructions/<fingerprint>.json hold each new or changed tool
//     definition and each changed instructions text, once per fingerprint,
//     for review.
//
// Proxy, tool and gateway names are stored base64url-encoded, so no name can
// leave its directory, and every file is opened through an os.Root confined
// to the directory.
//
// The request path never touches the directory: gateways offer what they see
// to bounded queues that one background writer drains, and read the latest
// declarations in the background into a copy that calls read without a lock.
// Every list offers all its tools again, so a write dropped from a full queue
// is made by the next list.
type Pending struct {
	root         *os.Root
	gateway      string
	limits       Limits
	declarations chan declaration
	reviews      chan review
	latest       atomic.Pointer[map[string]Declared]
	counts       atomic.Pointer[entryCounts]
	now          func() time.Time
}

// Declared is a tool definition an upstream declared, by fingerprint, when a
// gateway received it, and the upstream it came from. An empty fingerprint
// means the definition could not be identified, which matches no approval.
type Declared struct {
	Fingerprint string    `json:"fingerprint"`
	SeenAt      time.Time `json:"seenAt"`
	Gateway     string    `json:"gateway"`
	Upstream    string    `json:"upstream"`
}

// ToolEntry and InstructionsEntry are the review files. FirstSeen and Gateway
// record where the change was first seen.
type ToolEntry struct {
	Proxy       string         `json:"proxy"`
	Tool        string         `json:"tool"`
	Fingerprint string         `json:"fingerprint"`
	Definition  jsontext.Value `json:"definition"`
	FirstSeen   time.Time      `json:"firstSeen"`
	Gateway     string         `json:"gateway"`
}

type InstructionsEntry struct {
	Proxy        string    `json:"proxy"`
	Fingerprint  string    `json:"fingerprint"`
	Instructions string    `json:"instructions"`
	FirstSeen    time.Time `json:"firstSeen"`
	Gateway      string    `json:"gateway"`
}

type declaration struct {
	proxy, tool string
	approved    bool
	declared    Declared
}

type review struct {
	tool         *ToolEntry
	instructions *InstructionsEntry
}

// entryCounts are the review entries each proxy held at a refresh.
type entryCounts struct {
	generation uint64
	byProxy    map[string]int
}

// queueLength bounds each queue of writes waiting for the writer. A write
// offered when its queue is full is dropped and logged.
const queueLength = 4096

// maxDeclarationFile bounds a declaration file the gateway reads, and
// maxGatewaysPerTool the declaration files it reads for one tool.
const (
	maxDeclarationFile = 4096
	maxGatewaysPerTool = 256
)

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// OpenPending opens the shared directory. An empty dir disables sharing: the
// returned value accepts and ignores writes and reports no declarations.
func OpenPending(dir, gateway string, limits Limits) (*Pending, error) {
	p := &Pending{gateway: gateway, limits: limits, now: time.Now}
	p.latest.Store(&map[string]Declared{})
	p.counts.Store(&entryCounts{byProxy: map[string]int{}})
	if dir == "" {
		return p, nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	p.root = root
	p.declarations = make(chan declaration, queueLength)
	p.reviews = make(chan review, queueLength)
	go p.write()
	return p, nil
}

func encodeName(name string) string { return base64.RawURLEncoding.EncodeToString([]byte(name)) }

func decodeName(encoded string) (string, bool) {
	name, err := base64.RawURLEncoding.DecodeString(encoded)
	return string(name), err == nil && len(name) > 0
}

// Saw shares the definition an upstream declared for a tool, approved or
// not, so every gateway decides calls on the newest declaration. An empty
// fingerprint is shared as a definition that matches no approval.
func (p *Pending) Saw(proxy, upstream, tool, fingerprint string, approved bool, at time.Time) {
	if p.declarations == nil || (fingerprint != "" && !fingerprintPattern.MatchString(fingerprint)) || len(tool) > maxToolName {
		return
	}
	select {
	case p.declarations <- declaration{proxy: proxy, tool: tool, approved: approved,
		declared: Declared{Fingerprint: fingerprint, SeenAt: at.UTC(), Gateway: p.gateway, Upstream: upstream}}:
	default:
		slog.Warn("Drift declaration queue is full; the next list shares the declaration", "proxy", proxy, "tool", tool)
	}
}

// Changed queues a new or changed tool definition for review. A definition
// larger than the limit, or one that could not be fingerprinted, is not
// written.
func (p *Pending) Changed(proxy, tool, fingerprint string, definition jsontext.Value) {
	if !fingerprintPattern.MatchString(fingerprint) || len(definition) > p.limits.MaxDefinitionBytes || len(tool) > maxToolName {
		return
	}
	p.offerReview(review{tool: &ToolEntry{Proxy: proxy, Tool: tool, Fingerprint: fingerprint,
		Definition: definition.Clone(), FirstSeen: p.now().UTC(), Gateway: p.gateway}})
}

// ChangedInstructions queues changed instructions for review, including
// instructions the upstream removed, which are empty.
func (p *Pending) ChangedInstructions(proxy, fingerprint, instructions string) {
	if !fingerprintPattern.MatchString(fingerprint) || len(instructions) > p.limits.MaxDefinitionBytes {
		return
	}
	p.offerReview(review{instructions: &InstructionsEntry{Proxy: proxy, Fingerprint: fingerprint,
		Instructions: instructions, FirstSeen: p.now().UTC(), Gateway: p.gateway}})
}

func (p *Pending) offerReview(r review) {
	if p.reviews == nil {
		return
	}
	select {
	case p.reviews <- r:
	default:
		slog.Warn("Drift review queue is full; the next list queues the change")
	}
}

// Latest returns the newest declaration of a tool any gateway shares.
func (p *Pending) Latest(proxy, tool string) (Declared, bool) {
	d, ok := (*p.latest.Load())[observationKey(proxy, tool)]
	return d, ok
}

// writer holds what the background writer has written, which only it reads.
type writer struct {
	own        map[string]Declared
	unapproved map[string]int
	generation uint64
	written    map[string]int
}

func (p *Pending) write() {
	w := writer{own: map[string]Declared{}, unapproved: map[string]int{}, written: map[string]int{}}
	for {
		var err error
		select {
		case d := <-p.declarations:
			err = p.writeDeclaration(&w, d)
		case r := <-p.reviews:
			err = p.writeReview(&w, r)
		}
		if err != nil {
			slog.Error("Could not share a drift declaration", "error", err)
		}
	}
}

// writeDeclaration writes this gateway's declaration of a tool. A declaration
// that repeats this gateway's last one is not written again, unless another
// gateway has since shared a newer, different one, which this sighting must
// override. Tools without approval are shared up to the per-proxy limit.
func (p *Pending) writeDeclaration(w *writer, d declaration) error {
	key := observationKey(d.proxy, d.tool)
	last, written := w.own[key]
	if written && last.Fingerprint == d.declared.Fingerprint && last.Upstream == d.declared.Upstream {
		shared, ok := p.Latest(d.proxy, d.tool)
		if !ok || !shared.SeenAt.After(last.SeenAt) || shared.Fingerprint == last.Fingerprint {
			return nil
		}
	}
	if written && d.declared.SeenAt.Before(last.SeenAt) {
		return nil
	}
	if !d.approved && !written {
		if w.unapproved[d.proxy] >= p.limits.MaxUnapprovedPerProxy {
			return nil
		}
		w.unapproved[d.proxy]++
	}
	dir := path.Join(encodeName(d.proxy), "latest", encodeName(d.tool))
	if err := p.root.MkdirAll(dir, 0o775); err != nil {
		return err
	}
	data, err := jsonv2.Marshal(d.declared, jsonv2.Deterministic(true))
	if err != nil {
		return err
	}
	if err := p.publish(dir, encodeName(p.gateway)+".json", data, true); err != nil {
		return err
	}
	w.own[key] = d.declared
	return nil
}

// writeReview writes a review entry once per fingerprint. The per-proxy limit
// counts the entries found at the last refresh and those written since.
func (p *Pending) writeReview(w *writer, r review) error {
	counts := p.counts.Load()
	if counts.generation != w.generation {
		w.generation, w.written = counts.generation, map[string]int{}
	}
	proxy := ""
	var dir, name string
	var v any
	switch {
	case r.tool != nil:
		proxy, v = r.tool.Proxy, r.tool
		dir, name = path.Join(encodeName(proxy), "tools", encodeName(r.tool.Tool)), r.tool.Fingerprint+".json"
	case r.instructions != nil:
		proxy, v = r.instructions.Proxy, r.instructions
		dir, name = path.Join(encodeName(proxy), "instructions"), r.instructions.Fingerprint+".json"
	default:
		return nil
	}
	if counts.byProxy[proxy]+w.written[proxy] >= p.limits.MaxUnapprovedPerProxy {
		return nil
	}
	if err := p.root.MkdirAll(dir, 0o775); err != nil {
		return err
	}
	data, err := jsonv2.Marshal(v, jsonv2.Deterministic(true))
	if err != nil {
		return err
	}
	if _, err := p.root.Stat(path.Join(dir, name)); err == nil {
		return nil
	}
	if err := p.publish(dir, name, data, false); err != nil {
		return err
	}
	w.written[proxy]++
	return nil
}

// publish writes a file whole: to a temporary file first, then linked or
// renamed into place, so readers never see part of one. Without replace an
// existing file is kept.
func (p *Pending) publish(dir, name string, data []byte, replace bool) error {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temp := path.Join(dir, "."+hex.EncodeToString(random)+".tmp")
	f, err := p.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o664)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		if replace {
			err = p.root.Rename(temp, path.Join(dir, name))
		} else if err = p.root.Link(temp, path.Join(dir, name)); errors.Is(err, fs.ErrExist) {
			err = nil
		}
	}
	if removeErr := p.root.Remove(temp); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) && err == nil {
		err = removeErr
	}
	return err
}

// Refresh reads the newest declaration of every tool keep accepts, and
// counts each proxy's review entries. keep limits reading to the tools of the
// active policy set, so declarations of tools no longer reviewed cannot
// crowd out current ones. Files that cannot be read, or are larger than a
// declaration can be, are skipped.
func (p *Pending) Refresh(keep func(proxy, tool string) bool) {
	if p.root == nil {
		return
	}
	latest, counts := map[string]Declared{}, map[string]int{}
	proxies, err := p.readDir(".")
	if err != nil {
		slog.Error("Could not read shared drift declarations", "error", err)
		return
	}
	for _, encodedProxy := range proxies {
		proxy, ok := decodeName(encodedProxy)
		if !ok {
			continue
		}
		counts[proxy] = p.countEntries(encodedProxy)
		tools, _ := p.readDir(path.Join(encodedProxy, "latest"))
		for _, encodedTool := range tools {
			tool, ok := decodeName(encodedTool)
			if !ok || !keep(proxy, tool) {
				continue
			}
			gateways, _ := p.readDir(path.Join(encodedProxy, "latest", encodedTool))
			for i, file := range gateways {
				if i >= maxGatewaysPerTool {
					break
				}
				var d Declared
				if !p.readJSON(path.Join(encodedProxy, "latest", encodedTool, file), &d) ||
					(d.Fingerprint != "" && !fingerprintPattern.MatchString(d.Fingerprint)) {
					continue
				}
				key := observationKey(proxy, tool)
				if newest, ok := latest[key]; !ok || d.SeenAt.After(newest.SeenAt) {
					latest[key] = d
				}
			}
		}
	}
	p.latest.Store(&latest)
	p.counts.Store(&entryCounts{generation: p.counts.Load().generation + 1, byProxy: counts})
}

// countEntries counts a proxy's review entries, stopping past the limit.
func (p *Pending) countEntries(encoded string) int {
	instructions, _ := p.readDir(path.Join(encoded, "instructions"))
	count := len(instructions)
	tools, _ := p.readDir(path.Join(encoded, "tools"))
	for _, tool := range tools {
		if count > p.limits.MaxUnapprovedPerProxy {
			break
		}
		entries, _ := p.readDir(path.Join(encoded, "tools", tool))
		count += len(entries)
	}
	return count
}

// readDir lists the names in a directory, without temporary files.
func (p *Pending) readDir(dir string) ([]string, error) {
	f, err := p.root.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if name := e.Name(); len(name) > 0 && name[0] != '.' {
			names = append(names, name)
		}
	}
	return names, nil
}

func (p *Pending) readJSON(name string, v any) bool {
	f, err := p.root.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxDeclarationFile+1))
	return err == nil && len(data) <= maxDeclarationFile && jsonv2.Unmarshal(data, v) == nil
}
