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
//   - <proxy>/tools/<tool>/<fingerprint>.json and
//     <proxy>/instructions/<fingerprint>.json hold each new or changed tool
//     definition and each changed instructions text, once per fingerprint,
//     for review;
//   - <proxy>/latest/<tool>.json holds the fingerprint of the definition a
//     gateway last saw an upstream declare for an approved tool, and when.
//
// Proxy and tool names are stored base64url-encoded, so no name can leave its
// directory, and every file is opened through an os.Root confined to the
// directory.
//
// The request path never touches the directory: gateways offer what they see
// to a bounded queue that one background writer drains, and read the latest
// declarations in the background into a copy that calls read without a lock.
// A gateway refuses calls to a tool whose newest declaration, its own or
// another gateway's, is not the approved one, so a change seen by one gateway
// is refused by all within their refresh interval.
type Pending struct {
	root    *os.Root
	gateway string
	limits  Limits
	queue   chan pendingWrite
	latest  atomic.Pointer[map[string]Declared]
	counts  atomic.Pointer[map[string]int]
	now     func() time.Time
}

// Declared is a tool definition an upstream declared, by fingerprint, and
// when a gateway received it.
type Declared struct {
	Fingerprint string    `json:"fingerprint"`
	SeenAt      time.Time `json:"seenAt"`
	Gateway     string    `json:"gateway"`
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

type pendingWrite struct {
	tool         *ToolEntry
	instructions *InstructionsEntry
	latest       *latestWrite
}

type latestWrite struct {
	proxy, tool string
	declared    Declared
}

// pendingQueue bounds the writes waiting for the writer. A write offered when
// the queue is full is dropped and logged; the next list offers it again.
const pendingQueue = 1024

// maxLatestFile bounds a latest-declaration file the gateway reads.
const maxLatestFile = 4096

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// OpenPending opens the shared directory. An empty dir disables sharing: the
// returned value accepts and ignores writes and reports no declarations.
func OpenPending(dir, gateway string, limits Limits) (*Pending, error) {
	p := &Pending{gateway: gateway, limits: limits, now: time.Now}
	empty, counts := map[string]Declared{}, map[string]int{}
	p.latest.Store(&empty)
	p.counts.Store(&counts)
	if dir == "" {
		return p, nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	p.root = root
	p.queue = make(chan pendingWrite, pendingQueue)
	go p.write()
	return p, nil
}

func encodeName(name string) string { return base64.RawURLEncoding.EncodeToString([]byte(name)) }

func decodeName(encoded string) (string, bool) {
	name, err := base64.RawURLEncoding.DecodeString(encoded)
	return string(name), err == nil && len(name) > 0
}

// offer queues a write without waiting.
func (p *Pending) offer(w pendingWrite) {
	if p.queue == nil {
		return
	}
	select {
	case p.queue <- w:
	default:
		slog.Warn("Drift review queue is full; a declaration was not shared")
	}
}

// Changed queues a new or changed tool definition for review. A definition
// larger than the limit, or one that could not be fingerprinted, is not
// written.
func (p *Pending) Changed(proxy, tool, fingerprint string, definition jsontext.Value) {
	if !fingerprintPattern.MatchString(fingerprint) || len(definition) > p.limits.MaxDefinitionBytes || len(tool) > maxToolName {
		return
	}
	p.offer(pendingWrite{tool: &ToolEntry{Proxy: proxy, Tool: tool, Fingerprint: fingerprint,
		Definition: definition.Clone(), FirstSeen: p.now().UTC(), Gateway: p.gateway}})
}

// ChangedInstructions queues changed instructions for review.
func (p *Pending) ChangedInstructions(proxy, fingerprint, instructions string) {
	if !fingerprintPattern.MatchString(fingerprint) || len(instructions) > p.limits.MaxDefinitionBytes {
		return
	}
	p.offer(pendingWrite{instructions: &InstructionsEntry{Proxy: proxy, Fingerprint: fingerprint,
		Instructions: instructions, FirstSeen: p.now().UTC(), Gateway: p.gateway}})
}

// Saw shares the fingerprint an upstream declared for an approved tool, when
// it differs from the newest declaration the gateways share, so every gateway
// decides calls on the newest one.
func (p *Pending) Saw(proxy, tool, fingerprint string, at time.Time) {
	if !fingerprintPattern.MatchString(fingerprint) || len(tool) > maxToolName {
		return
	}
	if shared, ok := p.Latest(proxy, tool); ok && shared.Fingerprint == fingerprint {
		return
	}
	p.offer(pendingWrite{latest: &latestWrite{proxy: proxy, tool: tool,
		declared: Declared{Fingerprint: fingerprint, SeenAt: at.UTC(), Gateway: p.gateway}}})
}

// Latest returns the newest declaration of a tool the gateways share.
func (p *Pending) Latest(proxy, tool string) (Declared, bool) {
	d, ok := (*p.latest.Load())[observationKey(proxy, tool)]
	return d, ok
}

func (p *Pending) write() {
	for w := range p.queue {
		var err error
		switch {
		case w.tool != nil:
			err = p.writeTool(w.tool)
		case w.instructions != nil:
			err = p.writeInstructions(w.instructions)
		case w.latest != nil:
			err = p.writeLatest(w.latest)
		}
		if err != nil {
			slog.Error("Could not share a drift declaration", "error", err)
		}
	}
}

// full reports whether a proxy already has as many review entries as the
// limit allows. Counts come from the last refresh, so gateways writing at
// once can pass the limit by a few entries.
func (p *Pending) full(proxy string) bool {
	return (*p.counts.Load())[proxy] >= p.limits.MaxUnapprovedPerProxy
}

func (p *Pending) writeTool(e *ToolEntry) error {
	if p.full(e.Proxy) {
		return nil
	}
	dir := path.Join(encodeName(e.Proxy), "tools", encodeName(e.Tool))
	return p.create(dir, e.Fingerprint+".json", e)
}

func (p *Pending) writeInstructions(e *InstructionsEntry) error {
	if p.full(e.Proxy) {
		return nil
	}
	return p.create(path.Join(encodeName(e.Proxy), "instructions"), e.Fingerprint+".json", e)
}

// create writes a review file once: an existing file for the same
// fingerprint is left as it is, so FirstSeen keeps the first sighting.
func (p *Pending) create(dir, name string, v any) error {
	if err := p.root.MkdirAll(dir, 0o775); err != nil {
		return err
	}
	data, err := jsonv2.Marshal(v, jsonv2.Deterministic(true))
	if err != nil {
		return err
	}
	return p.publish(dir, name, data, false)
}

func (p *Pending) writeLatest(w *latestWrite) error {
	dir := path.Join(encodeName(w.proxy), "latest")
	if err := p.root.MkdirAll(dir, 0o775); err != nil {
		return err
	}
	data, err := jsonv2.Marshal(w.declared, jsonv2.Deterministic(true))
	if err != nil {
		return err
	}
	return p.publish(dir, encodeName(w.tool)+".json", data, true)
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

// Refresh reads the latest declarations and counts the review entries of
// every proxy. It reads at most maxLatest declarations per proxy, and skips
// files it cannot read or that are larger than a declaration can be.
func (p *Pending) Refresh(maxLatest int) {
	if p.root == nil {
		return
	}
	latest, counts := map[string]Declared{}, map[string]int{}
	proxies, err := p.readDir(".")
	if err != nil {
		slog.Error("Could not read shared drift declarations", "error", err)
		return
	}
	for _, encoded := range proxies {
		proxy, ok := decodeName(encoded)
		if !ok {
			continue
		}
		counts[proxy] = p.countEntries(encoded)
		files, err := p.readDir(path.Join(encoded, "latest"))
		if err != nil {
			continue
		}
		read := 0
		for _, file := range files {
			tool, ok := decodeName(trimJSON(file))
			if !ok || read >= maxLatest {
				continue
			}
			var d Declared
			if p.readJSON(path.Join(encoded, "latest", file), &d) && fingerprintPattern.MatchString(d.Fingerprint) {
				latest[observationKey(proxy, tool)] = d
				read++
			}
		}
	}
	p.latest.Store(&latest)
	p.counts.Store(&counts)
}

// countEntries counts a proxy's review entries, stopping past the limit.
func (p *Pending) countEntries(encoded string) int {
	count := 0
	instructions, _ := p.readDir(path.Join(encoded, "instructions"))
	count += len(instructions)
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
	data, err := io.ReadAll(io.LimitReader(f, maxLatestFile+1))
	return err == nil && len(data) <= maxLatestFile && jsonv2.Unmarshal(data, v) == nil
}

func trimJSON(name string) string {
	if len(name) > 5 && name[len(name)-5:] == ".json" {
		return name[:len(name)-5]
	}
	return ""
}
