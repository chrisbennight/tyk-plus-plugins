package drift

import (
	"crypto/rand"
	"crypto/sha256"
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
//   - <proxy>/latest/<tool>/<gateway>.<upstream>.json holds the definition, by
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
	dir          string
	root         *os.Root
	gateway      string
	limits       Limits
	declarations chan declaration
	reviews      chan review
	latest       atomic.Pointer[sharedSnapshot]
	counts       atomic.Pointer[entryCounts]
	// reviewed holds the review entries this gateway has written or found,
	// so a change it already queued is not copied again on every list.
	reviewed atomic.Pointer[map[string]bool]
	now      func() time.Time
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

// queueLength and reviewQueueLength bound the writes waiting for the writer.
// A write offered when its queue is full is dropped and logged. Review
// entries carry whole definitions, so fewer wait.
const (
	queueLength       = 4096
	reviewQueueLength = 256
)

// maxSharedName is the longest tool name a file name can hold once encoded.
// Approved tools are shared up to it; tools without approval only up to the
// shorter limit the gateway records them with.
const maxSharedName = 180

// maxDeclarationFile bounds a declaration file the gateway reads, and
// maxGatewaysPerTool the declaration files, one per gateway and upstream, it
// reads for one tool; past it the declarations are not current.
const (
	maxDeclarationFile = 4096
	maxGatewaysPerTool = 256
)

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// OpenPending prepares the shared directory. An empty dir disables sharing:
// the returned value accepts and ignores writes and reports no declarations.
// A directory that cannot be opened yet is opened by a later Refresh; until
// one succeeds the declarations are not current, so calls on proxies under
// drift review are refused rather than decided without them.
func OpenPending(dir, gateway string, limits Limits) *Pending {
	p := &Pending{dir: dir, gateway: gateway, limits: limits, now: time.Now}
	p.latest.Store(&sharedSnapshot{declared: map[string]Declared{}})
	p.reviewed.Store(&map[string]bool{})
	p.counts.Store(&entryCounts{byProxy: map[string]int{}})
	if dir == "" {
		return p
	}
	p.declarations = make(chan declaration, queueLength)
	p.reviews = make(chan review, reviewQueueLength)
	p.open()
	return p
}

// open opens the directory and starts the writer, once. Only the goroutine
// that refreshes calls it.
func (p *Pending) open() bool {
	if p.root != nil {
		return true
	}
	root, err := os.OpenRoot(p.dir)
	if err != nil {
		slog.Error("Could not open the drift review directory; calls under drift review are refused until it opens", "error", err)
		return false
	}
	p.root = root
	go p.write()
	return true
}

// declarationFile names a gateway's declaration file for one upstream. The
// upstream is hashed, since URLs can be longer than a file name may be.
func declarationFile(gateway, upstream string) string {
	sum := sha256.Sum256([]byte(upstream))
	return encodeName(gateway) + "." + hex.EncodeToString(sum[:8]) + ".json"
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
	if p.declarations == nil || (fingerprint != "" && !fingerprintPattern.MatchString(fingerprint)) || len(tool) > maxSharedName || (!approved && len(tool) > maxToolName) {
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
	if !fingerprintPattern.MatchString(fingerprint) || len(definition) > p.limits.MaxDefinitionBytes || len(tool) > maxToolName ||
		(*p.reviewed.Load())[reviewKey(proxy, tool, fingerprint)] {
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

func reviewKey(proxy, tool, fingerprint string) string {
	return proxy + "\x00" + tool + "\x00" + fingerprint
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

// Latest returns the newest declaration of a tool from an upstream that any
// gateway shares. Declarations from other upstreams are kept apart, so a
// gateway still on a previous upstream cannot hide one from the reviewed one.
func (p *Pending) Latest(proxy, tool, upstream string) (Declared, bool) {
	d, ok := p.latest.Load().declared[declarationKey(proxy, tool, upstream)]
	return d, ok
}

// sharedSnapshot is the declarations read at one refresh, for the tools of
// the policy set identified by version.
type sharedSnapshot struct {
	version  string
	declared map[string]Declared
}

// Current reports whether the shared declarations were read for the policy
// set with this version, so they cover every tool it reviews. Without a
// shared directory there is nothing to read, and they always are.
func (p *Pending) Current(version string) bool {
	return p.dir == "" || p.latest.Load().version == version
}

// Lookup returns, from one consistent read, whether the shared declarations
// were read for the policy set with this version and the newest declaration
// of a tool from an upstream.
func (p *Pending) Lookup(version, proxy, tool, upstream string) (current bool, d Declared, ok bool) {
	snapshot := p.latest.Load()
	d, ok = snapshot.declared[declarationKey(proxy, tool, upstream)]
	return p.dir == "" || snapshot.version == version, d, ok
}

func declarationKey(proxy, tool, upstream string) string {
	return observationKey(proxy, tool) + "\x00" + upstream
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

// writeDeclaration writes this gateway's declaration of a tool, when it was
// received after the last one written, so the file always holds the newest
// sighting and its time, whatever other gateways shared since. Tools without
// approval are shared up to the per-proxy limit.
func (p *Pending) writeDeclaration(w *writer, d declaration) error {
	key := observationKey(d.proxy, d.tool)
	last, written := w.own[key]
	if written && !d.declared.SeenAt.After(last.SeenAt) {
		return nil
	}
	charge := !d.approved && !written
	if charge && w.unapproved[d.proxy] >= p.limits.MaxUnapprovedPerProxy {
		return nil
	}
	dir := path.Join(encodeName(d.proxy), "latest", encodeName(d.tool))
	if err := p.root.MkdirAll(dir, 0o775); err != nil {
		return err
	}
	data, err := jsonv2.Marshal(d.declared, jsonv2.Deterministic(true))
	if err != nil {
		return err
	}
	// One file per gateway and upstream, so a gateway that moves to another
	// upstream never overwrites what it saw from the previous one.
	if err := p.publish(dir, declarationFile(p.gateway, d.declared.Upstream), data, true); err != nil {
		return err
	}
	// A tool without approval counts against the limit once its file exists.
	if charge {
		w.unapproved[d.proxy]++
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
	written := func() {
		if r.tool != nil {
			p.markReviewed(reviewKey(proxy, r.tool.Tool, r.tool.Fingerprint))
		}
	}
	if _, err := p.root.Stat(path.Join(dir, name)); err == nil {
		written()
		return nil
	}
	if err := p.publish(dir, name, data, false); err != nil {
		return err
	}
	written()
	w.written[proxy]++
	return nil
}

// markReviewed records a review entry that exists. Only the writer adds to
// the set, publishing a new copy each time, so readers never lock.
func (p *Pending) markReviewed(key string) {
	current := *p.reviewed.Load()
	if current[key] {
		return
	}
	next := make(map[string]bool, len(current)+1)
	for k := range current {
		next[k] = true
	}
	next[key] = true
	p.reviewed.Store(&next)
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

// Refresh reads the newest declaration of every tool keep accepts, for the
// policy set with this version, and counts each proxy's review entries. keep
// limits reading to the tools of that set, so declarations of tools no longer
// reviewed cannot crowd out current ones. Files that are not declarations,
// or are larger than one can be, are skipped; if the directory cannot be
// read, the previous declarations are kept, so a failed read cannot release
// a tool another gateway saw change.
func (p *Pending) Refresh(version string, keep func(proxy, tool string) bool) {
	if p.dir == "" || !p.open() {
		return
	}
	latest, counts := map[string]Declared{}, map[string]int{}
	proxies, err := p.readDir(".")
	if err != nil {
		slog.Error("Could not read shared drift declarations", "error", err)
		p.stale()
		return
	}
	for _, encodedProxy := range proxies {
		proxy, ok := decodeName(encodedProxy)
		if !ok {
			continue
		}
		counts[proxy] = p.countEntries(encodedProxy)
		tools, err := p.readDir(path.Join(encodedProxy, "latest"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Error("Could not read shared drift declarations; keeping the previous ones", "error", err)
			p.stale()
			return
		}
		for _, encodedTool := range tools {
			tool, ok := decodeName(encodedTool)
			if !ok || !keep(proxy, tool) {
				continue
			}
			gateways, err := p.readDir(path.Join(encodedProxy, "latest", encodedTool))
			if err != nil {
				slog.Error("Could not read shared drift declarations; keeping the previous ones", "error", err)
				p.stale()
				return
			}
			if len(gateways) > maxGatewaysPerTool {
				// Reading only some could miss the newest; calls under drift
				// review wait until the files are pruned.
				slog.Error("Too many shared drift declarations for one tool; prune those of retired gateways", "proxy", proxy, "tool", tool, "files", len(gateways))
				p.stale()
				return
			}
			for _, file := range gateways {
				var d Declared
				switch err := p.readJSON(path.Join(encodedProxy, "latest", encodedTool, file), &d); {
				case errors.Is(err, errNotDeclaration):
					continue
				case err != nil:
					slog.Error("Could not read a shared drift declaration; keeping the previous ones", "error", err)
					p.stale()
					return
				}
				if d.Fingerprint != "" && !fingerprintPattern.MatchString(d.Fingerprint) {
					continue
				}
				key := declarationKey(proxy, tool, d.Upstream)
				if newest, ok := latest[key]; !ok || d.SeenAt.After(newest.SeenAt) {
					latest[key] = d
				}
			}
		}
	}
	p.latest.Store(&sharedSnapshot{version: version, declared: latest})
	p.counts.Store(&entryCounts{generation: p.counts.Load().generation + 1, byProxy: counts})
}

// stale keeps the previous declarations but marks them as read for no set,
// so calls under drift review are refused until a read succeeds; a
// declaration recorded since could otherwise go unenforced.
func (p *Pending) stale() {
	previous := p.latest.Load()
	p.latest.Store(&sharedSnapshot{declared: previous.declared})
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

// errNotDeclaration marks a file that is too large or not JSON, which no
// gateway wrote, as opposed to one that could not be read.
var errNotDeclaration = errors.New("not a declaration")

func (p *Pending) readJSON(name string, v any) error {
	f, err := p.root.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxDeclarationFile+1))
	if err != nil {
		return err
	}
	if len(data) > maxDeclarationFile || jsonv2.Unmarshal(data, v) != nil {
		return errNotDeclaration
	}
	return nil
}
