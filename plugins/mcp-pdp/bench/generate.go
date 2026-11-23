// Package bench measures how fast a policy set compiles and decides tool
// calls. It can measure a published set or a synthetic deployment generated
// from a seed, so results are reproducible and comparable across changes.
package bench

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"
	"strings"

	"github.com/chrisbennight/tyk-plus-plugins/plugins/mcp-pdp/policy"
)

// Sizes controls the shape of a synthetic deployment and of the request mix.
type Sizes struct {
	Proxies       int
	ToolsPerProxy int
	Callers       int
	Rules         int
	Requests      int
	// PermitRatio is the target share of measured requests that are permitted.
	PermitRatio float64
}

// DefaultSizes describes a mid-sized deployment.
var DefaultSizes = Sizes{Proxies: 5, ToolsPerProxy: 40, Callers: 1000, Rules: 500, Requests: 20000, PermitRatio: 0.5}

// Vocabulary holds the names callers, tools, and rules draw from. Popular
// names are drawn more often, as real role and team names are.
type Vocabulary struct {
	issuers, subjects, roles, groups, scopes []string
}

func names(prefix string, count int) []string {
	out := make([]string, count)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%d", prefix, i)
	}
	return out
}

// skewed picks from items with a Zipf distribution, so early items dominate.
type skewed struct {
	rng  *rand.Rand
	zipf map[int]*rand.Zipf
}

func (s *skewed) index(count int) int {
	if count <= 1 {
		return 0
	}
	z, ok := s.zipf[count]
	if !ok {
		z = rand.NewZipf(s.rng, 1.2, 1, uint64(count-1))
		s.zipf[count] = z
	}
	return int(z.Uint64())
}

func (s *skewed) pick(items []string) string { return items[s.index(len(items))] }

func (s *skewed) some(items []string, low, high int) []string {
	if len(items) == 0 {
		return nil
	}
	count := low + s.rng.Intn(high-low+1)
	seen := map[string]bool{}
	var out []string
	for range count {
		if item := s.pick(items); !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

var (
	teams    = names("team", 16)
	tags     = names("tag", 40)
	risks    = []string{"low", "medium", "high"}
	argNames = names("arg", 8)
)

// argKind gives each argument name a fixed type, as a real tool schema would.
func argKind(name string) string {
	var i int
	fmt.Sscanf(name, "arg-%d", &i)
	return [...]string{"string", "long", "boolean"}[i%3]
}

type toolSpec struct {
	Facts      map[string]any    `json:"facts,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	Arguments  map[string]string `json:"arguments,omitempty"`
	Definition map[string]any    `json:"definition,omitempty"`
}

// Synthetic generates a deployment: proxies and reviewed tools with mixed
// facts, tags, arguments, and upstream annotations; then rules drawn from
// varied templates over that deployment. It returns the policy files and the
// vocabulary that callers are built from.
func Synthetic(seed int64, sizes Sizes) (rules, tools []byte, vocab Vocabulary) {
	s := &skewed{rng: rand.New(rand.NewSource(seed)), zipf: map[int]*rand.Zipf{}}
	vocab = Vocabulary{
		issuers: names("https://idp", 2), subjects: names("user", max(sizes.Callers, 1)),
		roles: names("role", 24), groups: names("group", 60), scopes: names("scope", 12),
	}
	inventory := map[string]any{}
	type ref struct{ proxy, name string }
	var refs []ref
	for p := range sizes.Proxies {
		proxy := fmt.Sprintf("proxy-%d", p)
		specs := map[string]toolSpec{}
		for t := range sizes.ToolsPerProxy {
			name := fmt.Sprintf("tool-%d", t)
			spec := toolSpec{
				Facts: map[string]any{"readOnly": s.rng.Intn(2) == 0, "team": s.pick(teams),
					"risk": risks[s.rng.Intn(len(risks))], "tier": int64(1 + s.rng.Intn(5))},
				Tags: s.some(tags, 0, 3),
			}
			for i := range s.rng.Intn(3) {
				spec.Facts[fmt.Sprintf("custom-%d", i)] = s.rng.Intn(100)
			}
			if args := s.some(argNames, 0, 3); len(args) > 0 {
				spec.Arguments = map[string]string{}
				for _, a := range args {
					spec.Arguments[a] = argKind(a)
				}
			}
			if s.rng.Intn(10) < 3 {
				spec.Definition = map[string]any{"name": name, "annotations": map[string]any{
					"readOnlyHint": s.rng.Intn(2) == 0, "vendor.batchSafe": s.rng.Intn(2) == 0}}
			}
			specs[name] = spec
			refs = append(refs, ref{proxy, name})
		}
		inventory[proxy] = map[string]any{"upstream": fmt.Sprintf("https://%s.example/mcp", proxy), "tools": specs}
	}
	tools, _ = json.Marshal(inventory)

	// Each template is a different shape of rule seen in practice: role and
	// group grants, per-tool grants, fact and tag matches, argument
	// constraints, individual grants, exceptions, and forbids.
	templates := []func() string{
		func() string {
			return fmt.Sprintf(`permit (principal, action == Action::"tools/call", resource) when { principal.roles.contains(%q) && resource.reviewed.flags.contains({name: "readOnly", value: true}) };`, s.pick(vocab.roles))
		},
		func() string {
			return fmt.Sprintf(`permit (principal, action, resource) when { principal.groups.contains(%q) && resource.reviewed.tags.contains(%q) };`, s.pick(vocab.groups), s.pick(tags))
		},
		func() string {
			r := refs[s.index(len(refs))]
			return fmt.Sprintf(`permit (principal, action, resource) when { principal.roles.contains(%q) && resource.proxy == %q && resource.name == %q };`, s.pick(vocab.roles), r.proxy, r.name)
		},
		func() string {
			return fmt.Sprintf(`permit (principal, action, resource) when { principal.roles.contains(%q) && resource.reviewed.strings.contains({name: "team", value: %q}) };`, s.pick(vocab.roles), s.pick(teams))
		},
		func() string {
			return fmt.Sprintf(`permit (principal, action, resource) when { principal.scopes.contains(%q) && context.numbers.contains({name: "arg-1", value: %d}) };`, s.pick(vocab.scopes), s.rng.Intn(10))
		},
		func() string {
			return fmt.Sprintf(`permit (principal, action, resource) when { principal.issuer == %q && principal.subject == %q };`, s.pick(vocab.issuers), s.pick(vocab.subjects))
		},
		func() string {
			return fmt.Sprintf(`permit (principal, action, resource) when { resource.upstreamAnnotations has readOnlyHint && resource.upstreamAnnotations.readOnlyHint && principal.roles.contains(%q) };`, s.pick(vocab.roles))
		},
		func() string {
			return fmt.Sprintf(`permit (principal, action, resource) when { principal.roles.containsAny([%q, %q]) && resource.reviewed.numbers.contains({name: "tier", value: %d}) } unless { principal.groups.contains(%q) };`, s.pick(vocab.roles), s.pick(vocab.roles), 1+s.rng.Intn(5), s.pick(vocab.groups))
		},
		func() string {
			return fmt.Sprintf(`forbid (principal, action, resource) when { resource.reviewed.strings.contains({name: "risk", value: "high"}) && !principal.roles.contains(%q) };`, s.pick(vocab.roles))
		},
		func() string {
			return fmt.Sprintf(`forbid (principal, action, resource) when { context.flags.contains({name: "arg-2", value: true}) && !principal.scopes.contains(%q) };`, s.pick(vocab.scopes))
		},
	}
	var b strings.Builder
	for i := range sizes.Rules {
		// Forbids are rarer than permits, as in most real policies.
		t := s.rng.Intn(len(templates) - 2)
		if s.rng.Intn(10) == 0 {
			t = len(templates) - 2 + s.rng.Intn(2)
		}
		fmt.Fprintf(&b, "@id(\"rule-%d\")\n%s\n", i, templates[t]())
	}
	return []byte(b.String()), tools, vocab
}

var literal = regexp.MustCompile(`principal\.(roles|groups|scopes)\.contains\("((?:[^"\\]|\\.)*)"\)|principal\.(issuer|subject) == "((?:[^"\\]|\\.)*)"`)

// Harvest builds a caller Vocabulary from the names an existing set's rules
// mention, so generated callers can match those rules. Kinds the rules never
// mention fall back to generic names.
func Harvest(rules []byte, callers int) Vocabulary {
	found := map[string][]string{}
	seen := map[string]bool{}
	for _, m := range literal.FindAllStringSubmatch(string(rules), -1) {
		kind, value := m[1], m[2]
		if kind == "" {
			kind, value = m[3]+"s", m[4]
		}
		if !seen[kind+"\x00"+value] {
			seen[kind+"\x00"+value] = true
			found[kind] = append(found[kind], value)
		}
	}
	or := func(kind string, fallback []string) []string {
		if len(found[kind]) > 0 {
			return found[kind]
		}
		return fallback
	}
	return Vocabulary{
		issuers: or("issuers", names("https://idp", 2)), subjects: or("subjects", names("user", max(callers, 1))),
		roles: or("roles", names("role", 24)), groups: or("groups", names("group", 60)), scopes: or("scopes", names("scope", 12)),
	}
}

func (v Vocabulary) callers(s *skewed, count int) []policy.Caller {
	out := make([]policy.Caller, max(count, 1))
	for i := range out {
		out[i] = policy.Caller{
			Issuer: s.pick(v.issuers), Subject: v.subjects[i%len(v.subjects)],
			Roles: s.some(v.roles, 1, 3), Groups: s.some(v.groups, 0, 4), Scopes: s.some(v.scopes, 0, 3),
		}
	}
	return out
}

// Request is one tool call to decide.
type Request struct {
	Caller    policy.Caller
	Tool      policy.ToolRef
	Arguments json.RawMessage
}

func arguments(s *skewed, declared map[string]string) json.RawMessage {
	args := map[string]any{}
	for name, kind := range declared {
		if s.rng.Intn(5) == 0 {
			continue
		}
		switch kind {
		case "string":
			args[name] = fmt.Sprintf("v%d", s.rng.Intn(10))
		case "long":
			args[name] = s.rng.Intn(10)
		case "boolean":
			args[name] = s.rng.Intn(2) == 0
		}
	}
	data, _ := json.Marshal(args)
	return data
}

// Requests draws calls with popular callers and tools favored, then selects
// them so that the target share is permitted. If the set cannot produce
// enough of one outcome, the actual share is lower or higher than the target.
func Requests(seed int64, snapshot *policy.Snapshot, vocab Vocabulary, sizes Sizes) []Request {
	s := &skewed{rng: rand.New(rand.NewSource(seed + 1)), zipf: map[int]*rand.Zipf{}}
	tools := snapshot.Tools()
	if len(tools) == 0 || sizes.Requests <= 0 {
		return nil
	}
	callers := vocab.callers(s, sizes.Callers)
	wantPermit := int(float64(sizes.Requests)*sizes.PermitRatio + 0.5)
	wantDeny := sizes.Requests - wantPermit
	var permitted, other []Request
	for attempt := 0; attempt < 20*sizes.Requests && (len(permitted) < wantPermit || len(other) < wantDeny); attempt++ {
		t := tools[s.index(len(tools))]
		r := Request{Caller: callers[s.index(len(callers))], Tool: t, Arguments: arguments(s, t.Arguments)}
		if outcome, _ := snapshot.Decide(r.Caller, t.Proxy, t.Upstream, t.Name, r.Arguments); outcome == "permitted" {
			if len(permitted) < wantPermit {
				permitted = append(permitted, r)
			}
		} else if len(other) < wantDeny {
			other = append(other, r)
		}
	}
	out := append(permitted, other...)
	// Fill any shortfall from the outcome the set does produce.
	for i := 0; len(out) < sizes.Requests && len(out) > 0; i++ {
		out = append(out, out[i])
	}
	s.rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}
