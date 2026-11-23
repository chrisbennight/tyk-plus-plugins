package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/cedar-policy/cedar-go"
	jsonv2 "github.com/go-json-experiment/json"
)

type caller struct {
	Issuer  string   `json:"issuer"`
	Subject string   `json:"subject"`
	Roles   []string `json:"roles"`
	Groups  []string `json:"groups"`
	Scopes  []string `json:"scopes"`
}

func stringsSet(items []string) cedar.Set {
	values := make([]cedar.Value, 0, len(items))
	for _, item := range items {
		values = append(values, cedar.String(item))
	}
	return cedar.NewSet(values...)
}

type scalarFacts map[string][]cedar.Value

func (f scalarFacts) add(kind, name string, value cedar.Value) {
	f[kind] = append(f[kind], cedar.NewRecord(cedar.RecordMap{"name": cedar.String(name), "value": value}))
}

func (f scalarFacts) fields() cedar.RecordMap {
	return cedar.RecordMap{"strings": cedar.NewSet(f["string"]...), "numbers": cedar.NewSet(f["long"]...), "flags": cedar.NewSet(f["boolean"]...)}
}

func argumentFacts(selected map[string]string, raw json.RawMessage) (cedar.Record, error) {
	var args map[string]json.RawMessage
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return cedar.Record{}, err
		}
	}
	sets := scalarFacts{}
	for name, kind := range selected {
		data, exists := args[name]
		if !exists {
			continue
		}
		var v cedar.Value
		switch kind {
		case "string":
			var s *string
			if json.Unmarshal(data, &s) != nil || s == nil {
				return cedar.Record{}, fmt.Errorf("expected string")
			}
			v = cedar.String(*s)
		case "boolean":
			var b *bool
			if json.Unmarshal(data, &b) != nil || b == nil {
				return cedar.Record{}, fmt.Errorf("expected boolean")
			}
			v = cedar.Boolean(*b)
		case "long":
			var n *int64
			if json.Unmarshal(data, &n) != nil || n == nil {
				return cedar.Record{}, fmt.Errorf("expected integer")
			}
			v = cedar.Long(*n)
		}
		sets.add(kind, name, v)
	}
	return cedar.NewRecord(sets.fields()), nil
}

func (s *snapshot) decide(who caller, proxy, upstream, name string, args json.RawMessage) (string, []string) {
	inv, exists := s.tools[proxy]
	if exists && upstream != inv.Upstream {
		return "unreviewed_upstream", nil
	}
	t, ok := inv.Tools[name]
	if !ok {
		return "unknown_tool", nil
	}
	facts, err := argumentFacts(t.Arguments, args)
	if err != nil {
		return "invalid_argument", nil
	}
	// Tuple encoding keeps issuer/subject and proxy/tool identifiers unambiguous.
	principalID, _ := json.Marshal([2]string{who.Issuer, who.Subject})
	toolID, _ := json.Marshal([2]string{proxy, name})
	principal := cedar.NewEntityUID("Caller", cedar.String(principalID))
	resource := cedar.NewEntityUID("Tool", cedar.String(toolID))
	annotations := scalarFacts(nil).fields()
	if t.Definition != nil {
		annotations = t.Definition.facts
	}
	callerFacts := cedar.RecordMap{
		"issuer": cedar.String(who.Issuer), "subject": cedar.String(who.Subject),
		"roles": stringsSet(who.Roles), "groups": stringsSet(who.Groups), "scopes": stringsSet(who.Scopes),
	}
	toolFacts := cedar.RecordMap{
		"proxy": cedar.String(proxy), "upstream": cedar.String(upstream), "name": cedar.String(name),
		"reviewed": t.reviewed, "upstreamAnnotations": cedar.NewRecord(annotations),
	}
	entities := cedar.EntityMap{
		principal: {UID: principal, Attributes: cedar.NewRecord(callerFacts)},
		resource:  {UID: resource, Attributes: cedar.NewRecord(toolFacts)},
	}
	req := cedar.Request{Principal: principal, Action: cedar.NewEntityUID("Action", "tools/call"), Resource: resource, Context: facts}
	outcome, ids := s.evaluate(entities, req)
	if outcome == "permitted" && t.Definition != nil && len(t.Definition.Annotations) > 0 {
		// An upstream hint may narrow access. Permission must be justified
		// by trusted facts even if the upstream supplies no annotations.
		attrs := entities[resource].Attributes.Map()
		attrs["upstreamAnnotations"] = cedar.NewRecord(scalarFacts(nil).fields())
		entities[resource] = cedar.Entity{UID: resource, Attributes: cedar.NewRecord(attrs)}
		baseline, baselineIDs := s.evaluate(entities, req)
		if baseline != "permitted" {
			return baseline, baselineIDs
		}
		ids = append(ids, baselineIDs...)
		slices.Sort(ids)
		return baseline, slices.Compact(ids)
	}
	return outcome, ids
}

func (s *snapshot) evaluate(entities cedar.EntityMap, req cedar.Request) (string, []string) {
	decision, diag := cedar.Authorize(s.policies, entities, req)
	var ids []string
	for _, reason := range diag.Reasons {
		ids = append(ids, string(reason.PolicyID))
	}
	outcome := "policy_denied"
	if decision == cedar.Allow {
		outcome = "permitted"
	}
	for _, failure := range diag.Errors {
		if s.policies.Get(failure.PolicyID).Effect() == cedar.Forbid {
			if outcome == "permitted" {
				ids = nil
			}
			outcome = "forbid_error"
			ids = append(ids, string(failure.PolicyID))
		}
	}
	slices.Sort(ids)
	return outcome, ids
}

func Authorize(w http.ResponseWriter, r *http.Request) {
	if ctx.GetMCPMethod(r) != "tools/call" {
		return
	}
	name := ctx.GetMCPPrimitiveName(r)
	var who caller
	if session := ctx.GetSession(r); session != nil {
		data, err := json.Marshal(session.MetaData["cedar"])
		if err == nil {
			if err = json.Unmarshal(data, &who); err != nil {
				who = caller{}
			}
		}
	}
	oas := ctx.GetOASDefinition(r)
	state := current()
	var call struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	// Match the MCP ingress limit in the pinned Tyk gateway.
	const maxBody = 1 << 20
	body, readErr := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	r.Body = io.NopCloser(bytes.NewReader(body))
	validBody := readErr == nil && len(body) <= maxBody && jsonv2.Unmarshal(body, &call) == nil
	var rules []string
	version, reason := "", "unavailable"
	if state != nil {
		version = state.version
	}
	switch {
	case state == nil:
	case who.Issuer == "" || who.Subject == "":
		reason = "invalid_caller_metadata"
	case oas == nil || oas.GetTykExtension() == nil:
		reason = "missing_proxy"
	default:
		reason = "invalid_call"
		if validBody && call.Method == "tools/call" && call.Params.Name == name {
			reason, rules = state.decide(who, oas.GetTykExtension().Info.ID, oas.GetTykExtension().Upstream.URL, name, call.Params.Arguments)
		}
	}
	slog.Info("Cedar authorization", "issuer", who.Issuer, "subject", who.Subject, "tool", name, "allowed", reason == "permitted", "reason", reason, "policy_version", version, "rules", rules)
	if reason == "permitted" {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "error": map[string]any{"code": -32002, "message": "Tool call denied"}})
}

func main() {}
