package policy

import (
	"encoding/json"
	"slices"
)

// ApprovedTool is one approved tool on a proxy. Definition is the upstream
// definition the operator approved, or nil when the set approves the tool
// without one.
type ApprovedTool struct {
	Name       string
	Definition json.RawMessage
}

// ReviewedUpstream returns the upstream URL a proxy's approved tools were
// reviewed for, or "" when the set has none for the proxy.
func (s *Snapshot) ReviewedUpstream(proxy string) string {
	return s.tools[proxy].Upstream
}

// ApprovedTools lists a proxy's approved tools in name order, with the
// upstream URL they were reviewed for.
func (s *Snapshot) ApprovedTools(proxy string) (upstream string, tools []ApprovedTool) {
	inv, ok := s.tools[proxy]
	if !ok {
		return "", nil
	}
	for name, t := range inv.Tools {
		var definition json.RawMessage
		if t.Definition != nil {
			definition = t.Definition.raw
		}
		tools = append(tools, ApprovedTool{Name: name, Definition: definition})
	}
	slices.SortFunc(tools, func(a, b ApprovedTool) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	return inv.Upstream, tools
}
