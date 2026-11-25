package policy

import (
	"encoding/json"
	"fmt"
	"slices"
)

// driftSettings is a proxy's optional drift configuration in
// approved_tools.json. Drift enforcement applies to a proxy once this object
// exists, so adopting an upstream is an explicit, reviewed step.
type driftSettings struct {
	// ChangedTools is "hide" (the default) or "serve-approved": whether a tool
	// whose upstream definition changed is left out of lists or shown with
	// its approved definition. Calls to it are refused either way.
	ChangedTools string `json:"changedTools"`
	// ChangedInstructions is "replace" (the default) or "strip".
	ChangedInstructions string `json:"changedInstructions"`
	// RejectedTools lists, by tool name, upstream definitions a reviewer has
	// rejected, so they are not raised for review again.
	RejectedTools map[string][]string `json:"rejectedTools"`
	// RejectedInstructions lists rejected upstream instructions.
	RejectedInstructions []string `json:"rejectedInstructions"`
}

func (d *driftSettings) validate(proxy string) error {
	switch d.ChangedTools {
	case "":
		d.ChangedTools = "hide"
	case "hide", "serve-approved":
	default:
		return fmt.Errorf("proxy %q: changedTools must be hide or serve-approved", proxy)
	}
	switch d.ChangedInstructions {
	case "":
		d.ChangedInstructions = "replace"
	case "replace", "strip":
	default:
		return fmt.Errorf("proxy %q: changedInstructions must be replace or strip", proxy)
	}
	for name, fingerprints := range d.RejectedTools {
		if name == "" {
			return fmt.Errorf("proxy %q: rejected tools need a name", proxy)
		}
		for _, fp := range fingerprints {
			if !fingerprintPattern.MatchString(fp) {
				return fmt.Errorf("proxy %q: rejected definition of %q is not a fingerprint", proxy, name)
			}
		}
	}
	for _, fp := range d.RejectedInstructions {
		if !fingerprintPattern.MatchString(fp) {
			return fmt.Errorf("proxy %q: rejected instructions entry is not a fingerprint", proxy)
		}
	}
	return nil
}

// DriftView is what a gateway needs to enforce drift review on one proxy.
type DriftView struct {
	settings *driftSettings
	upstream string
	tools    map[string]*tool
}

// Drift returns the drift view of a proxy and whether drift enforcement
// applies to it.
func (s *Snapshot) Drift(proxy string) (DriftView, bool) {
	inv, ok := s.tools[proxy]
	if !ok || inv.Drift == nil {
		return DriftView{}, false
	}
	return DriftView{settings: inv.Drift, upstream: inv.Upstream, tools: inv.Tools}, true
}

// DriftProxies returns, sorted, the proxies under drift review.
func (s *Snapshot) DriftProxies() []string {
	var proxies []string
	for proxy, inv := range s.tools {
		if inv.Drift != nil {
			proxies = append(proxies, proxy)
		}
	}
	slices.Sort(proxies)
	return proxies
}

// ApprovedTools returns, sorted, the tools with an approved definition.
func (v DriftView) ApprovedTools() []string {
	var names []string
	for name, t := range v.tools {
		if t.Definition != nil {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// Approved returns a tool's approved definition and its fingerprint. A tool
// without an approved definition is not approved, even if listed.
func (v DriftView) Approved(name string) (fingerprint string, definition json.RawMessage, ok bool) {
	t := v.tools[name]
	if t == nil || t.Definition == nil {
		return "", nil, false
	}
	return t.Definition.fingerprint, t.Definition.raw, true
}

// Upstream is the upstream URL the proxy's tools were reviewed for. Another
// upstream's declarations say nothing about those tools.
func (v DriftView) Upstream() string { return v.upstream }

// Rejected reports whether a reviewer rejected this definition of a tool.
func (v DriftView) Rejected(name, fingerprint string) bool {
	return slices.Contains(v.settings.RejectedTools[name], fingerprint)
}

// Has reports whether the set reviews a tool, approved or not.
func (v DriftView) Has(name string) bool {
	_, ok := v.tools[name]
	return ok
}

// RejectedInstructions reports whether a reviewer rejected these
// instructions, by fingerprint.
func (v DriftView) RejectedInstructions(fingerprint string) bool {
	return slices.Contains(v.settings.RejectedInstructions, fingerprint)
}

// StripInstructions reports whether changed instructions are removed rather
// than replaced with the approved text.
func (v DriftView) StripInstructions() bool { return v.settings.ChangedInstructions == "strip" }

// ServeApproved reports whether a changed tool is shown with its approved
// definition rather than hidden.
func (v DriftView) ServeApproved() bool { return v.settings.ChangedTools == "serve-approved" }
