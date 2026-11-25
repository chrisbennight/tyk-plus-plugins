// Example rules. They illustrate one convention for the example servers and
// are not a default: the gateway ships with no rules.

// Analysts may call tools an operator has reviewed and marked read-only.
@id("analyst-read")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("analyst") && resource.reviewed.flags.contains({name: "readOnly", value: true}) };

// Administrators may call any approved tool, subject to the forbids below.
@id("admin-call")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("admin") };

// Analysts may run Code Mode programs. Each call a program makes is still
// decided by the analyst's own rules, so a program grants nothing more.
@id("analyst-code-mode")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("analyst") && resource.name like "codemode.*" };

// Members of the finance group may call payment tools.
@id("finance-payments")
permit (principal, action == Action::"tools/call", resource)
when { principal.groups.contains("finance") && resource.reviewed.tags.contains("payments") };

// A caller holding the notes:read scope may search notes.
@id("scoped-notes-search")
permit (principal, action == Action::"tools/call", resource)
when { principal.scopes.contains("notes:read") && resource.proxy == "notes" && resource.name == "search" };

// Analysts may issue refunds, but only in the test environment.
@id("analyst-test-refunds")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("analyst") && resource.name == "refund" && context.strings.contains({name: "environment", value: "test"}) };

// The indexing service may export; it is the only key caller without the
// admin role that may. Administrators may too, through admin-call.
@id("indexer-export")
permit (principal, action == Action::"tools/call", resource)
when { principal.issuer == "examples" && principal.subject == "indexer" && resource.reviewed.tags.contains("export") };

// Nobody moves money in production through the gateway, administrators included.
@id("no-production-payments")
forbid (principal, action == Action::"tools/call", resource)
when { resource.reviewed.tags.contains("payments") && context.strings.contains({name: "environment", value: "production"}) };

// Destructive tools are reserved to the deployment service.
@id("destructive-reserved")
forbid (principal, action == Action::"tools/call", resource)
when { resource.reviewed.tags.contains("destructive") && !(principal.issuer == "examples" && principal.subject == "deployer") };

// When an operator recorded a tool as read-only but the upstream declares that
// it writes, only administrators may call it until someone resolves the
// disagreement. An upstream annotation can narrow access; it never grants it.
@id("upstream-disagrees-read-only")
forbid (principal, action == Action::"tools/call", resource)
when {
  resource.reviewed.flags.contains({name: "readOnly", value: true}) &&
  resource.upstreamAnnotations has readOnlyHint && resource.upstreamAnnotations.readOnlyHint == false &&
  !principal.roles.contains("admin")
};
