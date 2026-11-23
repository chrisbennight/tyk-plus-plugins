@id("support-read")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("support") && resource.reviewed.readOnly };

@id("operator-call")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("operator") };

@id("operator-required-for-changes")
forbid (principal, action == Action::"tools/call", resource)
when { !resource.reviewed.readOnly && !principal.roles.contains("operator") };
