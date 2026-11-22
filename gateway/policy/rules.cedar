@id("support-read")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("support") && resource.reviewed.readOnly };

@id("operator-call")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("operator") };
