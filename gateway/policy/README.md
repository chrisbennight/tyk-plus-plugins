# Authorize MCP tool calls

Set `MCP_UPSTREAM_URL` to the Streamable HTTP endpoint reachable from the gateway container. The configured proxy ID is `governed`. Tyk authenticates callers using its API keys and removes the key before forwarding requests.

**The gateway ships with no rules, an empty tool inventory, and no activation checks, so it denies every tool call.** Access exists only after you add a tool to the inventory and write a rule that permits calling it. The plug-in has no built-in user types or rules.

## Callers

Give each caller a Tyk key with access to `governed`. Set the following metadata on the key when provisioning it through Tyk’s control API. Use the verified issuer and subject from your identity source. Roles, groups, and scopes are arrays of strings whose names you choose.

```json
{"meta_data":{"cedar":{"issuer":"company","subject":"jane","roles":["analyst"]}}}
```

## Tools and reviewed facts

Add reviewed tools to [tools.json](tools.json), keyed by proxy ID and exact upstream tool name. A tool that is not in the inventory is denied even if a rule broadly permits access.

```json
{
  "governed": {
    "upstream": "https://mcp.company.example/mcp",
    "tools": {
      "lookup": {"facts": {"readOnly": true, "team": "billing", "tier": 1}, "tags": ["directory"]},
      "update": {"arguments": {"count": "long"},
                 "definition": {"name": "update", "annotations": {"readOnlyHint": true}}}
    }
  }
}
```

Set `upstream` to the exact `MCP_UPSTREAM_URL` reviewed for this proxy. Changing that URL requires reviewing the replacement upstream’s tools.

Every field of a tool entry is optional:

- `facts` records what you have reviewed about the tool. You choose the names. Values are strings, booleans, or signed 64-bit integers. Any other value rejects the inventory. Rules see them as `resource.reviewed.strings`, `.numbers`, and `.flags`, for example `resource.reviewed.flags.contains({name: "readOnly", value: true})`.
- `tags` is a list of names you choose. Rules see it as `resource.reviewed.tags`, for example `resource.reviewed.tags.contains("directory")`.
- `arguments` selects top-level call arguments for rules, typed `string`, `long`, or `boolean`. Rules see them as `context.strings`, `context.numbers`, and `context.flags`, for example `context.numbers.contains({name: "count", value: 2})`.
- `definition` is the upstream’s tool object copied from `tools/list` during review. Rules can match its annotations through `resource.upstreamAnnotations.strings`, `.numbers`, and `.flags`, and the direct `readOnlyHint` field. Nested values, nulls, and non-integer numbers are omitted. Upstream annotations can only restrict an otherwise permitted call.

A fact or tag that a tool does not have contributes nothing to a rule. Write rules so that a missing fact cannot grant access.

## Rules

Write Cedar rules in [rules.cedar](rules.cedar). Cedar sees the caller as `principal`, the tool as `resource`, and the MCP method as `action`. See the [policy schema](../../plugins/mcp-pdp/schema.cedarschema). A call needs a matching permit, an explicit forbid takes precedence, and a forbid that errors during evaluation blocks the call.

The following rules illustrate one convention, not a default. Callers with an `analyst` role may call tools you marked read-only, callers with an `admin` role may call any reviewed tool, and a forbid reserves every other tool for admins even if another rule broadly permits access.

```cedar
@id("analyst-read")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("analyst") && resource.reviewed.flags.contains({name: "readOnly", value: true}) };

@id("admin-call")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("admin") };

@id("admin-required-for-changes")
forbid (principal, action == Action::"tools/call", resource)
when { !resource.reviewed.flags.contains({name: "readOnly", value: true}) && !principal.roles.contains("admin") };
```

## Activation checks

[Activation checks](checks.json) are optional. Each check specifies the caller, proxy, upstream URL, tool, optional arguments, and expected decision, `permitted` or `policy_denied`. A candidate configuration whose checks do not all pass is rejected. To test rules without publishing a tool, give a check a `hypotheticalTool` with its own `facts`, `tags`, and `arguments`. Without one, the check uses the real inventory entry.

```json
[{"caller": {"issuer": "company", "subject": "jane", "roles": ["analyst"]},
  "proxy": "governed", "upstream": "https://mcp.company.example/mcp", "tool": "update",
  "hypotheticalTool": {}, "expect": "policy_denied"}]
```

## Deploying changes

The policy directory must contain `rules.cedar`, `tools.json`, and `checks.json`. A missing file makes the configuration unreadable. When you have no rules, tools, or checks, use an empty `rules.cedar`, `{}`, and `[]` respectively.

CI builds the gateway and checks policy behavior through the MCP endpoint. To deploy a tested change, rebuild the image or mount your policy directory at `/opt/tyk-gateway/cedar` and replace a file by atomic rename. Use an image rollout for coordinated changes to multiple files. The next tool call validates changed configuration. A rejected change preserves the running process’s last valid configuration. With no valid configuration, tool calls are denied. Gateway logs record the decision, caller, tool, reason, policy version, and determining rule IDs.
