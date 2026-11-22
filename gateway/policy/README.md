# Authorize MCP tool calls

Set `MCP_UPSTREAM_URL` to the Streamable HTTP endpoint reachable from the gateway container. The configured proxy ID is `governed`. Tyk authenticates callers using its API keys and removes the key before forwarding requests.

Give each caller a Tyk key with access to `governed`. Set the following metadata on the key when provisioning it through Tyk’s control API. Use the verified issuer and subject from your identity source. Roles, groups, and scopes are arrays of strings.

```json
{"meta_data":{"cedar":{"issuer":"company","subject":"support-user","roles":["support"]}}}
```

Add reviewed tools to [tools.json](tools.json), keyed by proxy ID and exact upstream tool name. The initial inventory is empty. A new or unreviewed tool is denied even if the caller has a broad permit.

```json
{
  "governed": {
    "lookup": {"readOnly": true, "risk": "low"},
    "update": {"readOnly": false, "arguments": {"count": "long"},
               "upstreamAnnotations": {"readOnlyHint": true}}
  }
}
```

The operator sets `readOnly` and `risk`. Copy an upstream’s declared `readOnlyHint` into `upstreamAnnotations` when that fact matters to a rule. It can restrict an otherwise permitted call. The supplied [rules](rules.cedar) permit support to invoke reviewed read-only tools and operators to invoke reviewed tools.

Cedar sees the caller as `principal`, the tool as `resource`, and the MCP method as `action`. For selected top-level arguments, use `context.strings`, `context.numbers`, and `context.flags` for `string`, `long`, and `boolean` values. For example, `context.numbers.contains({name: "count", value: 2})` matches a submitted integer. See the [policy schema](../cedar/schema.cedarschema).

CI builds the gateway and checks policy behavior through the MCP endpoint. To deploy a tested change, rebuild the image or mount your policy directory at `/opt/tyk-gateway/cedar` and replace a file by atomic rename. Use an image rollout for coordinated changes to both files. The next tool call validates changed configuration. A rejected change preserves the running process’s last valid configuration. With no valid configuration, tool calls are denied. Gateway logs record the decision, caller, tool, policy version, and determining rule IDs.
