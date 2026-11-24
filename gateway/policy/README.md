# Authorize MCP tool calls

Set `MCP_UPSTREAM_URL` to the Streamable HTTP endpoint reachable from the gateway container. The configured proxy ID is `governed`. Tyk authenticates each caller with either a token or a key, and removes the credential before forwarding requests.

**The gateway ships with no rules, an empty tool inventory, and no activation checks, so it denies every tool call.** Access exists only after you add a tool to the inventory and write a rule that permits calling it. The plug-in has no built-in user types or rules.

## Callers

A caller presents one of two credentials. The gateway tries the key first, then the token.

| Caller | Credential | Identity Cedar sees |
| --- | --- | --- |
| A person signed in through your identity provider | `Authorization: Bearer <token>` | The token's claims |
| A service account | `X-API-Key: <key>` | Metadata on the Tyk key |

The first credential Tyk accepts identifies the caller. A request with a valid key is identified by that key even if it also carries a token. When a token identifies the caller, its claims are the whole identity; key metadata never adds to or replaces them. Tyk removes both credential headers before forwarding the request. When moving a client from a key to a token, remove its key header: if Tyk rejects the key before accepting the token, the request reaches the gateway's checks without its body, so a tool call is denied and other requests fail at the upstream.

Cedar decides which tools every caller may use. Do not give Tyk keys or policies per-tool MCP access rights, because tool access is controlled through Cedar alone.

### Tokens

Tyk verifies the token's signature against your identity provider's published keys, then checks its issuer, audience, and expiry. Set these variables on the gateway:

| Variable | Meaning |
| --- | --- |
| `MCP_TOKEN_JWKS_URL` | The identity provider's JSON Web Key Set URL. Use `https://`: the gateway trusts whatever keys this URL returns, so the connection must be authenticated. Tokens must be signed with RSA. |
| `MCP_TOKEN_ISSUER` | The exact `iss` value of accepted tokens. |
| `MCP_TOKEN_AUDIENCE` | An `aud` value that accepted tokens must contain. |

Leave all three unset to accept keys only. The gateway then refuses every token.

The caller's issuer and subject come from the `iss` and `sub` claims. A token without both, or without an `exp` expiry, cannot identify a caller, and the gateway refuses every request made with it. Roles, groups, and scopes come from the claims named by these variables:

| Variable | Default |
| --- | --- |
| `CEDAR_ROLES_CLAIM` | `roles` |
| `CEDAR_GROUPS_CLAIM` | `groups` |
| `CEDAR_SCOPES_CLAIM` | `scope` |

Each claim may be a list of strings or one space-separated string. Set a variable to an empty value to ignore that claim. A claim of any other shape denies the call. Use top-level claim names; configure your identity provider to place nested values in a top-level claim.

Every token caller receives access to `governed` through the Tyk policy in [`governed-tokens.json`](../policies/governed-tokens.json). That policy sets no rate limit or quota. Change it if you want Tyk to limit token callers.

A token stays valid until it expires, even after the person is disabled in your identity provider. Issue short-lived tokens so that access ends soon after a person is removed.

### Keys

Give each service account a Tyk key with access to `governed`. Set the following metadata on the key when provisioning it through Tyk's control API. The gateway refuses every request made with a key that lacks an issuer and subject. Roles, groups, and scopes are arrays of strings whose names you choose. Deleting the key revokes access immediately.

```json
{"meta_data":{"cedar":{"issuer":"company","subject":"indexer","roles":["analyst"]}}}
```

## Tools and reviewed facts

Add approved tools to [approved_tools.json](approved_tools.json), keyed by proxy ID and exact upstream tool name. A tool that is not in the inventory is denied even if a rule broadly permits access.

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

Write Cedar rules in [rules.cedar](rules.cedar). Cedar sees the caller as `principal`, the tool as `resource`, and the MCP method as `action`. See the [policy schema](../../plugins/mcp-pdp/policy/schema.cedarschema). A call needs a matching permit, an explicit forbid takes precedence, and a forbid that errors during evaluation blocks the call.

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

[Activation checks](checks.json) are optional, but add representative permit and deny cases for your own rules so that a change which alters those decisions is rejected before it takes effect. Each check specifies the caller, proxy, upstream URL, tool, optional arguments, and expected decision, `permitted` or `policy_denied`. A candidate configuration whose checks do not all pass is rejected. To test rules without publishing a tool, give a check a `hypotheticalTool` with its own `facts`, `tags`, and `arguments`. Without one, the check uses the real inventory entry.

```json
[{"caller": {"issuer": "company", "subject": "jane", "roles": ["analyst"]},
  "proxy": "governed", "upstream": "https://mcp.company.example/mcp", "tool": "update",
  "hypotheticalTool": {}, "expect": "policy_denied"}]
```

## Approved instructions

[approved_instructions.json](approved_instructions.json) records, for each proxy, the server instructions an operator has approved, as a string. An empty string is an approved value meaning "no instructions". The file is optional when publishing; without it, no instructions are approved.

```json
{"governed": "Use lookup to find records before changing them."}
```

## Deploying changes

A policy set is the files above published together: `rules.cedar`, `approved_tools.json`, `approved_instructions.json` and `checks.json`. They take effect as a whole or not at all, so a rule and the tools it depends on never go live separately. When you have no rules, tools, instructions or checks, use an empty `rules.cedar`, `{}`, `{}` and `[]` respectively.

Each approved tool definition has a fingerprint: the SHA-256 of its RFC 8785 canonical JSON, ignoring the top-level `_meta` member. Field order, whitespace and different spellings of the same number (`1`, `1.0`, `1e0`) don't change it; any other change does. A set whose definitions repeat a key is rejected. In a format-2 set, rules see each upstream annotation as its canonical value, the same text the fingerprint covers, so two definitions with one fingerprint always produce the same facts. Format-1 sets read annotations as written, exactly as before.

### The policy store

The gateway reads a policy store at `/opt/tyk-gateway/cedar`:

- `sets/<fingerprint>/` holds each published set: its policy files and a `manifest.json` recording the set's format and the files' SHA-256 hashes. The fingerprint is derived from those hashes, so a set's name identifies its content. Sets are never modified after publication.
- `active` is a small JSON file naming the set gateways should enforce, the set it replaced, and when it was promoted.

The image ships a store whose active set is the empty policy in this directory. To manage policy at run time, mount your own store at `/opt/tyk-gateway/cedar`.

### Upgrading key callers

Earlier builds read keys from the `Authorization` header. Keys now go in `X-API-Key`, and `Authorization` carries tokens only. Update clients that use keys before upgrading; a key sent in `Authorization` is refused. Every request now needs an identifiable caller, including `initialize` and `tools/list`, so give every key `cedar` metadata with an issuer and subject before upgrading.

### Upgrading to approved tools

Earlier builds published sets with `tools.json` instead of `approved_tools.json` and no approved instructions (format 1). Gateways still enforce those sets, so nothing breaks on upgrade. `cedar-policy promote` accepts a directory in either layout and always publishes the current format, so rename `tools.json` to `approved_tools.json` in your policy source when convenient. A directory containing both is refused as ambiguous.

Upgrade every gateway that shares a store before publishing with the new `cedar-policy`, because it always publishes format 2 and older gateways cannot read it. Until upgraded, an older gateway treats a format-2 set as not ready: if it is running, it keeps enforcing its current set; if it restarts, it has no valid set and denies every tool call. To roll back while older gateways remain, activate the previous format-1 set with `cedar-policy activate`.

Format-1 sets load exactly as before. Only format-2 sets require each approved definition to have a fingerprint, so a definition that cannot be canonicalized, for example one with a number outside the range of a 64-bit float, is refused when converting to format 2 rather than when loading an older set.

### Upgrading from the three-file layout

Earlier builds read `rules.cedar`, `tools.json`, and `checks.json` directly from `/opt/tyk-gateway/cedar`. If you mount a directory containing only those files there, convert it before upgrading: run `cedar-policy promote -store <new store> <old directory>` and mount the new store instead. A gateway that finds no `active` pointer denies every call and reports the pointer as unreadable.

### Promoting and rolling back

Use the `cedar-policy` command, which is included in the image at `/opt/tyk-gateway/bin/cedar-policy`. It validates with the same code the gateway runs, so a set it activates is one the gateway accepts.

```sh
cedar-policy promote -store /path/to/store -label "add billing tools" ./my-policy
cedar-policy show -store /path/to/store
cedar-policy activate -store /path/to/store <previous fingerprint>
```

`promote` validates the policy files in a directory, stores them as a set, and switches `active` to it. A set keeps the label it was first published with. A set that fails validation, including any activation check, is not activated. `activate` validates an existing set again and switches to it, which is how you roll back to the set `active` records as previous. Every change to the store, publishing a set or switching `active`, happens under a lock on the store, so concurrent publishers cannot interleave and the recorded previous set is the one actually replaced. Each switch replaces `active` by atomic rename. Published files and directories take their permissions from the store directory, so set its permissions so the gateway's user can read it; `promote` creates a new store directory readable by all users. `activate` also repairs an unreadable `active` file.

### What the gateway does

The gateway reads `active` every `CEDAR_REFRESH_INTERVAL`, a Go duration that defaults to `5s`, and validates a newly named set in the background. A change takes effect after the next check finishes validating it, normally within about one interval, and tool calls never wait for the check or the validation.

- A set whose files do not match its manifest is treated as not ready, for example while it is still being copied. The gateway keeps its current set and checks again.
- A set that fails validation is rejected, and the gateway keeps enforcing its last good set.
- `active` only moves to a set that passed validation, so after a restart the gateway enforces the same last good set. If `active` names a set the gateway rejects, for example after a manual edit, calls are denied and the status report shows the rejection. The gateway never falls back to an older set on its own, because an older set could grant access a later set revoked. Roll back with `cedar-policy activate`.
- With no valid set, tool calls are denied.

Set `CEDAR_STATUS_FILE` to have each gateway write a JSON report of the set it is enforcing, the set `active` names, and the outcome of its last evaluation: `activated`, `rejected`, `not_ready`, or `unreadable`. Comparing `enforcing` with `active` shows whether a gateway has caught up. The Compose deployment writes it to `/opt/tyk-gateway/cedar-status/status.json`.

Gateway logs record each decision with the caller, whether a token or a key identified them, the tool, the reason, the fingerprint and label of the enforced set, and determining rule IDs. CI builds the gateway and checks policy behavior through the MCP endpoint, including after a restart with no valid set. Unit tests run under the Go race detector and check that decisions never wait for a set being validated or swapped in.

## Measuring performance

`cedar-policy bench` measures how long a policy set takes to compile, which the gateway does on every change, and how long it takes to decide one tool call. Run it on demand. It does not start a gateway or change the store.

```sh
cedar-policy bench -synthetic
cedar-policy bench -synthetic -rules 5000 -tools 100 -seed 7 -format json
cedar-policy bench -store /path/to/store
```

`-synthetic` generates a deployment from `-seed`, so the same seed and sizes give the same set and request mix. Proxies carry reviewed tools with a mix of facts, tags, argument types, and upstream annotations. Callers hold skewed sets of roles, groups, and scopes. Rules are drawn from varied shapes: role and group grants, grants for one tool, fact, tag, and argument matches, grants to one subject, exceptions, and forbids. `-proxies`, `-tools`, `-rules`, `-callers`, and `-requests` set the sizes.

`-store` measures the store's active set. Its requests use the set's reviewed tools. Generated callers and argument values favor the string and integer values the set's rules mention, so requests can match the rules.

In both modes, popular callers and tools are requested more often, and requests are chosen so that the share set by `-permit-ratio` is permitted when the set allows it. The report gives the median, 99th percentile, and maximum time for compiling and for each decision, the count of each outcome, the memory the compiled set holds, the memory each decision allocates, and the process's peak resident memory, along with the seed, the set's fingerprint, and the Go and cedar-go versions. A synthetic set's fingerprint changes whenever its content does, so compare results that share one. `-format json` prints the same report as JSON for tracking over time. Timings depend on the machine, so compare results from the same machine. CI runs the synthetic benchmark and prints the results; it does not yet fail on any threshold.
