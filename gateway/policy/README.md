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

Add approved tools to [approved_tools.json](approved_tools.json), keyed by proxy ID and exact upstream tool name. A tool that is not in the inventory is denied even if a rule broadly permits access. The exceptions are [Code Mode](#code-mode) tools, which the plug-in answers itself.

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

### Argument names

Arguments are matched by their exact names. The gateway passes the client's request to the upstream unchanged, and some upstreams, such as Go servers built on `encoding/json`, match names regardless of letter case. So a tool call is refused, and logged with the reason `ambiguous_call`, when an upstream could read it differently from the gateway:

- two top-level argument names are equal apart from letter case, such as `environment` and `Environment`. This applies to every argument, declared or not, so a tool that genuinely takes both `id` and `Id` cannot be called through the gateway;
- an argument name equals a declared argument apart from letter case, such as `Environment` alone when `environment` is declared;
- an argument name contains a control character, such as a trailing `\u0000`;
- a member of the request or of its `params` equals one the gateway reads apart from letter case, such as `Params` or `Arguments`.

Letter case is compared as Go's `strings.EqualFold` compares it, so `ſ` matches `s` and the Kelvin sign matches `k`.

An argument the call does not send is not a fact, so **a forbid that tests an argument's value does not apply when the argument is missing**. An upstream that supplies a default for a missing argument may act on a value your rules never saw. Instead of only forbidding the unsafe value, permit only the safe one, for example `context.strings.contains({name: "environment", value: "test"})`, or make sure the approved tool definition's `inputSchema` requires the argument and the upstream enforces it.

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

### Code Mode

[Code Mode](../code-mode.md) adds tools the plug-in answers itself: `codemode.search`, `codemode.describe`, `codemode.limits` and `codemode.execute`. A caller is listed, and may call, only those its rules permit. Rules grant them as they grant any tool, by name, proxy or caller. They ship with the plug-in rather than an upstream, so they have no reviewed facts, tags or upstream annotations, and their arguments are never facts.

That means a forbid on tools without some reviewed fact also forbids Code Mode tools. The example above reserves every tool not marked read-only for admins, so to let analysts run programs, leave Code Mode tools out of that forbid by name:

```cedar
@id("admin-required-for-changes")
forbid (principal, action == Action::"tools/call", resource)
when { !resource.reviewed.flags.contains({name: "readOnly", value: true}) && !principal.roles.contains("admin") && !(resource.name like "codemode.*") };

@id("analyst-code-mode")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("analyst") && resource.name like "codemode.*" };
```

Every tool a program calls is still decided by the caller's own rules, so running a program never grants a call the caller could not make directly.

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

## Drift review

An upstream can change a tool's definition after you reviewed it, for example to add instructions to its description. Drift review makes the gateway pass on only the definitions you approved. It applies to a proxy once its entry in `approved_tools.json` has a `drift` object, so turning it on is a reviewed step:

```json
{
  "governed": {
    "upstream": "https://mcp.company.example/mcp",
    "drift": {"changedTools": "hide"},
    "tools": {
      "lookup": {"definition": {"name": "lookup", "description": "Find a record", "inputSchema": {"type": "object"}}}
    }
  }
}
```

Under drift review:

- A tool is approved when its entry has a `definition`. A tool without one is treated as not approved.
- `tools/list` replies, plain or streamed, contain only tools whose upstream definition has the same fingerprint as the approved one, and those tools are sent as their approved definition, so a top-level `_meta` member is the approved one too. Tools the upstream added and tools without an approved definition are left out. Each tool is listed at most once, and a reply that declares one tool with conflicting definitions counts as a changed definition.
- A caller's list leaves out tools that Cedar shows no arguments could ever let that caller call, so its model does not spend context on them. A test that reads the call's arguments counts as either true or false, while tests on the caller and tool still decide wherever they appear in `&&`, `||`, `!` or `if`, so a permit limited to one role that way never shows its tool to anyone else. A caller or tool test inside any other expression that also reads arguments, such as a comparison of the two, makes the whole expression unclear, and the tool is shown; write role limits with `&&` to keep them exact. A permit counts if some arguments could make it apply, and a forbid only if every set of arguments would, so a tool some arguments could let the caller call is never hidden. For a tool that declares no arguments, the list matches the call decision exactly. Upstream annotations can only hide a tool, as they can only narrow a call. Each tool is checked as a call to it would be, and results are kept per caller until the policy set changes; `cedar-policy bench` reports first-list and cached-list times. Calls are still decided exactly, so a shown tool may refuse particular arguments.
- `changedTools` decides what happens to an approved tool whose upstream definition changed: `hide` (the default) leaves it out of lists, and `serve-approved` lists the approved definition instead of the upstream's. Either way, calls to it are refused until you approve the new definition or the upstream returns to the approved one.
- A call to a tool that is not approved, or whose upstream last listed a different definition, is refused with the same reply as any other denied call, before rules are evaluated.
- Activation checks apply the same rule: a check that expects a permit for a tool without an approved definition rejects the set, and one that expects a denial passes.
- Each gateway compares calls with the definitions it last saw in a `tools/list` reply, including definitions of tools that were not approved when listed, so approving a definition the upstream no longer declares does not let calls through. Until a gateway has seen a tool in a list, it checks calls to it against approval alone.
- New and changed tool definitions, and changed instructions, wait for review in `<proxy>/tools/<tool>/<fingerprint>.json` and `<proxy>/instructions/<fingerprint>.json`, once per fingerprint, with the full definition or text, when it was first seen and on which gateway. Rejected definitions and instructions are not written. A proxy holds at most `CEDAR_PENDING_MAX_PER_PROXY` entries, give or take what several gateways write between refreshes, and a definition larger than `CEDAR_PENDING_MAX_DEFINITION_BYTES` is not written. Proxy, tool and gateway names in these paths are base64url-encoded. Gateways write from the background, so the request path never touches the directory; a write dropped because its queue is full is made by the next list. Instructions an upstream stopped declaring are queued as empty instructions.
- A `tools/list` reply that cannot be checked, such as a compressed or unreadable one, or any reply while the gateway has no valid set, is replaced with a JSON-RPC error. Checked replies carry `Cache-Control: private, no-cache` and no upstream `ETag`, because they depend on your approvals as well as the upstream. A streamed list that was already open when drift review started on its proxy ends at that point, and the client lists again through the check. A checked stream ends after the reply that answers the request and carries no event IDs, so a client cannot resume it on a request the gateway does not check; it lists again instead, and a reply to any other request is replaced with an error answering this one. While the proxy targets an upstream other than the one in `approved_tools.json`, its lists are replaced with an error and its instructions are removed, as its calls are refused.
- Server instructions in `initialize` and `server/discover` replies pass on only when they are the text in `approved_instructions.json` for the proxy. `changedInstructions` decides what happens otherwise: `replace` (the default) sends the approved text instead, and `strip` removes the instructions. With no approved text, or an empty one, the instructions are removed. The rest of the reply passes unchanged, and a `server/discover` reply whose instructions were changed is marked `cacheScope: private` with a `ttlMs` of at most one minute, so clients ask again soon after you approve the new text. Replies that cannot be checked are handled as for lists, except that while the gateway has no valid set the instructions are removed, so sessions can still start.

Two settings bound the work of checking lists:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CEDAR_PENDING_MAX_DEFINITION_BYTES` | `262144` | The largest upstream tool definition the gateway fingerprints. A larger one counts as a changed definition, so raise this if you approve larger definitions. |
| `CEDAR_PENDING_MAX_PER_PROXY` | `200` | How many tools without approval each gateway remembers per proxy, and how many review entries a proxy holds in the drift review directory. Once a proxy passes the limit, or declares a tool name longer than 128 bytes, a call to a tool the gateway has not seen listed is refused until a list shows it. |

The `drift` object also accepts `rejectedTools` (tool names mapped to lists of rejected definition fingerprints) and `rejectedInstructions` (a list of fingerprints). Gateways do not queue a rejected definition or rejected instructions for review again, and calls to a rejected definition stay refused.

### Sharing sightings between gateways

Gateways that share the directory in `CEDAR_PENDING_DIR` (the Compose file sets it to `/opt/tyk-gateway/cedar-pending`, which the image provides writable by the gateway's user; give it a volume every gateway can write) also share what they see:

- Each gateway writes the definition it last saw an upstream declare for each tool, by fingerprint, with when it received it and from which upstream, to its own file `<proxy>/latest/<tool>/<gateway>.<upstream>.json`. A definition that cannot be identified is shared as one that matches no approval, and tools without approval are shared up to `CEDAR_PENDING_MAX_PER_PROXY`. The upstream in a file name is a short hash of its URL.
- Every gateway reads, each refresh interval, the declarations of the tools its active set reviews, and decides calls on the newest of its own and the shared ones from the reviewed upstream; declarations from other upstreams are kept apart. A new set's shared declarations are read before it becomes active. A gateway's own sightings are kept per upstream too, so a sighting from a previous upstream is never taken for the reviewed one. A gateway decides from its own records, which order its replies as it received them, and uses its own files only for tools it holds no record of, as after a restart.
- A change one gateway sees is refused by all within their refresh interval, and seeing the approved definition again releases it. This holds while every sighting reaches the directory: a sighting dropped because the writer's queue is full, or one that could not be written, is logged, and other gateways follow the previous declaration until the next list is shared. When two replies with different definitions arrive out of order, the gateway that saw them refuses calls until a later list settles it, while other gateways follow the newer of the two.
- If the directory cannot be opened or read, the previous declarations are kept and calls on proxies under drift review are refused until a later read succeeds, so a failed read never releases a tool another gateway saw change. A declaration file that is not valid, including one whose gateway or upstream does not match its name, also holds calls on proxies under drift review until it is removed. Calls to a tool whose name is longer than 180 bytes, or on a reviewed upstream whose URL is longer than 8 KiB, are refused while sharing is on, since a change to them could not be shared.
- Run every gateway sharing a directory as the same user, as the image does. Gateways that run as different users need a shared group with the setgid bit on the directory, as described for the policy store below, and a umask of `002`, so each can write in directories another created. Keep the clocks of gateways sharing a directory in sync. Each gateway's files are named after `CEDAR_GATEWAY_ID`, or its host name when that is unset. Give every gateway a different, stable name so a gateway keeps one file per tool across restarts: past 256 files for one tool (one per gateway and upstream), calls under drift review are refused until the files of retired gateways are removed with `cedar-policy drift retire`.

### Reviewing changes

Review what gateways queued in the [review dashboard](../../admin/README.md), in a browser, signed in through your identity provider, or on the command line; both use the same code and the same store.

On the command line, `cedar-policy drift` reviews what gateways queued, with the policy store in `-store` and the shared directory in `-pending`:

```sh
cedar-policy drift list -store /path/to/store -pending /path/to/pending
cedar-policy drift show -store /path/to/store -pending /path/to/pending -proxy governed -tool lookup <fingerprint>
cedar-policy drift approve -store /path/to/store -pending /path/to/pending -proxy governed -tool lookup <fingerprint>
cedar-policy drift reject -store /path/to/store -pending /path/to/pending -proxy governed -instructions <fingerprint>
```

- `list` shows, for each proxy under drift review, new and changed tools and changed instructions waiting for review, and approved tools no gateway has seen the upstream declare (`missing`). A waiting definition is `latest` when it is what gateways saw the upstream declare last, and `superseded` when the upstream has changed again since. Entries the active set already approves or rejects are not shown.
- `show` prints one waiting change: a labelled diff against the approved version (description, parameters added or removed, changed types, required parameters, annotations and other fields), then the full definition. Invisible characters, such as zero-width spaces and direction overrides, are written as `⟨U+XXXX⟩`, and a non-ASCII letter in a word that also has ASCII letters is followed by its code point, so a name spelled with a look-alike letter stands out. For a new tool it hints at a likely rename when an approved tool the upstream no longer declares takes the same input or has the same description. An annotation change is flagged so you can revisit the tool's facts.
- `approve` writes exactly the definition or instructions with the given fingerprint into a copy of the active set and makes the copy active, labelled `drift approve …` unless you give `-label`. The entry is checked first: a definition that does not have the fingerprint it is filed under is refused. A definition's top-level `_meta` is not part of its fingerprint, so it is left out of the approved definition. A newer change to the same tool stays waiting. A newly approved tool has no facts, tags or arguments; add them with `cedar-policy promote` if your rules need them.
- `reject` records the fingerprint in the `drift` object of a new active set. The same definition is not queued again; a different one is.
- `revoke -proxy NAME -tool NAME FINGERPRINT` withdraws a tool's approved definition, the one with that fingerprint, in a new active set. Activation checks that expect calls to the tool to be permitted would fail the new set; `-remove-permit-checks` removes them with the approval, logging each removal, and without it the revocation is refused. Gateways then hide the tool and refuse calls to it until a definition is approved again. The tool's facts, tags and arguments stay, ready for the next approval. To approve the same definition again, approve its review entry; if that entry was pruned, a gateway queues the definition again when it restarts.
- `approve-all -proxy NAME` adopts what an upstream declares now, for example when drift review is first turned on with an empty `tools` object: it approves, for each tool, the definition gateways saw the upstream declare last. A tool the upstream has since withdrawn may be adopted too; gateways list only tools the upstream declares, so it reaches clients only if the upstream declares exactly that definition again. Instructions reach clients as text, so they are adopted only while the proxy has no approved instructions and exactly one text is waiting; review other instructions with `show` and approve them with `approve -instructions`. Run it first without `-confirm` to see what it would approve, including the full text of any instructions, then again with `-confirm` set to the code shown. The code stands for that exact list and the set it was made against, so if a gateway queues a different definition or another set becomes active in between, nothing is approved and the new list is shown.
- `prune` removes review entries the active set already approves or rejects, holding the store's lock so no set becomes active meanwhile. Decisions leave entries in place, so rolling back to an earlier set leaves them to review again; settled entries still count towards `CEDAR_PENDING_MAX_PER_PROXY` until pruned. A running gateway queues each tool definition once, so if you roll back after pruning, a tool definition whose entry was pruned is queued again only when a gateway restarts; changed instructions are queued again on the next handshake.
- `retire GATEWAY` removes every declaration file a gateway shared. Use it only for a gateway that will not run again: other gateways would lose a running gateway's sightings until its next tools list.

Each command decides against the set active when it starts and writes its new set under the store's lock. If another set became active in between, nothing is changed and the command asks you to review again, so two reviewers working at once cannot undo each other's decisions. Each one is a new set, so `cedar-policy activate` with the previous fingerprint rolls it back.

Every approval, rejection and revocation, and every roll back made in the [review dashboard](../../admin/README.md), is recorded in `decisions.log` in the store: one JSON line each, with who made it, when, the action, the proxy, tool or instructions, the fingerprint, the set it was made against and the set it made active. The command line records the local user, with the issuer `local`; the dashboard records the operator's verified identity. The line is written under the store's lock before the new set becomes active, so no set is enforced without its record: if the log cannot be written, the decision is not made, and if activation fails after the line is written, the line names a set that never became active.

## Deploying changes

A policy set is the files above published together: `rules.cedar`, `approved_tools.json`, `approved_instructions.json` and `checks.json`. They take effect as a whole or not at all, so a rule and the tools it depends on never go live separately. When you have no rules, tools, instructions or checks, use an empty `rules.cedar`, `{}`, `{}` and `[]` respectively.

Each approved tool definition has a fingerprint: the SHA-256 of its canonical JSON, ignoring the top-level `_meta` member. In the canonical form object keys are sorted, whitespace is removed, and strings are compared by their text rather than their escapes; numbers keep their exact written form, so `1` and `1.0` are different definitions. Any change other than key order, whitespace or string escapes changes the fingerprint. A definition that repeats a key is rejected. Rules read annotation values as written in every format: only an integer spelling is an integer fact, and `null` is never a number.

### The policy store

The gateway reads a policy store at `/opt/tyk-gateway/cedar`:

- `sets/<fingerprint>/` holds each published set: its policy files and a `manifest.json` recording the set's format and the files' SHA-256 hashes. The fingerprint is derived from those hashes, so a set's name identifies its content. Sets are never modified after publication.
- `active` is a small JSON file naming the set gateways should enforce, the set it replaced, and when it was promoted.

The image ships a store whose active set is the empty policy in this directory. To manage policy at run time, mount your own store at `/opt/tyk-gateway/cedar`.

#### Sharing a store between publishers

Several people or services can publish into one store when they share a Unix group. Create the store root owned by that group, group-writable, with the setgid bit, for example `chgrp policy /srv/policy && chmod 2770 /srv/policy`. Everything published inside takes the root's permissions and keeps its group, whatever each publisher's own primary group and umask, and any member can publish, roll back, or repair a set another member published. Give the gateway's user read access through the same group.

These setups are not supported or handled:

- A store root with the sticky bit, such as a directory like `/tmp`. Members could not replace the `active` pointer another member wrote.
- Stores that rely on default access control lists. Publishing sets explicit modes taken from the root, which can override an inherited access control list.
- Leftover `.staging-*` and `.damaged-*` directories inside `sets/` after a publisher crashes. They are never named by `active`, so gateways ignore them, but they are not cleaned up automatically; remove them while no one is publishing.

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

### Upgrading key callers

Earlier builds read keys from the `Authorization` header. Keys now go in `X-API-Key`, and `Authorization` carries tokens only. Update clients that use keys before upgrading; a key sent in `Authorization` is refused. Every request now needs an identifiable caller, including `initialize` and `tools/list`, so give every key `cedar` metadata with an issuer and subject before upgrading.

### Upgrading to approved tools

Earlier builds published sets with `tools.json` instead of `approved_tools.json` and no approved instructions (format 1). Gateways still enforce those sets, so nothing breaks on upgrade. `cedar-policy promote` accepts a directory in either layout and always publishes the current format, so rename `tools.json` to `approved_tools.json` in your policy source when convenient. A directory containing both is refused as ambiguous.

Upgrade every gateway that shares a store before publishing with the new `cedar-policy`, because it always publishes format 2 and older gateways cannot read it. Until upgraded, an older gateway treats a format-2 set as not ready: if it is running, it keeps enforcing its current set; if it restarts, it has no valid set and denies every tool call. To roll back while older gateways remain, activate the previous format-1 set with `cedar-policy activate`.

Format-1 sets load and decide exactly as before, and converting one to format 2 changes no decision: both formats read definitions the same way.

### Upgrading from the three-file layout

Earlier builds read `rules.cedar`, `tools.json`, and `checks.json` directly from `/opt/tyk-gateway/cedar`. If you mount a directory containing only those files there, convert it before upgrading: run `cedar-policy promote -store <new store> <old directory>` and mount the new store instead. A gateway that finds no `active` pointer denies every call and reports the pointer as unreadable.

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
