# Examples

A complete local deployment for trying the gateway's authorization and for checking other gateways, MCP servers and MCP clients against a known-good reference:

- the gateway, with one proxy per mock server;
- an example policy;
- five mock MCP servers written with FastMCP;
- a token issuer and a deck of example people;
- a Code Mode sandbox host;
- a runner that checks every expected outcome;
- configurations for Claude Code and Codex.

**Nothing here is a default.** The gateway image ships with no rules and denies every tool call. The roles, groups, facts and rules below are one example convention.

The examples run only on demand; CI does not run them. They are separate from [`tests/`](../tests). A test may use any part of them, and the test decides which parts to start and stops them afterwards. Every part starts on its own and finds the others only through the URLs in [`compose.yaml`](compose.yaml).

## Run

```sh
cd examples
export TYK_GW_SECRET="$(openssl rand -hex 32)"
export TYK_GW_NODESECRET="$(openssl rand -hex 32)"
docker compose up --build -d
docker compose run --build --rm runner
```

`up` starts these services:

- `gateway`, Redis and the token `issuer`;
- the Code Mode sandbox host, `sandbox` and `sandbox-launcher`, with certificates `sandbox-certs` makes for it;
- the mock servers `directory`, `payments`, `notes`, `older` and `changing`;
- `policy`, which publishes the example policy set into the gateway's store and exits.

The runner checks every row of [`expected.json`](expected.json) with clients of both supported protocol versions. It confirms what the client sees, whether the call reached the server, and that each client used the protocol version it should. It also checks each caller's tool list on each server against `listed`: a caller is shown the approved tools it could call with some arguments, and no others. It runs the Code Mode programs in [Code Mode](#code-mode). It sets `changing` to version 0 first, and at the end walks it through each of its versions, as [Drift](#drift) describes, leaving it at version 0 again. It ends by printing how many checks passed and failed, and exits non-zero on any failure.

Code Mode programs run on a sandbox host that uses gVisor. On a machine where gVisor cannot run, use the development backend instead; it runs the launcher privileged, so use it only on your own machine:

```sh
export SANDBOX_BACKEND=runc COMPOSE_FILE=compose.yaml:../sandbox/compose.runc.yaml
```

The gateway and the sandbox host trust each other through certificates `sandbox-certs` makes, which last a day and are kept until then. Once they have expired, make new ones and restart both with them: `docker compose up -d --force-recreate sandbox-certs gateway sandbox`.

The gateway listens on `127.0.0.1:8080` (`GATEWAY_PORT`) and the issuer on `127.0.0.1:8090` (`ISSUER_PORT`). Stop everything with `docker compose down -v`.

To start only some parts, name them, for example `docker compose up -d notes` or `docker compose up -d gateway directory`. Compose reads every service's settings even when starting one, so set the two secrets first; any values do when the gateway is not among the parts.

## What each server shows

Each server is behind its own proxy at `http://127.0.0.1:8080/<server>/`. The `why` field of each row in `expected.json` explains its outcome.

| Server | Tools | What it shows |
| --- | --- | --- |
| `directory` | `search`, `get_person` (declared read-only); `update_person`, `export_directory` (declared as writing); `delete_person` (declared destructive) | Honest declarations. Analysts read, administrators also write, and deletion is reserved to one service. The operator recorded `export_directory` as read-only by mistake. The upstream says it writes, and that narrows access. |
| `payments` | `get_balance`, `refund(amount, environment)`, `transfer(amount, environment)` | Rules on arguments. Analysts may refund only in `test`; nobody, administrators included, moves money in `production`. The same caller is permitted one tool and refused another. An argument of the wrong type is refused. |
| `notes` | `search` (no annotations); `purge` (claims read-only but deletes); `export` (described only by `_meta`); `archive` (never approved) | Missing or false declarations. No annotation gives no read-only access, and a false claim grants nothing. `_meta` counts only once an operator records it as facts. A tool that was never approved is refused like one that does not exist. A scope grants `search`. |
| `older` | The `directory` tools on FastMCP 2, which speaks only protocol `2025-11-25`, with sessions and streamed replies | A newer client falls back to the older protocol. |
| `changing` | `lookup` (read-only), `update` (writes) and `report` (read-only), and server instructions, at version 0 | Drift. The server can switch to versions that change what it declares; see [Drift](#drift). |

Every server reports, outside MCP at `GET /requests`, how many MCP POST requests it received (the streams clients open for notifications are not counted), how many tool calls it ran, and the last call's arguments. It also refuses any request that still carries a caller's credential.

## Code Mode

Code Mode is on for `directory`, `payments` and `notes`. A caller may run programs when a rule grants it the Code Mode tools: here administrators, through their grant of every tool, and analysts, through `analyst-code-mode`. Those callers see the four Code Mode tools in their tool lists on those proxies.

A program's tool calls go back through the gateway as the caller who ran it, so each call gets exactly the outcome the caller's direct call gets. The `codeMode` section of `expected.json` lists programs whose calls span two servers. Each call repeats a row of `calls` for the same caller, and the runner checks that permitted calls run on their server and refused ones are refused exactly as direct calls are, without reaching it. A caller no rule grants Code Mode is refused `codemode.execute` itself.

For example, an analyst's program:

```js
const balance = await connectors.payments.get_balance({ account: "ops" });
const people = await connectors.directory.search({ query: "ada" });
return [balance.content[0].text, people.content[0].text];
```

See the [Code Mode guide](../gateway/code-mode.md) for writing programs and the limits.

## Drift

Every proxy is under drift review, and `changing` exists to show it. The example policy approves what `changing` declares at version 0. Each other version changes one thing:

| Version | What changes | What a client sees |
| --- | --- | --- |
| 1 | `lookup`'s description gains text addressed to the model | `lookup` is hidden and refused until the change is approved |
| 2 | `lookup`'s description gains an invisible character and a look-alike letter | The same; the review writes both out |
| 3 | `lookup` gains a parameter | The same |
| 4 | `update` now claims to be read-only | `update` is hidden and refused; the review shows the annotation change |
| 5 | A new tool, `delete`, appears | `delete` is hidden and refused as new |
| 6 | `report` is no longer listed | `report` is missing; the other tools are unaffected. Nothing waits for review, since a tool the upstream stops listing needs no approval |
| 7 | `report` is renamed `summary` | `summary` is hidden and refused as new |
| 8 | Only the server instructions change | The approved instructions are still given |
| 9 | Only `lookup`'s `_meta` changes | Nothing; `_meta` is not part of a definition |
| 10 | `lookup`'s description gains different text | Held separately from version 1's change |
| 0 | Back to the approved version | Every tool works again. The earlier changes stay in the review queue until a reviewer rejects them |

Each switch tells connected clients that the tool list changed, in both protocol versions: on `subscriptions/listen` streams for `2026-07-28` clients, and on the session stream for `2025-11-25` clients. Clients that connect later see the change at once. Set `CHANGING_VERSION` before `docker compose up` to start the server at a later version, so drift is visible on first connect.

The `drift` section of `expected.json` states what the `deployer` caller sees at each version, and the runner checks it.

### Walk through a review

Connect a client to `changing` as described in [Connect Claude Code or Codex](#connect-claude-code-or-codex), then:

```sh
docker compose run --rm runner version 2   # lookup's description gains hidden characters
```

The client is told the tool list changed. Ask it to list the tools on `changing` again: `lookup` is gone, and the gateway, having seen the change, queues it for review. A change waits for review only once the gateway has seen it in a tool list.

```sh
docker compose run --rm review             # list what waits for review
```

`review` runs `cedar-policy drift` against the gateway's store and its queue of changes; with no arguments it lists the queue. Show the change with its labelled diff, which writes out the invisible and look-alike characters, then approve or reject it by the fingerprint the list printed:

```sh
docker compose run --rm review show -store /store -pending /pending -proxy changing -tool lookup FINGERPRINT
docker compose run --rm review reject -store /store -pending /pending -proxy changing -tool lookup FINGERPRINT
docker compose run --rm runner version 0   # back to the approved tools
```

Approving a change makes a new policy set active, so the runner's expectations no longer hold until you publish the example policy again with `docker compose up -d --force-recreate policy gateway`. The [policy guide](../gateway/policy/README.md#reviewing-changes) describes every review command. The runner's own walk leaves its changes in the queue, waiting for review; `docker compose down -v` starts afresh.

## Callers

| Caller | Credential | Identity |
| --- | --- | --- |
| `analyst` | Token | Role `analyst` |
| `admin` | Token | Role `admin` |
| `finance` | Token | Group `finance`, no role |
| `scoped` | Token | Scopes `notes:read payments:read`, as one space-separated string, and no role |
| `indexer` | Key | Role `analyst` |
| `deployer` | Key | Role `admin` |

- **People** are in the issuer's deck, [`callers/people.json`](callers/people.json). See the [issuer guide](issuer/README.md).
- **Services** are Tyk keys whose metadata is in [`callers/keys.json`](callers/keys.json). The runner creates the keys through Tyk's control API.
- **Refused callers.** The runner also checks seven callers that must be refused: no credential, an expired token, a token for another audience, a token without a subject, a token signed with an unpublished key, a token whose roles claim has the wrong shape, and a key without metadata. On every proxy, each must fail to connect in both protocol versions and be refused on the methods a client sends first, with no request reaching a server. Those methods are `initialize`, `notifications/initialized`, `server/discover`, `tools/list` and `tools/call`.
- **Every refusal looks the same.** Every refused tool call must return the same JSON-RPC error, so a caller cannot tell a tool it may not call from one that was never approved or does not exist.
- **Key and token together.** A request carrying both a key and a token is identified by the key. Two cases show it: a strong key with a weak token is permitted, and a weak key with a strong token is refused.

## Policy

[`policy/`](policy) is the example policy set: [rules](policy/rules.cedar), [approved tools](policy/approved_tools.json), approved instructions and activation checks. The [policy guide](../gateway/policy/README.md) explains the format.

Every proxy is under drift review, so clients see only the approved tool definitions, and each caller sees only the tools it could call. A tool that was never approved, such as `notes.archive`, is neither listed nor callable. The approved tool definitions are copied exactly from each server's `tools/list`; a tool whose definition differs from what the server declares is hidden, and its calls are refused once the gateway has seen the difference in a tool list, until the new definition is approved or the server declares the approved one again. A tool's top-level `_meta` is not part of its definition, and clients are given the approved one.

The activation checks are generated from `expected.json`. The gateway rejects a policy set whose checks fail, and the runner refuses to run while the committed checks differ from `expected.json`. Regenerate the checks whenever you change `expected.json` or the approved tools, so the published policy is checked against the current expectations. After changing `expected.json`, regenerate the checks and publish again:

```sh
docker compose run --build --rm runner checks > checks.new && mv checks.new policy/checks.json
docker compose up -d --force-recreate policy gateway
```

Argument rules match exact values only, such as an environment name. A rule cannot compare an argument with a limit, such as a refund under 100, because the policy sees arguments as sets of name and value pairs.

## Connect Claude Code or Codex

Print credentials for every example caller into your shell. Tokens expire after an hour; run it again for fresh ones. The runner prints only values made of token and key characters, each quoted, so the output is safe to `eval`.

```sh
eval "$(docker compose run --build --rm runner env)"
```

The configurations name two callers with different access side by side, so the difference is visible:

| Client | Key callers (default) | Token callers |
| --- | --- | --- |
| Claude Code | [`clients/claude-code/.mcp.json`](clients/claude-code/.mcp.json) | [`clients/claude-code/tokens.mcp.json`](clients/claude-code/tokens.mcp.json) |
| Codex | [`clients/codex/config.toml`](clients/codex/config.toml) | [`clients/codex/tokens.config.toml`](clients/codex/tokens.config.toml) |

**Claude Code.** Run `claude --mcp-config clients/claude-code/.mcp.json` from this directory. The servers in a project `.mcp.json` wait for approval in an interactive session; `--mcp-config` loads the file without it. Values such as `${EXAMPLE_INDEXER_KEY}` are read from the environment.

**Codex.** Copy the tables into `~/.codex/config.toml`. Codex reads a project's `.codex/config.toml` only when you trust the project. `env_http_headers` and `bearer_token_env_var` name environment variables; the files never hold a credential.

Check in each client:

1. Each server lists only the tools that caller may call. For example, `indexer` sees `search` and `get_person` on `directory`, and `deployer` also sees the tools that change records.
2. A permitted call works. For example, `indexer` searches the directory.
3. A refused call is reported. Both clients show a refusal as an error from the server, not as a failed tool result: Claude Code shows the server's reply, containing `-32002` and `Tool call denied`, and Codex shows `Mcp error: -32002: Tool call denied`.
4. The two callers differ. For example, `deployer` may delete a person and `indexer` may not.
5. A held tool disappears. Run `docker compose run --rm runner version 1`: the client is told the tool list changed, and `lookup` is no longer listed on `changing`. `docker compose run --rm runner version 0` brings it back.

## Swap a part

| To check | Do this |
| --- | --- |
| Another gateway | Configure it with an equivalent policy. Run the runner against it with `GATEWAY_URL`, and set `EXAMPLE_INDEXER_KEY` and `EXAMPLE_DEPLOYER_KEY` to credentials your gateway accepts for those callers, and `EXAMPLE_KEY_WITHOUT_METADATA_KEY` to a key it recognizes that carries no identity. `expected.json` states every outcome without naming Cedar. |
| Another MCP server | Replace a mock server's service in `compose.yaml` and point that proxy's API definition in `gateway/apps/` at it. In `policy/approved_tools.json`, set that proxy's `upstream` to the same URL and approve the new server's tools, copying each definition exactly from its `tools/list`; the gateway refuses every call while the two URLs differ, and hides any tool whose definition differs. The runner also reads each mock's `GET /requests` report to see what arrived, and switches `changing` through `POST /version`, so to use the runner, the replacement must serve the same report, and a replacement for `changing` the same versions; otherwise check it with a client. |
| Another MCP client | Connect it to `http://127.0.0.1:8080/<server>/` with a key in `X-API-Key` or a token in `Authorization: Bearer`, and compare what it shows with `expected.json`. |
