# Examples

A complete local deployment for trying the gateway's authorization and for checking other gateways, MCP servers and MCP clients against a known-good reference:

- the gateway, with one proxy per mock server;
- an example policy;
- four mock MCP servers written with FastMCP;
- a token issuer and a deck of example people;
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
- the mock servers `directory`, `payments`, `notes` and `older`;
- `policy`, which publishes the example policy set into the gateway's store and exits.

The runner checks every row of [`expected.json`](expected.json) with clients of both supported protocol versions. It confirms what the client sees, whether the call reached the server, and that each client used the protocol version it should. It ends by printing how many checks passed and failed, and exits non-zero on any failure.

The gateway listens on `127.0.0.1:8080` (`GATEWAY_PORT`) and the issuer on `127.0.0.1:8090` (`ISSUER_PORT`). Stop everything with `docker compose down -v`.

To start only some parts, name them, for example `docker compose up -d notes` or `docker compose up -d gateway directory`.

## What each server shows

Each server is behind its own proxy at `http://127.0.0.1:8080/<server>/`. The `why` field of each row in `expected.json` explains its outcome.

| Server | Tools | What it shows |
| --- | --- | --- |
| `directory` | `search`, `get_person` (declared read-only); `update_person`, `export_directory` (declared as writing); `delete_person` (declared destructive) | Honest declarations. Analysts read, administrators also write, and deletion is reserved to one service. The operator recorded `export_directory` as read-only by mistake. The upstream says it writes, and that narrows access. |
| `payments` | `get_balance`, `refund(amount, environment)`, `transfer(amount, environment)` | Rules on arguments. Analysts may refund only in `test`; nobody, administrators included, moves money in `production`. The same caller is permitted one tool and refused another. An argument of the wrong type is refused. |
| `notes` | `search` (no annotations); `purge` (claims read-only but deletes); `export` (described only by `_meta`); `archive` (never approved) | Missing or false declarations. No annotation gives no read-only access, and a false claim grants nothing. `_meta` counts only once an operator records it as facts. A tool that was never approved is refused like one that does not exist. A scope grants `search`. |
| `older` | The `directory` tools on FastMCP 2, which speaks only protocol `2025-11-25`, with sessions and streamed replies | A newer client falls back to the older protocol. |

Every server reports, outside MCP at `GET /requests`, how many MCP requests it received and the last call's arguments. It also refuses any request that still carries a caller's credential.

## Callers

| Caller | Credential | Identity |
| --- | --- | --- |
| `analyst` | Token | Role `analyst` |
| `admin` | Token | Role `admin` |
| `finance` | Token | Group `finance`, no role |
| `scoped` | Token | Scope `notes:read` only |
| `indexer` | Key | Role `analyst` |
| `deployer` | Key | Role `admin` |

- **People** are in the issuer's deck, [`callers/people.json`](callers/people.json). See the [issuer guide](issuer/README.md).
- **Services** are Tyk keys whose metadata is in [`callers/keys.json`](callers/keys.json). The runner creates the keys through Tyk's control API.
- **Refused callers.** The runner also checks seven callers that must be refused: no credential, an expired token, a token for another audience, a token without a subject, a token signed with an unpublished key, a token whose roles claim has the wrong shape, and a key without metadata. Each must fail to connect in both protocol versions and be refused on the methods a client sends first, with no request reaching a server. Those methods are `initialize`, `notifications/initialized`, `server/discover`, `tools/list` and `tools/call`.
- **Every refusal looks the same.** Every refused tool call must return the same JSON-RPC error, so a caller cannot tell a tool it may not call from one that was never approved or does not exist.
- **Key and token together.** A request carrying both a key and a token is identified by the key. Two cases show it: a strong key with a weak token is permitted, and a weak key with a strong token is refused.

## Policy

[`policy/`](policy) is the example policy set: [rules](policy/rules.cedar), [approved tools](policy/approved_tools.json), approved instructions and activation checks. The [policy guide](../gateway/policy/README.md) explains the format.

The approved tool definitions are copied from each server's `tools/list`.

The activation checks are generated from `expected.json`. The gateway rejects a policy set whose checks fail, and the runner refuses to run while the committed checks differ from `expected.json`, so the policy the gateway enforces always agrees with the expected outcomes. After changing `expected.json`, regenerate the checks and publish again:

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

1. Each server lists its tools.
2. A permitted call works. For example, `indexer` searches the directory.
3. A refused call is reported. Both clients show a refusal as an error from the server, not as a failed tool result: Claude Code shows the server's reply, containing `-32002` and `Tool call denied`, and Codex shows `Mcp error: -32002: Tool call denied`.
4. The two callers differ. For example, `deployer` may delete a person and `indexer` may not.

## Swap a part

| To check | Do this |
| --- | --- |
| Another gateway | Configure it with an equivalent policy. Run the runner against it with `GATEWAY_URL`, and set `EXAMPLE_INDEXER_KEY` and `EXAMPLE_DEPLOYER_KEY` to credentials your gateway accepts for those callers, and `EXAMPLE_KEY_WITHOUT_METADATA_KEY` to a key it recognizes that carries no identity. `expected.json` states every outcome without naming Cedar. |
| Another MCP server | Replace a mock server's service in `compose.yaml` and point that proxy's API definition in `gateway/apps/` at it. In `policy/approved_tools.json`, set that proxy's `upstream` to the same URL and approve the new server's tools; the gateway refuses every call while the two URLs differ. |
| Another MCP client | Connect it to `http://127.0.0.1:8080/<server>/` with a key in `X-API-Key` or a token in `Authorization: Bearer`, and compare what it shows with `expected.json`. |
