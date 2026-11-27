# Tyk Plus Plugins

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/branding/assets/header-dark.svg">
  <img src="docs/branding/assets/header-light.svg" width="760" alt="MCP clients connect through Tyk Plus to Cedar policy, drift review, and sandboxed Code Mode.">
</picture>

Tyk Plus Plugins brings policy-based Cedar authorization, upstream drift review, and sandboxed Code Mode to the open-source Tyk Gateway for Model Context Protocol (MCP) traffic, with Docker Compose as the reference deployment.

[Waygate](https://github.com/chrisbennight/waygate) provides working examples of the behavior brought to Tyk here. The [initial capability epic](https://github.com/chrisbennight/tyk-plus-plugins/issues/1) tracks the roadmap.

**[Try the 5-server lab](examples/README.md)** ·
**[Cedar policy & drift guide](gateway/policy/README.md)** ·
**[Drift review dashboard](admin/README.md)** ·
**[Code Mode](gateway/code-mode.md)** ·
**[Sandbox host](sandbox/README.md)** ·
**[Releases](RELEASING.md)**

## Capabilities

### Cedar authorization

The gateway ships with no rules, an empty tool inventory, and no activation checks, so it denies every tool call until you write a rule in [`rules.cedar`](gateway/policy/README.md#rules) and, for upstream tools, add the tool to [`approved_tools.json`](gateway/policy/README.md#tools-and-reviewed-facts) (built-in `codemode.*` tools on Code Mode proxies are answered by the plug-in itself and authorized directly by Cedar rules). Each request carries exactly one credential, and a request carrying both a key and a token is refused. Rules evaluate the caller's identity (OpenID Connect token claims for people, Tyk key metadata for service accounts), operator-reviewed tool facts and tags, and typed top-level call arguments. Arguments are read by their exact names, and a call that an upstream matching names regardless of letter case could read differently, such as one sending both `environment` and `Environment`, is refused before it is decided. Upstream tool annotations such as `readOnlyHint` can only narrow an otherwise permitted call, never grant access. Every call denied by Cedar rules, held by drift review, or targeting an upstream tool not in `approved_tools.json` returns the same `-32002: Tool call denied` JSON-RPC error.

### Upstream drift review

An upstream MCP server can change a tool's definition or server instructions after you review them. Under [drift review](gateway/policy/README.md#drift-review), the gateway fingerprints each approved tool definition by the SHA-256 of its canonical JSON (ignoring top-level `_meta`) and server instructions by the SHA-256 of their text, passes on only the definitions and instructions you approved, and leaves out of `tools/list` any upstream tool that Cedar shows no arguments could ever let that caller invoke. When a gateway sees a `tools/list` reply add an unapproved tool or change an approved definition, it hides the tool by default (or lists the approved definition when `changedTools` is `serve-approved`) and refuses calls to it; gateways sharing a drift directory write sightings in the background and pick up peer sightings on each refresh interval. Reviewers inspect diffs, invisible (`⟨U+XXXX⟩`) or look-alike Unicode characters, and rename hints with [`cedar-policy drift`](gateway/policy/README.md#reviewing-changes) or in the OIDC [drift review dashboard](admin/README.md) at `/extensions/admin/`.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/change-dark.png">
  <img src="docs/screenshots/change-light.png" width="760" alt="Drift review dashboard inspecting a changed tool definition with advisory flags, a word-level diff, and approve or reject controls.">
</picture>

### Sandboxed Code Mode

On proxies with [Code Mode](gateway/code-mode.md) enabled, a client can find tools it is allowed to use across proxies with `codemode.search` and `codemode.describe`, check runtime budgets with `codemode.limits`, and run a short async JavaScript program with `codemode.execute` that combines or filters multiple tool calls and returns one result and its `console` output. Programs run on a separate [sandbox host](sandbox/README.md) reached over mutual TLS: one fresh gVisor (`runsc`, systrap) sandbox per run executing QuickJS-NG compiled to WebAssembly, with a read-only root filesystem and no filesystem, environment, process, or non-loopback network access (verified at launcher startup by a self-test sandbox). The gateway keeps caller authentication headers and verified identity on the gateway side; when a program calls a tool, the sandbox service relays the call over the mutual-TLS connection to the gateway plug-in, which sends an authenticated request to the gateway's own listener as the original caller.

### Atomic policy sets and verifiable releases

Rules, approved tools, approved instructions, and [activation checks](gateway/policy/README.md#activation-checks) (`checks.json`) publish together as an immutable, content-addressed policy set with `cedar-policy promote`. Candidate sets whose activation checks do not all pass are rejected before taking effect, and running gateways validate and swap sets in the background without locking the request path. Tagged releases build Tyk Gateway from source with the same Go toolchain as the plug-in and publish distroless Debian 13 images (`gateway`, `admin`, `sandbox`) to GitHub Container Registry, each tested, scanned, and attested with SLSA build provenance and an SPDX SBOM you can verify with `gh attestation verify`; see [RELEASING.md](RELEASING.md).

## Architecture

```mermaid
flowchart LR
  Client["MCP Client<br/>(Claude Code, Codex, Agent)"]
  subgraph GatewayTier["Tyk Gateway Tier"]
    Tyk["Tyk Gateway + MCP PDP Plug-in<br/>(Token / Key Auth, Cedar Policy,<br/>Drift Filter, Code Mode Proxy)"]
    Store[("Versioned Policy Store<br/>(read-only to gateway)")]
    Pending[("Shared Drift Queue<br/>& Sightings")]
  end
  Admin["Drift Review Dashboard<br/>(/extensions/admin/ · OIDC)"]
  subgraph SandboxTier["Code Mode Sandbox Tier (mTLS)"]
    Service["sandbox-service & launcher"]
    Worker["Ephemeral gVisor Sandbox<br/>(QuickJS-NG in WebAssembly,<br/>no caller auth headers or network)"]
  end
  Upstream["Upstream MCP Servers<br/>(2025-11-25 & 2026-07-28)"]

  Client -->|"MCP (Bearer token or X-API-Key)"| Tyk
  Tyk -->|"Strips credentials;<br/>forwards permitted call"| Upstream
  Tyk <-->|"mTLS: program, relayed tool<br/>calls & results"| Service
  Service <-->|"Pipes: program & tool calls"| Worker
  Tyk -.->|"Re-enters local gateway listener<br/>for nested calls as original caller"| Tyk
  Store --> Tyk
  Tyk <--> Pending
  Admin <-->|"Approve, reject, revoke,<br/>roll back (decisions.log)"| Store
  Pending --> Admin
```

## Quick start: run the 5-server lab

To see the gateway working with an example policy, a local token issuer, five FastMCP mock servers (`directory`, `payments`, `notes`, `older`, and `changing`), the Code Mode sandbox host, and configurations for Claude Code and Codex, run the [examples](examples/README.md):

```sh
cd examples
export TYK_GW_SECRET="$(openssl rand -hex 32)"
export TYK_GW_NODESECRET="$(openssl rand -hex 32)"
docker compose up --build -d
docker compose run --build --rm runner
```

The runner checks every expected outcome in [`examples/expected.json`](examples/expected.json) across both supported MCP protocol versions, including permitted calls, refusals, per-caller `tools/list` filtering, multi-server Code Mode programs, and a 10-step upstream drift walk-through. Code Mode in the lab uses the production gVisor sandbox backend by default; on a development machine where gVisor cannot run, see [`examples/README.md`](examples/README.md#run) for the development `runc` override.

Stop the lab with `docker compose down -v` (and if you exported `SANDBOX_BACKEND` or `COMPOSE_FILE` for the development backend, run `unset SANDBOX_BACKEND COMPOSE_FILE` before starting other Compose stacks in the same shell).

## Run your own gateway

At the repository root, [`compose.yaml`](compose.yaml) runs Tyk and Redis with the [MCP policy decision point plug-in](plugins/mcp-pdp/). Set `MCP_UPSTREAM_URL` to your upstream’s MCP endpoint and configure the [Cedar authorization policy](gateway/policy/README.md). The gateway ships with no rules and denies every tool call until you add them. Connect MCP clients to `http://127.0.0.1:8080/mcp/` with a token from your identity provider or a Tyk key; see [callers](gateway/policy/README.md#callers).

```sh
export TYK_GW_SECRET="$(openssl rand -hex 32)"
export TYK_GW_NODESECRET="$(openssl rand -hex 32)"
docker compose up --build -d
```

Docker Compose refuses to start the gateway without both secrets. `TYK_GW_SECRET` authorizes Tyk's control API, which creates keys. `TYK_GW_NODESECRET` signs the notifications that gateways exchange through Redis, such as reload and key-change signals, so a client that can write to Redis cannot forge them. Every gateway that shares a Redis instance needs the same node secret. Supply both from your secret store rather than writing them into files, and keep Redis reachable only from the gateways.

In the same shell, stop the stack with `docker compose down`.

To run the drift review dashboard at `/extensions/admin/`, start Compose with `docker compose --profile admin up -d` after setting your OpenID Connect provider variables; see [`admin/README.md`](admin/README.md#running-it). To enable Code Mode, start the sandbox host with `docker compose -f sandbox/compose.yaml up -d` after providing its mutual-TLS certificates and publishing port `8443` to the gateway (or connecting them on a shared network; see [`sandbox/README.md`](sandbox/README.md#run-it)), then configure the gateway's [Code Mode settings](gateway/code-mode.md#settings).

### Health checks

The images have no shell, `curl` or `wget`, so each long-running service checks
its own health with a command its image ships. The Compose files declare these
checks, and services that need another wait for it to be healthy. Use the same
commands as Kubernetes exec probes. Each exits 0 when healthy and 1 with a
one-line reason otherwise, and gives up within a few seconds.

| Service | Command | Healthy when |
|---|---|---|
| Gateway | `/opt/tyk-gateway/bin/cedar-policy health` | Tyk's readiness endpoint answers 200, which needs Redis and loaded APIs, and, when `CEDAR_STATUS_FILE` is set, the gateway enforces a policy set. A rejected new set leaves the previous one enforced and stays healthy. A gateway enforcing no set, which denies every tool call, is unhealthy; a restart does not fix that, so in Kubernetes use this as a readiness probe rather than a liveness probe. |
| Review dashboard | `/cedar-admin -healthcheck` | The dashboard answers `/healthz` on `ADMIN_LISTEN`. It does not contact the identity provider, so a provider outage leaves it healthy. |
| Sandbox launcher | `/usr/local/bin/sandbox-launcher -healthcheck` | The launcher answers and its startup self-test passed. The launcher answers only `SANDBOX_SERVICE_UID`, so the check, run as root in the launcher's container, switches to that user before asking. |
| Sandbox service | `/usr/local/bin/sandbox-service -healthcheck` | The launcher can start sandboxes, which is when the service takes runs. |

The gateway check finds Tyk's readiness endpoint from `tyk.conf` and the
`TYK_GW_*` variables that override it: the control API port when one is set,
otherwise the listen port. Pass `-conf` when Tyk reads another file.

## Documentation

| Guide | Contents |
| --- | --- |
| [Authorize MCP tool calls](gateway/policy/README.md) | OIDC tokens and Tyk keys, `approved_tools.json`, Cedar rules, activation checks, drift review, policy store management, and `cedar-policy bench` |
| [Drift review dashboard](admin/README.md) | Browser-based OIDC review queue, word-level diffs, advisory flags, bulk decisions, rollbacks, and settings |
| [Code Mode](gateway/code-mode.md) | `codemode.search`, `codemode.describe`, `codemode.limits`, `codemode.execute`, operator limits, settings, and audit records |
| [Token exchange](gateway/token-exchange.md) | Sending each upstream a token issued for it and naming the user, settings, identity provider set-up, and fail-closed behaviour |
| [Code Mode sandbox host](sandbox/README.md) | `sandbox-service`, `sandbox-launcher`, gVisor and WebAssembly isolation, startup self-test, settings, and line protocol |
| [Examples](examples/README.md) | Five-server reference lab, drift walk-through, Claude Code and Codex setup, and conformance testing against `expected.json` |
| [Releases](RELEASING.md) | Local release checks (`release/check-local.sh`), cutting releases, SLSA provenance and SPDX SBOM verification, and OpenVEX handling |
| [Design and visual identity](docs/design.md) | Symbol geometry, light and dark color tokens, accessibility rules, SVG brand assets, and dashboard screenshots |

## Supported MCP versions

The gateway supports MCP clients and upstream servers using protocol version `2025-11-25` (with `initialize` and sessions) or `2026-07-28` (stateless, with `server/discover`). A client that asks for `2026-07-28` uses it when the upstream supports it and otherwise falls back to `2025-11-25`, as the MCP specification requires. CI runs both client versions against an upstream that speaks both protocol versions, with plain and streamed replies; the same upstream keeping sessions; and an upstream that speaks only `2025-11-25`, with plain and streamed replies.
