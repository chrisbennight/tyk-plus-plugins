# Tyk Plus Plugins

Tyk Plus Plugins brings policy-based authorization, upstream drift review, and sandboxed Code Mode to a single Model Context Protocol (MCP) gateway. We are building these capabilities as plug-ins and services around the open-source Tyk Gateway, with Docker Compose as the reference deployment.

The [initial capability epic](https://github.com/chrisbennight/tyk-plus-plugins/issues/1) tracks delivery. [Waygate](https://github.com/chrisbennight/waygate) provides working examples of the behavior we are bringing to Tyk.

## Run locally

Tyk and Redis run under Docker Compose. The [MCP policy decision point plug-in](plugins/mcp-pdp/) evaluates tool calls using Cedar. Set `MCP_UPSTREAM_URL` to your upstream’s MCP endpoint and configure the [Cedar authorization policy](gateway/policy/README.md). The gateway ships with no rules and denies every tool call until you add them. Connect MCP clients to `http://127.0.0.1:8080/mcp/` with a token from your identity provider or a Tyk key; see [callers](gateway/policy/README.md#callers).

```sh
export TYK_GW_SECRET="$(openssl rand -hex 32)"
export TYK_GW_NODESECRET="$(openssl rand -hex 32)"
docker compose up --build -d
```

Docker Compose refuses to start the gateway without both secrets. `TYK_GW_SECRET` authorizes Tyk's control API, which creates keys. `TYK_GW_NODESECRET` signs the notifications that gateways exchange through Redis, such as reload and key-change signals, so a client that can write to Redis cannot forge them. Every gateway that shares a Redis instance needs the same node secret. Supply both from your secret store rather than writing them into files, and keep Redis reachable only from the gateways.

In the same shell, stop the stack with `docker compose down`.

## Supported MCP versions

The gateway supports MCP clients and upstream servers using protocol version `2025-11-25` (with `initialize` and sessions) or `2026-07-28` (stateless, with `server/discover`). A client that asks for `2026-07-28` uses it when the upstream supports it and otherwise falls back to `2025-11-25`, as the MCP specification requires. CI runs both client versions against an upstream that speaks both protocol versions, with plain and streamed replies; the same upstream keeping sessions; and an upstream that speaks only `2025-11-25`, with plain and streamed replies.
