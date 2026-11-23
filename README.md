# Tyk Plus Plugins

Tyk Plus Plugins brings policy-based authorization, upstream drift review, and sandboxed Code Mode to a single Model Context Protocol (MCP) gateway. We are building these capabilities as plug-ins and services around the open-source Tyk Gateway, with Docker Compose as the reference deployment.

The [initial capability epic](https://github.com/chrisbennight/tyk-plus-plugins/issues/1) tracks delivery. [Waygate](https://github.com/chrisbennight/waygate) provides working examples of the behavior we are bringing to Tyk.

## Run locally

Tyk and Redis run under Docker Compose. The [MCP policy decision point plug-in](plugins/mcp-pdp/) evaluates tool calls using Cedar. Set `MCP_UPSTREAM_URL` to your upstream’s MCP endpoint and configure the [Cedar authorization policy](gateway/policy/README.md). The gateway ships with no rules and denies every tool call until you add them. Connect MCP clients to `http://127.0.0.1:8080/mcp/` with their Tyk key.

```sh
export TYK_GW_SECRET="$(openssl rand -hex 32)"
docker compose up --build -d
```

In the same shell, stop the stack with `docker compose down`.
