# Tyk Plus Plugins

Tyk Plus Plugins brings policy-based authorization, upstream drift review, and sandboxed Code Mode to a single Model Context Protocol (MCP) gateway. We are building these capabilities as plug-ins and services around the open-source Tyk Gateway, with Docker Compose as the reference deployment.

The [initial capability epic](https://github.com/chrisbennight/tyk-plus-plugins/issues/1) tracks delivery. [Waygate](https://github.com/chrisbennight/waygate) provides working examples of the behavior we are bringing to Tyk.

## Run locally

The bootstrap runs Tyk, Redis, and a sample MCP server with one `echo` tool. The gateway listens on loopback and accepts local calls without authentication. Cedar authorization, drift review, and Code Mode are tracked in the epic.

With Docker Compose and Python 3 installed, run these commands in the same shell.

```sh
export TYK_GW_SECRET="$(openssl rand -hex 32)"
docker compose up --build -d
python3 scripts/smoke.py
docker compose down -v
```

Connect a Streamable HTTP MCP client to `http://127.0.0.1:8080/mcp/` while the stack is running. The proxy definitions live in [gateway/apps](gateway/apps).
