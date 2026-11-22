# Tyk Plus Plugins

Tyk Plus Plugins brings policy-based authorization, upstream drift review, and sandboxed Code Mode to a single Model Context Protocol (MCP) gateway. We are building these capabilities as plug-ins and services around the open-source Tyk Gateway, with Docker Compose as the reference deployment.

The [initial capability epic](https://github.com/chrisbennight/tyk-plus-plugins/issues/1) tracks delivery. [Waygate](https://github.com/chrisbennight/waygate) provides working examples of the behavior we are bringing to Tyk.

## Run locally

The bootstrap runs Tyk Gateway and Redis. It listens on `127.0.0.1:8080`. MCP upstreams and governance plug-ins will be added as the epic progresses.

```sh
export TYK_GW_SECRET="$(openssl rand -hex 32)"
docker compose up --build -d
```

Stop the stack with `docker compose down`.
