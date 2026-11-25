# Drift review dashboard

A web interface for reviewing upstream drift: what gateways queued for review, why each tool is allowed or refused, and decisions to approve or reject a change. It uses the same review code as `cedar-policy drift`, writes the same policy store, and records every decision in the store's decision log with the operator's verified identity.

Operators reach it through the gateway at `/extensions/admin/`.

## Pages

- **Overview.** For each proxy under drift review: changes waiting, tools refused, the active policy set, and each gateway sharing declarations with when it was last heard from.
- **Review queue.** Every waiting change, whether it is what the upstream declares now or has been superseded, and when and where it was first seen.
- **Change.** A labelled diff against the approved version with changed words marked. Invisible and look-alike characters are written out by code point, and a rename hint appears where one applies. The full definition can be read. A definition longer than 2,000 characters must be opened in full before it can be approved. Text larger than 1 MiB, well above the gateway's default limit, is not formatted here: review it with `cedar-policy drift show`, and approve it there. It can still be rejected here.
- **Tools.** Every tool the set reviews, and every new one waiting, with whether drift review lets calls through and why, linking to the change that resolves it.

## Decisions

Approve and Reject apply to exactly the fingerprint the page showed. A tool definition can be approved only when it is what gateways last saw the upstream declare: approving one the upstream has replaced could only refuse calls, and one no gateway has seen it declare may have been queued before the upstream changed. Either can still be rejected. Every decision applies against the policy set active when the page loaded; if another set has become active since, nothing changes and the queue says so. A decision makes a new set active, so `cedar-policy activate` with the previous set rolls it back.

## Sign-in and roles

The dashboard signs operators in itself with OpenID Connect: the authorization code flow with PKCE and a nonce, and an ID token verified against the identity provider's published keys. It does not trust identity headers, so it is safe even if reached other than through the gateway. Register it with your identity provider as a confidential client whose redirect URI is `<ADMIN_PUBLIC_URL>/callback`.

The groups claim of the ID token grants one of two roles:

- **reviewer**, for members of `ADMIN_REVIEWER_GROUP`: everything, including decisions;
- **viewer**, for members of `ADMIN_VIEWER_GROUP`: every page, but no decisions.

An account in neither group is refused. A sign-in in progress is kept only in the browser's short-lived login cookie, so unfinished sign-ins use no memory in the dashboard. Sessions are held in memory for at most eight hours, or until the ID token expires if sooner; restarting the dashboard signs everyone out. Decisions are form posts checked against the session's CSRF token and the browser's origin.

## Settings

| Variable | Meaning |
| --- | --- |
| `ADMIN_PUBLIC_URL` | The dashboard's address as browsers reach it, for example `https://gateway.example.com/extensions/admin`. Required. Use `https` outside a local or test network, so session cookies are only sent securely. |
| `ADMIN_OIDC_ISSUER` | The identity provider's issuer, as its tokens name it. Required. |
| `ADMIN_OIDC_DISCOVERY_URL` | Where to fetch the provider's configuration when it is reached at another address than its issuer, as on a private network. Optional. The configuration names the keys that verify ID tokens and where the client secret is sent, so it must be `https` unless `ADMIN_OIDC_ALLOW_INSECURE_HTTP` allows otherwise. |
| `ADMIN_OIDC_ALLOW_INSECURE_HTTP` | Set to `true` to allow reaching the identity provider without `https`, on a local or test network only. Otherwise the dashboard refuses to start when the issuer or discovery URL is not `https`, and refuses sign-in when the provider's token endpoint is not. |
| `ADMIN_OIDC_CLIENT_ID` | The dashboard's client ID at the provider. Required. |
| `ADMIN_OIDC_CLIENT_SECRET_FILE` | A file holding the client secret. `ADMIN_OIDC_CLIENT_SECRET` is read when no file is set. One is required. |
| `ADMIN_GROUPS_CLAIM` | The ID token claim listing the operator's groups. Defaults to `groups`. |
| `ADMIN_REVIEWER_GROUP` | The group whose members are reviewers. Required. |
| `ADMIN_VIEWER_GROUP` | The group whose members are viewers. Optional. |
| `ADMIN_STORE` | The policy store. Defaults to `/opt/tyk-gateway/cedar`, as in the gateway. |
| `ADMIN_PENDING_DIR` | The shared drift directory. Defaults to `/opt/tyk-gateway/cedar-pending`, as in the gateway. |
| `ADMIN_LISTEN` | The listening address. Defaults to `:8000`. |

## Running it

The repository's [`compose.yaml`](../compose.yaml) runs it with the `admin` profile, sharing the gateway's store and drift directory volumes:

```sh
export ADMIN_PUBLIC_URL=https://gateway.example.com/extensions/admin
export ADMIN_OIDC_ISSUER=https://id.example.com/application/o/drift-review/
export ADMIN_OIDC_CLIENT_ID=drift-review
export ADMIN_REVIEWER_GROUP=drift-reviewers ADMIN_VIEWER_GROUP=drift-viewers
# The client secret, kept out of the environment:
export ADMIN_OIDC_CLIENT_SECRET_PATH=./admin-oidc-client-secret
docker compose --profile admin up -d
```

The gateway routes `/extensions/admin/` to `ADMIN_UPSTREAM_URL`, which defaults to the `admin` service.

The dashboard runs as the gateway's user, which owns the store and the drift directory in the gateway image so the dashboard can write them. Gateways only read the store, so mount it read-only in every gateway, as `compose.yaml` does; then only reviewers, through the dashboard or `cedar-policy`, change it. A store shared with other publishers follows the store's group rules in [`gateway/policy/README.md`](../gateway/policy/README.md#sharing-a-store-between-publishers).
