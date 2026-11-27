# Token exchange

By default the gateway forwards a permitted request to its upstream without the caller's credential: Tyk removes it after authentication. With token exchange on for a proxy, the gateway instead sends the upstream a token issued for that upstream alone and naming the same user. It obtains the token from your identity provider with OAuth 2.0 Token Exchange ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)), exchanging the caller's own token, and forwards it as `Authorization: Bearer <token>`.

The upstream can then check who the user is and that the token was meant for it, without ever seeing the token the caller presented to the gateway. This is impersonation: the issued token names the user as its subject and does not name the gateway.

## How a request is handled

1. Tyk authenticates the caller's token, and the plug-in keeps it for the request. It is never logged.
2. The plug-in decides the request as usual. A request it refuses never reaches the identity provider.
3. For a request it forwards, the plug-in exchanges the caller's token at the token endpoint, sending:
   - `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`;
   - the caller's token as `subject_token`, with `subject_token_type=urn:ietf:params:oauth:token-type:access_token`;
   - `resource`, the canonical URI of the proxy's upstream MCP server, as the [MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#resource-parameter-implementation) requires of every client. `audience` is never sent with it;
   - `scope`, when one is configured for the proxy.

   The gateway authenticates as its own confidential client, with HTTP Basic authentication.
4. The issued token replaces the request's `Authorization` header and the request is forwarded.

Every forwarded request is covered, in both supported protocol versions: tool calls the rules permit, the handshakes, `tools/list` and every other method, notifications, and the event stream and session teardown of protocol `2025-11-25`. Code Mode tools are answered by the plug-in itself and never reach an upstream, so they need no exchange. A program's tool calls come back through the gateway as the caller and are exchanged like direct calls.

Issued tokens are cached in the gateway's memory only, never in Redis or on disk. An entry is keyed by a hash of the caller's token, the resource and the scope, and lasts until the earlier of the issued token's `expires_in`, counted from when the request was sent, and the caller's own token's expiry, less a margin, so an issued token is never used after the caller's token has expired. A reply without `expires_in` is used for its request and not cached. Concurrent requests that need the same exchange share one request to the identity provider. The gateway never reads the issued token: it treats it as opaque, as RFC 8693 expects.

## Turning it on for a proxy

1. List the proxy in `EXCHANGE_PROXIES`, with its upstream's canonical URI, and set the other settings (see [Settings](#settings)). The repository's `compose.yaml` passes each setting through from the environment `docker compose` runs in; mount any file a setting names into the gateway container. When you point the proxy at another upstream, change its resource with it: the gateway cannot compare the two, since it often reaches an upstream at an internal address that differs from the upstream's canonical URI. Once the proxy has approved tools, it refuses to send an exchanged token to an upstream other than the one they were reviewed for, with the reason `unreviewed_upstream`, as it refuses tool calls there.
2. Keep the proxy's token scheme reading the token from the `Authorization` header only: the default header, with no query parameter or cookie. No other credential, a key included, may be read from a query parameter or a cookie either, since the plug-in replaces only `Authorization` and Tyk no longer strips the rest. The plug-in exchanges and replaces the token in that header, so a proxy whose token Tyk reads from anywhere else refuses every request it would forward, with the reason `token_not_in_authorization_header` in the log.
3. In the proxy's definition, set `stripAuthorizationData` to `false` (`strip_auth_data` in the classic definition). On an MCP proxy, Tyk passes each request through its middleware more than once before forwarding it, and strips credentials again on the later passes, where the plug-in's hooks do not run. It would therefore also remove the exchanged token. With stripping off, the plug-in takes over: on a proxy with exchange on it replaces the caller's token with the issued one, or refuses the request, so the caller's own credential is still never forwarded. A proxy with exchange on that still has stripping on refuses every request it would forward, with the reason `strip_authorization_data_on` in the log. The reverse is refused too: a proxy with stripping off that exchange is not on for, for example through a typing error in its `EXCHANGE_PROXIES` ID or on a gateway without the exchange settings, refuses every request it would forward, with the reason `exchange_off_and_stripping_off`, rather than forwarding the caller's own credential, which the [MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#token-passthrough) forbids.
4. Point the proxy at its upstream over `https`. The issued token is a bearer credential for the user, so a proxy with exchange on whose upstream URL uses plain `http` refuses every request it would forward, with the reason `upstream_not_https`, unless `EXCHANGE_ALLOW_INSECURE_HTTP=true`.

## Who can use it

Only callers identified by a token. A caller identified by a Tyk key has no token to exchange, so on a proxy with exchange on every request from a key caller is refused with HTTP 403 and the JSON-RPC error `This proxy accepts token callers only`, including calls to Code Mode's own tools when Code Mode is on there too. Through Code Mode on another proxy, a key caller does not find such a proxy's tools.

## When the exchange fails

The gateway never forwards a request it has no exchanged token for, and never falls back to the caller's token, another configured credential or no credential. The exchange fails on:

- a network error or timeout;
- any reply that is not 2xx, whatever its `error` code. Identity providers use `invalid_request`, `invalid_grant`, `invalid_target` and other codes for similar cases, and the gateway treats them alike;
- a 2xx reply that is not a JSON object, or lacks `access_token`, `issued_token_type` or `token_type`;
- a `token_type` other than `Bearer`, including `N_A`;
- an `expires_in` of zero or less;
- a token identical to the caller's own, as a faulty provider or adapter might return;
- an `issued_token_type` other than an access token or a JWT;
- a token that is not valid bearer-token syntax for a header;
- the caller's own token, or the issued token's own lifetime, running out while the exchange is under way.

The reply's members are matched by their exact names.

The request is then answered with HTTP 503. A request with a JSON-RPC ID also gets the JSON-RPC error `-32603 Upstream credentials unavailable`; notifications, and the event stream and session teardown requests of protocol `2025-11-25`, carry no ID and get the status alone.

Each failure is logged with the proxy, a failure kind, the HTTP status and the identity provider's `error` code when it is one of the registered OAuth codes, such as `invalid_request` or `invalid_target`; any other value is logged as `other`. Tokens, the client secret and the provider's `error_description` are never logged, because providers may echo request details back in them. When a reply has no `error` code, as an empty `502` from an intermediary does, the status alone identifies the failure.

A proxy with exchange on refuses its requests the same way, with HTTP 503 and the reason in the log, when the exchange settings are invalid, when Tyk still strips credentials on it, reads the caller's token from somewhere other than the `Authorization` header, or reaches the upstream over plain `http` (see [Turning it on for a proxy](#turning-it-on-for-a-proxy)), or when Tyk itself is configured to set the upstream's credential: Tyk upstream authentication, or an `Authorization` header added to or removed from every request through `transformRequestHeaders`. Each could replace, contradict or drop the exchanged token. Requests on proxies without exchange are unaffected, as long as Tyk strips credentials there, as it does by default.

## Settings

Set these on the gateway. Exchange is off unless `EXCHANGE_PROXIES`, `EXCHANGE_TOKEN_URL` or `EXCHANGE_CLIENT_ID` is set. When it is configured but a setting is missing or invalid, the gateway logs every problem at startup and the affected proxies refuse their requests.

| Setting | Meaning |
| --- | --- |
| `EXCHANGE_PROXIES` | Each proxy with exchange on, with its upstream's canonical URI and an optional scope: `governed=https://mcp.example.com/mcp`, or `governed=https://mcp.example.com/mcp tools:read tools:write`. Entries are separated by commas, and proxies are named as in `CODEMODE_PROXIES`. The URI must be absolute, with a host and no fragment ([RFC 8707 section 2](https://www.rfc-editor.org/rfc/rfc8707#section-2)). A proxy named with an invalid URI stays on, so its requests are refused rather than forwarded without exchange. An entry whose proxy cannot be read makes every proxy refuse its requests. |
| `EXCHANGE_TOKEN_URL` | The identity provider's token endpoint. It must use `https`; set `EXCHANGE_ALLOW_INSECURE_HTTP=true` to allow `http`, for the token endpoint and for the upstreams of proxies with exchange on, on a local or test network only. A plain-HTTP token endpoint is reached directly, never through a proxy set in the environment. |
| `EXCHANGE_TLS_CA` | Optional. A file of certificate authorities. When set, only these are trusted for the token endpoint's certificate, for deployments whose token endpoint uses a private certificate authority, as `CODEMODE_TLS_CA` does for Code Mode. When unset, the system's trusted certificate authorities are used. |
| `EXCHANGE_CLIENT_ID` | The gateway's client ID at the identity provider. |
| `EXCHANGE_CLIENT_SECRET_FILE` | A file holding the gateway's client secret. `EXCHANGE_CLIENT_SECRET` is read when no file is set; a file keeps the secret out of the process environment. |
| `EXCHANGE_TIMEOUT` | How long one exchange may take, as a duration such as `15s`. Default `15s`. If an intermediary such as an adapter sits in front of the identity provider, make this longer than the intermediary's own timeout, so the intermediary answers first. |
| `EXCHANGE_EXPIRY_MARGIN` | How long before an issued or caller token expires its cache entry ends. Default `30s`. |
| `EXCHANGE_CACHE_MAX_ENTRIES` | The most issued tokens kept at once; the least recently used is dropped. Default `10000`. |

## Identity provider set-up

The identity provider must support the token-exchange grant for the gateway's client, accept the caller's token, which it issued for the gateway's audience (`MCP_TOKEN_AUDIENCE`), as the subject token, and issue a token for each upstream's canonical URI. Each upstream should check that the token's `aud` is its own canonical URI.

### authentik

Tested with authentik 2026.8.6, exchanging a service account's token. Exchanging a person's token, issued for the gateway's audience, has not been tested yet:

- authentik's token exchange **rejects `resource`** with `invalid_target`, by design, and names the target with `audience` instead, matched against the target provider's client ID. Put a small adapter in front of the token endpoint that renames `resource` to `audience`, passes everything else through unchanged, and refuses any resource it does not expect; point `EXCHANGE_TOKEN_URL` at the adapter, and use `EXCHANGE_TLS_CA` if it has a private certificate.
- Give each upstream's provider a client ID equal to the upstream's canonical URI. authentik then issues a token whose `aud` is that URI, as an RFC 8707 server would. The target provider must list the gateway's provider under *Federated OAuth2/OpenID Providers*.
- The issued token's `iss` is the target provider's own issuer and its `sub` is the caller's. Its header is `typ: JWT` rather than `at+jwt`, and it has no `client_id` claim, so upstreams must not require either.
