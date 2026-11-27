# Example token issuer

A small token issuer for the examples and the integration tests. It signs tokens with an RSA key and publishes that key, so the gateway can verify tokens without a real identity provider.

**It is not an identity provider.** Anyone who can reach it can obtain a token with any claims. Run it only on a local or test network. It warns at start-up when it listens on anything other than a loopback address.

## Endpoints

| Request | Result |
| --- | --- |
| `GET /token/<name>` | A token for a person in the deck. |
| `POST /token` | A token carrying exactly the JSON object in the body, up to 64 KiB. Tests use this for tokens the gateway must refuse, such as expired ones or ones without a subject. |
| `?key=unpublished` on either token request | The same token signed with a key the issuer does not publish, which the gateway must refuse. |
| `GET /jwks` | The published key, for the gateway's `MCP_TOKEN_JWKS_URL`. |
| `GET /healthz` | `ok` once the issuer is serving. |
| `GET /.well-known/openid-configuration`, `GET /oauth/authorize`, `POST /oauth/token` | OpenID Connect sign-in for the deck's clients, and token exchange; see [Sign-in](#sign-in) and [Token exchange](#token-exchange). |

## The deck

The deck is a JSON file naming each example person and the claims their token carries. Set `ISSUER_DECK` to its path. The examples' deck is [`../callers/people.json`](../callers/people.json).

```json
{
  "issuer": "https://issuer.example",
  "audience": "examples-gateway",
  "lifetimeSeconds": 3600,
  "people": {
    "analyst": {"roles": ["analyst"]},
    "scoped": {"scope": "notes:read payments:read"}
  }
}
```

- Set the gateway's `MCP_TOKEN_ISSUER` to `issuer` and `MCP_TOKEN_AUDIENCE` to `audience`.
- Every token for a person has `iss` and `aud` from the deck, `iat` set to the time of the request, and `exp` set `lifetimeSeconds` later.
- `sub` is the person's name unless the person sets their own `sub`.
- A person may carry any other claims. The deck owns `iss`, `aud`, `exp`, `iat` and `nbf`, so a person who sets one of these is an error.
- Names of people and clients use lowercase letters, digits and hyphens.
- `lifetimeSeconds` is at most one year.
- The issuer refuses to start when the deck has an unknown field, a name listed twice, data after the deck, or a missing setting, and names the problem.

## Settings

| Variable | Meaning |
| --- | --- |
| `ISSUER_DECK` | Path to the deck. Without it, only `POST /token` signs tokens. |
| `ISSUER_KEY_FILE` | Path to a PKCS #8 PEM signing key. The issuer creates it, readable only by its owner, if it is missing. Without it, every start generates a new key with a new key ID, and a running gateway may reject new tokens until its cached key set expires (five minutes in the gateway's API definition). |
| `ISSUER_LISTEN` | Listening address. Defaults to `127.0.0.1:8000`; the container image sets `:8000`. |
| `ISSUER_PUBLIC_URL` | The base URL browsers and applications use to reach the issuer, such as `http://127.0.0.1:8090`. The sign-in and token-exchange endpoints are served only when it is set and the deck lists clients. |

## Sign-in

Applications such as the drift review dashboard sign people in with OpenID Connect. The issuer offers the authorization-code flow for people in the deck, so those applications can be tried and tested without a real identity provider.

**There are no passwords.** Whoever opens the sign-in page chooses who to be, so this is no more an identity provider than the rest of the issuer. Keep it on a local or test network.

List each application in the deck under `clients`, with a secret and the exact redirect URIs it may return to. A redirect URI may not carry its own `code` or `state`, since the issuer adds those. The same list holds clients that use [token exchange](#token-exchange):

```json
"clients": {
  "dashboard": {"secret": "example-secret", "redirectURIs": ["http://127.0.0.1:8080/extensions/admin/callback"]}
}
```

- `GET /.well-known/openid-configuration` describes the endpoints. Its `issuer` is the deck's `issuer`. Standard OpenID Connect clients expect it to equal the URL they read the document from, so set the deck's `issuer` to `ISSUER_PUBLIC_URL` for them; an application that keeps a different issuer, such as one shared with the gateway's tokens, has to accept the difference.
- `GET /oauth/authorize` takes `response_type=code`, `client_id`, `redirect_uri`, `state`, `nonce`, and optionally `code_challenge` with `code_challenge_method=S256`.
  - With `login_hint` naming a person in the deck, it returns at once to the redirect URI with a code.
  - Without it, it shows a page listing the deck's people to choose from.
  - An unknown client, a client that may not use the authorization-code grant, or a redirect URI the client does not list exactly, is refused without redirecting.
- `POST /oauth/token` exchanges the code. The client authenticates with its secret, by HTTP Basic or in the form, and sends the same redirect URI and, if it gave a challenge, the code verifier.
  - A code works once, and only within a minute of being issued. A sign-in that gave a challenge needs its verifier, and one that gave none must send none.
  - Client IDs and secrets sent by HTTP Basic are form-encoded first, as OAuth requires ([RFC 6749 section 2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)).
  - A wrong or missing secret is refused with `401` and `invalid_client`. If the client tried HTTP Basic, even with a malformed header, the response also carries `WWW-Authenticate: Basic` ([RFC 6749 section 5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2)).
  - A request that uses HTTP Basic and also sends `client_secret` in the form is refused with `invalid_request`, because a client may use only one authentication method ([RFC 6749 section 2.3](https://www.rfc-editor.org/rfc/rfc6749#section-2.3)). So is a request that repeats a parameter ([RFC 6749 section 3.2](https://www.rfc-editor.org/rfc/rfc6749#section-3.2)), except `resource` and `audience`. A parameter sent without a value counts as omitted, as the same section requires.
  - A client that may not use the grant it sends is refused with `unauthorized_client`.
  - It returns an ID token whose audience is the client and which carries the sign-in's `nonce`, and an access token for the deck's `audience`.
  - Both carry the person's claims from the deck and are signed with the published key. The access token follows the JWT access token profile ([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)): its `typ` header is `at+jwt`, and it also carries `client_id` (the client) and a unique `jti`. The ID token's `typ` is `JWT`.
  - Responses carry `Cache-Control: no-store` and `Pragma: no-cache` ([RFC 6749 section 5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1)).

A client's ID must differ from the deck's `audience`, so a client's ID token, whose audience is its client ID, can never pass for a person's access token. A client may use only the grants it lists under `grants`. Without `grants` it may use the authorization-code grant only, so an existing deck needs no change. A client that may use the authorization-code grant needs at least one redirect URI; a token-exchange-only client needs none.

## Token exchange

The token endpoint also supports the token-exchange grant ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)), so the gateway's token exchange can be tested end to end. A client trades a person's token, signed by this issuer for the deck's `audience` (the gateway's), for a token issued to a target service. It is impersonation only: the issued token names the person and no actor.

List the targets under `targets`, keyed by resource URI, and give the exchanging client the grant:

```json
"clients": {
  "gateway": {"secret": "example-secret", "grants": ["urn:ietf:params:oauth:grant-type:token-exchange"]}
},
"targets": {
  "https://notes.example/mcp": {"audience": "notes", "scopes": ["notes:read", "notes:write"]},
  "https://slow.example/mcp": {"delayMilliseconds": 5000}
}
```

- A target's key is its resource URI, which must be absolute, without a fragment, and use only the characters a URI may contain.
- `audience` is an optional logical name for the target, unique in the deck.
- `scopes` lists the scope values a token for the target may carry.
- `delayMilliseconds` (at most 60000) holds every accepted exchange for the target that long before answering, so a test can make its caller time out. This is a test-only fault mode, not standard behaviour.

A request is a `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`, `subject_token_type` (`urn:ietf:params:oauth:token-type:access_token` or `urn:ietf:params:oauth:token-type:jwt`), one target, and optionally `scope` and `requested_token_type=urn:ietf:params:oauth:token-type:access_token`. The gateway names the target with `resource`, as the [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#resource-parameter-implementation) requires; `audience` with a target's name is also accepted. Resource URIs are compared exactly.

A successful response carries `access_token`, `issued_token_type` (`urn:ietf:params:oauth:token-type:access_token`), `token_type` (`Bearer`), `expires_in` and, when a scope was requested, `scope` ([RFC 8693 section 2.2.1](https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1)). The issued token follows the JWT access token profile: `typ` is `at+jwt`; `iss` is the deck's `issuer`; `aud` is the target's resource URI, whichever parameter named it; `sub` is the subject token's `sub`; `client_id` is the exchanging client; and it carries `iat`, `exp` (the deck's `lifetimeSeconds` later), a unique `jti` and, if requested, `scope`. It carries none of the person's other claims, and its lifetime does not depend on the subject token's.

Each refusal uses the error code the standards give, so a test can trigger it on purpose:

| To get | Send |
| --- | --- |
| `401 invalid_client` | a wrong or missing client secret, or a malformed HTTP Basic header; after an HTTP Basic attempt the response also carries `WWW-Authenticate: Basic` |
| `400 unauthorized_client` | the grant from a client whose `grants` do not include it |
| `400 invalid_request` | HTTP Basic together with `client_secret` in the form; a missing `subject_token` or `subject_token_type`; an unsupported `subject_token_type` or `requested_token_type`; any `actor_token` or `actor_token_type`; any parameter other than `resource` and `audience` sent twice; or a subject token that is not a valid token from this issuer for the deck's `audience`: expired, not yet valid, signed with `?key=unpublished`, from another issuer, for another audience, without `sub` or `exp`, or not `RS256` |
| `400 invalid_target` | no target, more than one (including `resource` with `audience`), a resource that is not an absolute URI without a fragment, or a resource or audience the deck does not list |
| `400 invalid_scope` | a scope value the target does not list |
| a slow answer | a target with `delayMilliseconds` |

RFC 8693 requires `invalid_request` for a subject or actor token that is invalid or unacceptable by policy ([section 2.2.2](https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2)), so this grant never answers `invalid_grant`. The issuer accepts no actor tokens, so any is unacceptable by policy.
