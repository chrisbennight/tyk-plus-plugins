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
| `GET /.well-known/openid-configuration`, `GET /oauth/authorize`, `POST /oauth/token` | OpenID Connect sign-in for the deck's clients; see [Sign-in](#sign-in). |

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
| `ISSUER_PUBLIC_URL` | The base URL browsers and applications use to reach the issuer, such as `http://127.0.0.1:8090`. The sign-in endpoints are served only when it is set and the deck lists clients. |

## Sign-in

Applications such as the drift review dashboard sign people in with OpenID Connect. The issuer offers the authorization-code flow for people in the deck, so those applications can be tried and tested without a real identity provider.

**There are no passwords.** Whoever opens the sign-in page chooses who to be, so this is no more an identity provider than the rest of the issuer. Keep it on a local or test network.

List each application in the deck under `clients`, with a secret and the exact redirect URIs it may return to:

```json
"clients": {
  "dashboard": {"secret": "example-secret", "redirectURIs": ["http://127.0.0.1:8080/extensions/admin/callback"]}
}
```

- `GET /.well-known/openid-configuration` describes the endpoints. Its `issuer` is the deck's `issuer`, which may differ from `ISSUER_PUBLIC_URL`; an application then has to accept that difference when it reads the document.
- `GET /oauth/authorize` takes `response_type=code`, `client_id`, `redirect_uri`, `state`, `nonce`, and optionally `code_challenge` with `code_challenge_method=S256`.
  - With `login_hint` naming a person in the deck, it returns at once to the redirect URI with a code.
  - Without it, it shows a page listing the deck's people to choose from.
  - An unknown client, or a redirect URI the client does not list exactly, is refused without redirecting.
- `POST /oauth/token` exchanges the code. The client authenticates with its secret, by HTTP Basic or in the form, and sends the same redirect URI and, if it gave a challenge, the code verifier.
  - A code works once, and only within a minute of being issued.
  - It returns an ID token whose audience is the client and which carries the sign-in's `nonce`, and an access token for the deck's `audience`.
  - Both carry the person's claims from the deck and are signed with the published key.
