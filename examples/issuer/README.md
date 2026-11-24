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
- Names use lowercase letters, digits and hyphens.
- The issuer refuses to start when the deck has an unknown field, a person listed twice, or a missing setting, and names the problem.

## Settings

| Variable | Meaning |
| --- | --- |
| `ISSUER_DECK` | Path to the deck. Without it, only `POST /token` signs tokens. |
| `ISSUER_KEY_FILE` | Path to a PKCS #8 PEM signing key. The issuer creates it, readable only by its owner, if it is missing. Without it, every start generates a new key with a new key ID, and a running gateway may reject new tokens until its cached key set expires (five minutes in the gateway's API definition). |
| `ISSUER_LISTEN` | Listening address. Defaults to `127.0.0.1:8000`; the container image sets `:8000`. |
