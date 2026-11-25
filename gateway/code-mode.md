# Code Mode

Code Mode lets an MCP client run a short JavaScript program that calls several tools and returns one result, so intermediate results never enter the model's context. The gateway plug-in answers four tools itself on each proxy where Code Mode is on: `codemode.search`, `codemode.describe` and `codemode.limits` to find tools and learn the limits, and `codemode.execute` to run a program. The program runs on a separate [sandbox host](../sandbox/README.md), and every tool call it makes comes back through the gateway as the caller who started the run, so it gets exactly the decision a direct call would get.

## Finding tools

On a proxy where Code Mode is on, `tools/list` includes each Code Mode tool the caller's rules permit, once, on the first page of the list. An upstream tool whose name starts with `codemode.` is hidden from lists on every proxy, and the gateway logs a warning naming it. To do this, the gateway reads every `tools/list` reply, plain or streamed, and asks upstreams for uncompressed replies; such a reply depends on the caller, so it is marked `Cache-Control: private, no-cache`. A compressed reply is refused with the gateway's error, as it is under drift review.

- **`codemode.search`** takes an optional `query`, `detail`, `limit` and `cursor`. It returns the tools the caller could call from a program, on every proxy where Code Mode is on that the caller's Tyk session may use: approved, passing the drift check that refuses calls, and visible under the caller's rules. Every word of the query must appear in a tool's name or description. `detail` is `summary` (the default: name, call form and first line of the description) or `full` (adds the approved input schema). Results come a page at a time, with a `nextCursor` for the next page of the same search.
- **`codemode.describe`** takes a `proxy` and a `name`, and returns the tool's approved description and input schema and its call form, such as `connectors["governed"]["lookup"]`. A tool approved without its upstream definition is described without a schema. A tool the caller could not call is described exactly as one that does not exist.
- **`codemode.limits`** returns the limits below.

Search and describe answer from the active policy set and the gateway's own records, and never contact an upstream.

## How a run works

1. Tyk authenticates the caller, and the caller's Cedar rules decide whether they may call `codemode.execute`, as for any tool. See [granting Code Mode](policy/README.md#code-mode).
2. The plug-in opens one mutual-TLS connection to the sandbox host and refuses the run unless the host reports a backend this gateway accepts. It then sends the program, its input and its limits.
3. For each tool call the program makes, the plug-in checks only that the proxy is one where Code Mode is on and that the tool name is well formed. It builds the request and every header itself and sends it to this gateway's own address for that proxy, with the caller's credential. Tyk's authentication, access rights and rate limits, the drift checks and the caller's rules then apply as they do to a direct call.
4. The result, or the refusal a direct caller would get, goes back to the program.

Calls on the run's own proxy use the client's protocol version and session. Calls to another proxy use protocol version `2025-11-25`, which every supported upstream speaks, with a session the run opens there as the caller and closes when it ends.
5. When the program returns, the client receives its result and console output, and the sandbox is destroyed.

The sandbox host never receives a credential or the caller's identity, and the plug-in never contacts an upstream itself.

## Writing programs

`codemode.execute` takes `source`, the body of an async JavaScript function, and optionally `input` (any JSON value, available as `input`), `timeout_seconds` and `limits`. Inside a program, each tool is an async function named by proxy and tool:

```js
const [a, b] = await Promise.all([
  connectors.governed.lookup({ count: 7 }),
  connectors.governed2.lookup({ count: 7 }),
]);
console.log("looked up both");
return [a.content[0].text, b.content[0].text];
```

A call resolves to the tool's result as a direct caller receives it. A refused call rejects with an error carrying the same `code` and `message` a direct caller gets; a tool on a proxy without Code Mode is refused the same way. Programs cannot call Code Mode tools. The `codemode.` prefix is reserved: an upstream tool with that name is never listed or called, on any proxy.

The tool result has `structuredContent` of `{"result": ..., "console": [...]}`, with the same JSON in its text. A run that does not finish returns a tool error (`isError`) whose `structuredContent.error` has a `kind` and a `message`:

| Kind | Meaning |
|---|---|
| `limit` | The run reached a limit, which the message names. |
| `exception` | The program threw, or never finished. |
| `busy` | The gateway or the sandbox host is running as many runs as it allows; try again shortly. |
| `cancelled` | The client disconnected, so the run was stopped. |
| `unavailable`, `protocol` | Code Mode could not run the program. The gateway's log has the details. |

When the client disconnects or the run ends, no new calls start. A call already in flight is recorded as having an unknown outcome and is never retried.

## Limits

Every limit is an operator maximum. A caller can lower any of them, with `timeout_seconds` or with the field in `limits` shown below, but never raise one.

| Limit | `limits` field | Setting | Default |
|---|---|---|---|
| Run time | `run_ms` | `CODEMODE_MAX_RUN_MS` | 30 s |
| Time per tool call | `call_ms` | `CODEMODE_MAX_CALL_MS` | 30 s |
| Memory | `memory_bytes` | `CODEMODE_MAX_MEMORY_BYTES` | 128 MiB; the sandbox host needs at least 16 MiB |
| Tool calls per run | `calls` | `CODEMODE_MAX_CALLS` | 64 |
| Tool calls at once | `calls_at_once` | `CODEMODE_MAX_CALLS_AT_ONCE` | 6; further calls wait their turn |
| Program size | `program_bytes` | `CODEMODE_MAX_PROGRAM_BYTES` | 256 KiB |
| Console output | `console_bytes` | `CODEMODE_MAX_CONSOLE_BYTES` | 256 KiB |
| Input, each tool result, the final result | `value_bytes` | `CODEMODE_MAX_VALUE_BYTES` | 1 MiB each |
| Runs at once on this gateway | | `CODEMODE_MAX_RUNS` | 8 |

The sandbox host has its own maximums and lowers any limit above them. The gateway's limit on a whole MCP request, 1 MiB, also applies: the input travels inside the `codemode.execute` request, and each call's arguments inside a nested request, so each must fit with the rest of its request. Results are not affected.

Tyk ends any response that takes longer than its `write_timeout` (120 seconds by default), and a plug-in cannot extend it. If the run time limit, plus 10 seconds for the sandbox host to start a run and 5 seconds to reply, does not fit within `write_timeout`, Code Mode reports itself unavailable at startup and every run returns `unavailable`.

## Settings

Code Mode is off unless `CODEMODE_SANDBOX_ADDRESS` or `CODEMODE_PROXIES` is set. Once either is set, a missing or invalid setting makes Code Mode unavailable, and the gateway logs why at startup.

| Setting | Meaning |
|---|---|
| `CODEMODE_SANDBOX_ADDRESS` | The sandbox host, or a load balancer in front of several, as `host:port`. |
| `CODEMODE_PROXIES` | The proxies where Code Mode is on, with their listen paths, as `governed=/mcp/,second=/mcp2/`. Programs may call tools on any of them. A nested call that reaches a different proxy than the one named here is refused. Every listed proxy must accept the same credentials, such as tokens from the same issuer for the same audience, because a run presents the caller's one credential to each of them, and search offers tools on every listed proxy the caller's Tyk session may use. |
| `CODEMODE_TLS_CERT`, `CODEMODE_TLS_KEY` | The gateway's client certificate and key files. |
| `CODEMODE_TLS_CA` | The certificate authority file that signed the sandbox host's certificate. |
| `CODEMODE_SANDBOX_SERVER_NAME` | The name on the sandbox host's certificate, when it differs from the host in the address. |
| `CODEMODE_BACKENDS` | The sandbox backends this gateway accepts, comma separated. The default, `gvisor`, is the only one for production; add `runc` only for development. |
| `CODEMODE_GATEWAY_URL` | Where nested calls reach this gateway. It must be on this machine: `localhost` or a loopback address, because nested calls carry the caller's credential. By default, Tyk's own port on `127.0.0.1`, which reaches Tyk when it listens on every address, as it does by default. |

With the reference Compose deployment, set these in the shell or an `.env` file, and mount the certificate files with an override file, since Compose cannot assume they exist:

```yaml
# compose.override.yaml
services:
  gateway:
    volumes:
      - ./codemode-tls:/etc/codemode:ro
```

Then set `CODEMODE_TLS_CERT=/etc/codemode/client.pem`, and the key and authority likewise.

Each Code Mode proxy also needs the `Capture` hook, which runs right after Tyk authenticates a caller. Tyk removes credential headers before the authorization hook runs, so `Capture` keeps a token caller's credential in the request's memory for the length of a run. A key caller's key comes from Tyk's own request context. The shipped [proxy definitions](apps/) include the hook; it does nothing while Code Mode is off.

## Audit

Each run logs a `Code Mode run` record with a random run ID, the caller, the proxy, the SHA-256 hash of the program, the sandbox backend, the start time and duration, call counts by outcome, and the outcome. Each call logs a `Code Mode call` record with the run ID and its outcome (`result`, `refused`, `failed` or `unknown`), and the nested request's `Cedar authorization` record carries the same `code_mode_run`. No record includes a credential, the program source, the input or any result.

Nested requests carry an `X-Code-Mode-Call` header so the plug-in can recognise them. The header only links a call to its run and refuses Code Mode tools inside a run; it grants nothing, and the plug-in removes it before a request reaches an upstream.
