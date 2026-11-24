# Code Mode sandbox host

Code Mode runs short JavaScript programs that call MCP tools. The programs are
untrusted: a prompt injection can make a model write one. This directory builds
the hosts that run them, in a tier separate from the gateways.

- **Sandbox service** (`sandbox-service`). Gateways connect to it over mutual
  TLS, one connection per run. It asks the launcher for a sandbox, passes the
  program in, and relays tool calls and their replies, checking every message
  against the run's limits. It runs as its own unprivileged user.
- **Launcher helper** (`sandbox-launcher`). The only privileged component. It
  accepts typed requests (start, health) on a Unix socket, only from the
  sandbox service's user, starts one sandbox per run from a fixed worker image,
  hands the run's pipes to the sandbox service, and destroys the sandbox when
  the run finishes, times out or loses its connection.
- **Worker** (`/worker` in every sandbox). Runs the program in QuickJS-NG
  compiled to WebAssembly, with no file system, environment, network or process
  access. The program's only way out is a tool call, which the gateway checks
  exactly like a direct call from the same caller.

The sandbox tier never holds caller credentials.

## Isolation

Each run gets a fresh sandbox from a read-only image containing only the
worker. It runs as an unprivileged user with no capabilities and no new
privileges, in its own process, network, IPC, host-name and mount namespaces,
with no network interface other than loopback.

| Backend | Runtime | Use |
|---|---|---|
| `gvisor` | gVisor `runsc`, systrap platform | Production |
| `runc` | Docker's standard runtime | Development where gVisor is unavailable, such as Docker Desktop on macOS |

The sandbox service reports its backend to gateways at the start of every run,
so a gateway can refuse a backend it does not accept.

When the launcher starts, it runs a self-test sandbox that tries to reach the
network, read a file from the launcher's container, and write to its own file
system. If any attempt succeeds, the host refuses every run and reports why.

### Launcher privileges

With the `gvisor` backend the launcher does not run privileged. It gets exactly
the capabilities `SYS_ADMIN`, `SETUID`, `SETGID` and `SETFCAP`, with Docker's
seccomp and AppArmor profiles off, `no-new-privileges`, and a read-only root
file system. Without `--privileged`, Docker's cgroup files are read-only, so
gVisor runs without a cgroup per sandbox. Each run is then bounded by the
WebAssembly memory cap and the engine's processor budget inside the sandbox,
and all runs on a host share the launcher container's memory and process
limits (`SANDBOX_HOST_MEMORY`).

The `runc` backend needs writable cgroups, so `compose.runc.yaml` runs the
launcher privileged. Use it only for development.

## Run it

The services are in the repository's `compose.yaml` under the `codemode`
profile. They need a TLS directory holding:

| File | Contents |
|---|---|
| `server.pem`, `server-key.pem` | The sandbox service's certificate and key |
| `client-ca.pem` | The authority that signs gateway client certificates |

Point `SANDBOX_TLS_DIR` at it (default `./sandbox/tls`, which Git ignores), then:

```sh
docker compose --profile codemode up -d sandbox-launcher sandbox
```

On a machine without gVisor, add the development backend:

```sh
docker compose -f compose.yaml -f sandbox/compose.runc.yaml --profile codemode up -d sandbox-launcher sandbox
```

At scale, run sandbox hosts on their own machines behind a load balancer.
Publish the sandbox service's port (8443) only to gateways, both in the
firewall and through the client authority. A host at capacity refuses a run with
`busy`; spreading runs across hosts is the load balancer's job.

Keep the host kernel and the gVisor release in `Dockerfile` up to date. Any
layer can have bugs, which is why there are several.

## Settings

| Variable | Service | Default | Meaning |
|---|---|---|---|
| `SANDBOX_BACKEND` | launcher | `gvisor` | `gvisor` or `runc` |
| `SANDBOX_MAX_RUN_MS` | launcher | `120000` | Longest run the launcher will start |
| `SANDBOX_MEMORY_BYTES` | launcher | 512 MiB | Memory limit per sandbox where the runtime enforces one (`runc`) |
| `SANDBOX_MAX_RUNS` | launcher | `16` | Sandboxes the launcher runs at once, whatever the service asks for |
| `SANDBOX_HOST_MEMORY` | Compose | `4g` | Memory shared by all sandboxes on the host |
| `SANDBOX_CAPACITY` | service | `8` | Runs the host takes at once |
| `SANDBOX_MAX_RUN_MS` | service | `30000` | Run time, including time waiting on tools |
| `SANDBOX_MAX_MEMORY_BYTES` | service | 128 MiB | WebAssembly memory per run |
| `SANDBOX_MAX_CALLS` | service | `64` | Tool calls per run |
| `SANDBOX_MAX_PROGRAM_BYTES` | service | 256 KiB | Program size |
| `SANDBOX_MAX_CONSOLE_BYTES` | service | 256 KiB | Console output per run |
| `SANDBOX_MAX_VALUE_BYTES` | service | 1 MiB | Input, each tool call's arguments and result, and the final result |
| `SANDBOX_TLS_CERT`, `SANDBOX_TLS_KEY`, `SANDBOX_CLIENT_CA` | service | files in `/etc/sandbox/tls` | Certificate, key and client authority |

The service's limits are maximums: a gateway can lower them for a run, never
raise them. Reaching a limit ends the run with an error that names it.

## Protocol

Every hop carries one JSON object per line.

1. The service sends `{"type":"hello","backend":"gvisor"}`.
2. The gateway sends `{"type":"start","source":"...","input":{...},"limits":{...}}`,
   or `{"type":"health"}` for the host's health and self-test results.
3. For each tool call, the service sends
   `{"type":"call","id":1,"proxy":"governed","tool":"lookup","arguments":{...}}`
   and the gateway answers `{"type":"result","id":1,"result":{...}}` or
   `{"type":"error","id":1,"error":{"code":-32002,"message":"Tool call denied"}}`.
4. The run ends with `{"type":"done","result":...,"console":[...]}` or
   `{"type":"failed","failure":{"kind":"limit","message":"..."}}`. Failure
   kinds are `limit`, `exception`, `busy`, `unavailable` and `protocol`.

Inside a program, tools are async functions named by proxy and tool:

```js
const first = await connectors.governed.lookup({ count: input.start });
const rest = await Promise.all([1, 2].map((n) => connectors.governed.lookup({ count: n })));
console.log("found", first.found);
return { first, rest };
```

A refused call rejects with the same code and message a direct caller gets.

## Tests

`go test ./...` in this directory covers the protocol, the launcher's request
checks and container definition, the service's refusals, and the engine's
limits. The image build runs them. CI also starts the whole host with each
backend and runs `tests/sandbox-probe` against it as a gateway would.
