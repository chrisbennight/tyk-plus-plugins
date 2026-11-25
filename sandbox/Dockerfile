# The sandbox host image: the network-facing sandbox service, the root launcher
# helper, the gVisor runtime, and the read-only worker image every sandbox
# runs. The "dev" target adds runc for machines without gVisor.
FROM golang:1.26.10-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY protocol/go.mod protocol/
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go vet ./... && go test -race ./... && (cd protocol && go vet ./... && go test -race ./...) && \
    CGO_ENABLED=0 go build -trimpath -o /out/ ./cmd/sandbox-launcher ./cmd/sandbox-service ./cmd/sandbox-worker && \
    mkdir -p /rootfs/proc /rootfs/dev /rootfs/scratch && chmod 0777 /rootfs/scratch && \
    cp /out/sandbox-worker /rootfs/worker && \
    /out/sandbox-worker precompile /rootfs/cache

FROM debian:bookworm-slim AS gvisor
# gVisor release 20261116.0, verified against checksums recorded when it was
# chosen rather than ones fetched alongside the download.
ARG TARGETARCH
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates curl zstd >/dev/null && \
    case "${TARGETARCH}" in \
      amd64) ARCH=x86_64 SUM=a34261504066142b6c1cc4d1813bb2d092761675416e350edc98c4cc66469b63b6f41acdeed09681b6c717c00e80e437f5f2f9c8d37705b8a9260632867c2b7d ;; \
      arm64) ARCH=aarch64 SUM=4f95f25e09e856dd868e05a1ea5ee394bbe0ad0843ece141d161ac592385ee61eb654575c3b71fc6eab974eaa51028ed1a736f4821b4d462c3470b1e6616d5f3 ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/gvisor.tar.zstd "https://storage.googleapis.com/gvisor/releases/release/20261116.0/${ARCH}/gvisor.tar.zstd" && \
    echo "${SUM}  /tmp/gvisor.tar.zstd" | sha512sum -c - && \
    mkdir /gvisor && tar --zstd -xf /tmp/gvisor.tar.zstd -C /gvisor

# Development only: adds runc, for machines without gVisor. Never released;
# select it with the target "dev", as compose.runc.yaml does.
FROM debian:bookworm-slim AS dev
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends runc >/dev/null && rm -rf /var/lib/apt/lists/*
COPY --from=gvisor /gvisor/runsc /usr/local/bin/runsc
COPY --from=gvisor /gvisor/gvisor-bin/gvisor_sentry /gvisor/gvisor-bin/gvisor-sentry-prewarmer /gvisor/gvisor-bin/gvisor-proc-umounter /gvisor/gvisor-bin/runsc-fd-parking /usr/local/bin/gvisor-bin/
COPY --from=build /out/sandbox-launcher /out/sandbox-service /usr/local/bin/
COPY --from=build /rootfs /opt/sandbox/rootfs
RUN runsc --version && runc --version

# The released image: only what the gVisor backend needs, on a distroless
# base with no shell or package manager. It is the default target.
FROM gcr.io/distroless/static-debian12 AS release
COPY --from=gvisor /gvisor/runsc /usr/local/bin/runsc
COPY --from=gvisor /gvisor/gvisor-bin/gvisor_sentry /gvisor/gvisor-bin/gvisor-sentry-prewarmer /gvisor/gvisor-bin/gvisor-proc-umounter /gvisor/gvisor-bin/runsc-fd-parking /usr/local/bin/gvisor-bin/
COPY --from=build /out/sandbox-launcher /out/sandbox-service /usr/local/bin/
COPY --from=build /rootfs /opt/sandbox/rootfs
RUN ["/usr/local/bin/runsc", "--version"]
