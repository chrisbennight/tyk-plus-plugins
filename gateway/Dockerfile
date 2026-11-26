# Tyk's source for the release below, as Tyk ships it for building plug-ins.
FROM --platform=linux/amd64 tykio/tyk-plugin-compiler:v5.16.0@sha256:ae914c7906034fe7bbaa4175bcffea18cd055be2777990a4b06431041bd54cfa AS tyk
# Tyk and the plug-in are built here together: a Go plug-in loads only into a
# binary built with the same Go release and the same dependencies, and
# building Tyk ourselves lets it take Go fixes without waiting for Tyk.
FROM golang:1.26.11-trixie@sha256:f9e99477a80ccd7adfb69780510b22c7249ce9169885f18aa762cd886e75e018 AS compiler
WORKDIR /src
COPY --from=tyk /go/src/github.com/TykTechnologies/tyk ./tyk
COPY --from=mcp-pdp . ./plugins/mcp-pdp
# The plug-in shares the sandbox host's message format, which has no
# dependencies of its own.
COPY --from=sandbox-protocol . ./sandbox/protocol
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go work init ./tyk ./plugins/mcp-pdp ./sandbox/protocol && cd plugins/mcp-pdp && \
    go test -race ./policy/ ./identity/ ./bench/ ./drift/ ./cmd/cedar-policy/ ./driftreview/ ./codemode/ && \
    go build -trimpath -tags=goplugin -buildmode=plugin -o /mcp-pdp.so . && \
    CGO_ENABLED=0 go build -trimpath -o /cedar-policy ./cmd/cedar-policy
# The open-source gateway as Tyk's own release builds it (the "std" build in
# ci/goreleaser/goreleaser.yml, without the commercially licensed "ee" code).
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd tyk && build=github.com/TykTechnologies/tyk/internal/build && \
    go build -trimpath -tags=goplugin -o /tyk -ldflags "\
      -X $build.Version=$(git describe --tags --exact-match | sed 's/^v//') \
      -X $build.Commit=$(git rev-parse HEAD) \
      -X $build.BuiltBy=tyk-plus-plugins" . && \
    /tyk version && test "$(/tyk version | sed -n 's/^Go version: *//p')" = "$(go env GOVERSION)"
# The default store activates the shipped policy, which grants nothing.
COPY policy/rules.cedar policy/approved_tools.json policy/approved_instructions.json policy/checks.json /default-policy/
RUN /cedar-policy promote -store /store -label default /default-policy && mkdir /status /pending

# Tyk's image provides the gateway's files and its distroless Debian 13 base;
# its binary is replaced with the one built above.
FROM tykio/tyk-gateway:v5.16.0@sha256:7af43f37fcae9bccf050c934e51a2ba710c48b5916290da13ef36fcdee3c60c1 AS gateway
COPY --from=compiler /tyk /opt/tyk-gateway/tyk
COPY --from=compiler /mcp-pdp.so /opt/tyk-gateway/middleware/mcp-pdp.so
COPY --from=compiler /cedar-policy /opt/tyk-gateway/bin/cedar-policy
COPY tyk.conf /opt/tyk-gateway/tyk.conf
COPY apps /opt/tyk-gateway/mcp-apps
COPY policies /opt/tyk-gateway/policies
# The gateway reads the store; the review dashboard, running as the same
# user, writes it when the two share a volume.
COPY --from=compiler --chown=65532:65532 /store /opt/tyk-gateway/cedar
# The gateway's user writes its enforcement report here.
COPY --from=compiler --chown=65532:65532 /status /opt/tyk-gateway/cedar-status
# Gateways share what upstreams declare, and queue changes for review, here.
COPY --from=compiler --chown=65532:65532 /pending /opt/tyk-gateway/cedar-pending

# Tests only: a second proxy, made from the shipped one, so Code Mode can be
# tested calling tools across proxies. Build it with the target "test". It
# needs no compiled code, so the release workflow can add it to a released
# gateway image without rebuilding the plug-in.
FROM golang:1.26.11-trixie@sha256:f9e99477a80ccd7adfb69780510b22c7249ce9169885f18aa762cd886e75e018 AS second-proxy
COPY apps /apps
RUN mkdir /second && for suffix in "" -mcp; do \
      sed -e 's/"governed"/"governed2"/' -e 's#"/mcp/"#"/mcp2/"#' -e 's/"Governed MCP"/"Governed MCP 2"/' \
        "/apps/governed$suffix.json" > "/second/governed2$suffix.json"; \
    done && grep -q '"governed2"' /second/governed2.json /second/governed2-mcp.json

FROM gateway AS test
COPY --from=second-proxy /second/ /opt/tyk-gateway/mcp-apps/

FROM gateway
