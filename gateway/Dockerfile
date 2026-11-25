FROM --platform=linux/amd64 tykio/tyk-plugin-compiler:v5.16.0 AS tyk
FROM golang:1.26.10-bookworm AS compiler
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
# The default store activates the shipped policy, which grants nothing.
COPY policy/rules.cedar policy/approved_tools.json policy/approved_instructions.json policy/checks.json /default-policy/
RUN /cedar-policy promote -store /store -label default /default-policy && mkdir /status /pending

FROM tykio/tyk-gateway:v5.16.0 AS gateway
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
# tested calling tools across proxies. Build it with the target "test".
FROM compiler AS second-proxy
COPY apps /apps
RUN mkdir /second && for suffix in "" -mcp; do \
      sed -e 's/"governed"/"governed2"/' -e 's#"/mcp/"#"/mcp2/"#' -e 's/"Governed MCP"/"Governed MCP 2"/' \
        "/apps/governed$suffix.json" > "/second/governed2$suffix.json"; \
    done && grep -q '"governed2"' /second/governed2.json /second/governed2-mcp.json

FROM gateway AS test
COPY --from=second-proxy /second/ /opt/tyk-gateway/mcp-apps/

FROM gateway
