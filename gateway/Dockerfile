FROM --platform=linux/amd64 tykio/tyk-plugin-compiler:v5.16.0 AS tyk
FROM golang:1.26.10-bookworm AS compiler
WORKDIR /src
COPY --from=tyk /go/src/github.com/TykTechnologies/tyk ./tyk
COPY --from=mcp-pdp . ./mcp-pdp
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go work init ./tyk ./mcp-pdp && cd mcp-pdp && \
    go test -race ./policy/ ./identity/ ./bench/ && \
    go build -trimpath -tags=goplugin -buildmode=plugin -o /mcp-pdp.so . && \
    CGO_ENABLED=0 go build -trimpath -o /cedar-policy ./cmd/cedar-policy
# The default store activates the shipped policy, which grants nothing.
COPY policy/rules.cedar policy/approved_tools.json policy/approved_instructions.json policy/checks.json /default-policy/
RUN /cedar-policy promote -store /store -label default /default-policy && mkdir /status

FROM tykio/tyk-gateway:v5.16.0
COPY --from=compiler /mcp-pdp.so /opt/tyk-gateway/middleware/mcp-pdp.so
COPY --from=compiler /cedar-policy /opt/tyk-gateway/bin/cedar-policy
COPY tyk.conf /opt/tyk-gateway/tyk.conf
COPY apps /opt/tyk-gateway/mcp-apps
COPY policies /opt/tyk-gateway/policies
COPY --from=compiler /store /opt/tyk-gateway/cedar
# The gateway's user writes its enforcement report here.
COPY --from=compiler --chown=65532:65532 /status /opt/tyk-gateway/cedar-status
