FROM --platform=linux/amd64 tykio/tyk-plugin-compiler:v5.16.0 AS tyk
FROM golang:1.26.10-bookworm AS compiler
WORKDIR /src
COPY --from=tyk /go/src/github.com/TykTechnologies/tyk ./tyk
COPY cedar ./cedar
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go work init ./tyk ./cedar && cd cedar && \
    go build -trimpath -tags=goplugin -buildmode=plugin -o /cedar.so .

FROM tykio/tyk-gateway:v5.16.0
COPY --from=compiler /cedar.so /opt/tyk-gateway/middleware/cedar.so
COPY tyk.conf /opt/tyk-gateway/tyk.conf
COPY apps /opt/tyk-gateway/mcp-apps
COPY policy /opt/tyk-gateway/cedar
