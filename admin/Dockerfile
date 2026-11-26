FROM golang:1.26.11-trixie@sha256:f9e99477a80ccd7adfb69780510b22c7249ce9169885f18aa762cd886e75e018 AS build
WORKDIR /src
COPY --from=mcp-pdp . ./plugins/mcp-pdp
COPY --from=sandbox-protocol . ./sandbox/protocol
COPY . ./admin
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd admin && go test -race ./... && CGO_ENABLED=0 go build -trimpath -o /cedar-admin .

# Runs as the same user as the gateway, which owns the policy store and the
# shared drift directory in the gateway image.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
COPY --from=build /cedar-admin /cedar-admin
EXPOSE 8000
ENTRYPOINT ["/cedar-admin"]
