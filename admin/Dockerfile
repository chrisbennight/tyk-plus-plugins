FROM golang:1.26.10-bookworm AS build
WORKDIR /src
COPY --from=mcp-pdp . ./plugins/mcp-pdp
COPY --from=sandbox-protocol . ./sandbox/protocol
COPY . ./admin
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd admin && go test -race ./... && CGO_ENABLED=0 go build -trimpath -o /cedar-admin .

# Runs as the same user as the gateway, which owns the policy store and the
# shared drift directory in the gateway image.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /cedar-admin /cedar-admin
EXPOSE 8000
ENTRYPOINT ["/cedar-admin"]
