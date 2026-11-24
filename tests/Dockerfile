FROM golang:1.26.10-bookworm AS build
WORKDIR /src
COPY upstream/ .
RUN CGO_ENABLED=0 go build -mod=readonly -o /upstream .

# The older-only upstream is the same server built on an SDK release that
# speaks only the older protocol.
FROM golang:1.26.10-bookworm AS legacy-build
WORKDIR /src
COPY upstream-legacy/go.mod upstream-legacy/go.sum ./
COPY upstream/main.go .
RUN CGO_ENABLED=0 go build -mod=readonly -o /upstream .

FROM golang:1.26.10-bookworm AS probe-build
WORKDIR /src
COPY probe/ .
RUN CGO_ENABLED=0 go build -mod=readonly -o /probe .

FROM scratch AS upstream
COPY --from=build /upstream /upstream
ENTRYPOINT ["/upstream"]

FROM scratch AS upstream-legacy
COPY --from=legacy-build /upstream /upstream
ENTRYPOINT ["/upstream"]

FROM scratch AS probe
COPY --from=probe-build /probe /probe
ENTRYPOINT ["/probe"]

FROM golang:1.26.10-bookworm AS sandbox-probe-build
WORKDIR /src
COPY sandbox-probe/ .
RUN CGO_ENABLED=0 go build -mod=readonly -o /sandbox-probe .

FROM scratch AS sandbox-probe
COPY --from=sandbox-probe-build /sandbox-probe /sandbox-probe
ENTRYPOINT ["/sandbox-probe"]
