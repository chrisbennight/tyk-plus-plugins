# Built from the examples directory, so the tests can read the examples' files.
# The check that policy/checks.json matches expected.json is left to "runner
# run", which refuses to start while they differ; failing the build instead
# would also block the runner that regenerates them.
FROM golang:1.26.10-bookworm AS build
WORKDIR /src
COPY . .
WORKDIR /src/runner
RUN go vet ./... && go test -skip TestCommittedChecksMatchExpected ./... && CGO_ENABLED=0 go build -mod=readonly -trimpath -o /runner .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /runner /runner
ENTRYPOINT ["/runner"]
