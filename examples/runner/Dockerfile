# Built from the examples directory, so the tests can compare the policy's
# activation checks with expected.json.
FROM golang:1.26.10-bookworm AS build
WORKDIR /src
COPY . .
WORKDIR /src/runner
RUN go vet ./... && go test ./... && CGO_ENABLED=0 go build -mod=readonly -trimpath -o /runner .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /runner /runner
ENTRYPOINT ["/runner"]
