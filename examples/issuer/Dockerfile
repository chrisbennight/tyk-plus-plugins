FROM golang:1.26.11-trixie AS build
WORKDIR /src
COPY . .
RUN go vet ./... && go test -race ./... && CGO_ENABLED=0 go build -mod=readonly -trimpath -o /issuer .

FROM scratch
COPY --from=build /issuer /issuer
# Inside its container the issuer must accept connections from other containers.
ENV ISSUER_LISTEN=:8000
EXPOSE 8000
ENTRYPOINT ["/issuer"]
