FROM golang:1.26.10-bookworm AS build
WORKDIR /src
COPY upstream/ .
RUN CGO_ENABLED=0 go build -mod=readonly -o /upstream .

FROM golang:1.26.10-bookworm AS issuer-build
WORKDIR /src
COPY issuer/ .
RUN CGO_ENABLED=0 go build -mod=readonly -o /issuer .

FROM scratch AS issuer
COPY --from=issuer-build /issuer /issuer
ENTRYPOINT ["/issuer"]

FROM scratch AS upstream
COPY --from=build /upstream /upstream
ENTRYPOINT ["/upstream"]

FROM python:3.13-alpine AS probe
COPY integration.py /integration.py
CMD ["python", "/integration.py"]
