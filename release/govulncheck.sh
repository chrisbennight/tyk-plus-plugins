#!/usr/bin/env bash
# Runs govulncheck on this repository's Go executables in a release image. It
# reports only vulnerable code the binaries can call, and fails on any. The
# gateway plug-in is not an executable, so the SBOM scan covers it instead.
#
# Usage: release/govulncheck.sh IMAGE@DIGEST
set -euo pipefail

image=$1
binaries=(
  /opt/tyk-gateway/bin/cedar-policy
  /cedar-admin
  /usr/local/bin/sandbox-launcher
  /usr/local/bin/sandbox-service
  /opt/sandbox/rootfs/worker
)
work=$(mktemp -d)
container=
cleanup() {
  if [ -n "$container" ]; then docker rm -f "$container" >/dev/null; fi
  rm -rf "$work"
}
trap cleanup EXIT

container=$(docker create "$image" /none)
docker export "$container" | tar -t > "$work/files"
mkdir "$work/bin"
found=0
for path in "${binaries[@]}"; do
  if grep -qx "${path#/}" "$work/files"; then
    docker cp "$container:$path" "$work/bin/"
    found=1
  fi
done
if [ "$found" -eq 0 ]; then
  echo "$image contains none of this repository's executables" >&2
  exit 1
fi

# The scanner reads the binaries from standard input, as a tar stream, so it
# needs no access to the host's files.
tar -C "$work/bin" -c . | docker run --rm -i golang:1.26.11-trixie@sha256:f9e99477a80ccd7adfb69780510b22c7249ce9169885f18aa762cd886e75e018 sh -ec '
  mkdir /scan && tar -C /scan -x
  status=0
  for binary in /scan/*; do
    echo "== ${binary#/scan/}"
    go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 -mode=binary "$binary" || status=1
  done
  exit $status'
