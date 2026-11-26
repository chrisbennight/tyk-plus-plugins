#!/usr/bin/env bash
# Fails if a release image contains anything production does not need: a
# shell, a package manager, runc, or a sandbox launcher built with the
# development runc backend. It checks both the image's files and its SBOM.
#
# Usage: release/check-image.sh IMAGE@DIGEST SBOM.spdx.json
set -euo pipefail

image=$1
sbom=$2
work=$(mktemp -d)
container=
cleanup() {
  if [ -n "$container" ]; then docker rm -f "$container" >/dev/null; fi
  rm -rf "$work"
}
trap cleanup EXIT

forbidden='^(sh|bash|dash|ash|zsh|busybox|toybox|apt|apt-get|aptitude|dpkg|rpm|apk|yum|dnf|microdnf|runc)$'
failed=0

# Release images have no command of their own to start, so give one that is
# never run.
container=$(docker create "$image" /none)
docker export "$container" | tar -t > "$work/files"
while IFS= read -r path; do
  case "$path" in
    */) continue ;;
    bin/* | sbin/* | */bin/* | */sbin/* | */libexec/*) ;;
    *) continue ;;
  esac
  if [[ "${path##*/}" =~ $forbidden ]]; then
    echo "$image contains /$path" >&2
    failed=1
  fi
done < "$work/files"

# Debian packages and Go modules for the same tools, as the SBOM lists them.
jq -r --arg re "$forbidden" '
  .packages[]
  | (.externalRefs // [])[]
  | select(.referenceType == "purl")
  | .referenceLocator
  | select(
      (startswith("pkg:deb/") and (ltrimstr("pkg:deb/") | split("/")[1] | split("@")[0] | test($re)))
      or startswith("pkg:golang/github.com/opencontainers/runc@")
    )' "$sbom" | sort -u > "$work/packages"
if [ -s "$work/packages" ]; then
  sed "s|^|$image SBOM lists |" "$work/packages" >&2
  failed=1
fi

# The sandbox launcher includes the runc backend only when built with the
# "dev" tag, which Go records in the binary.
if grep -qx 'usr/local/bin/sandbox-launcher' "$work/files"; then
  docker cp "$container:/usr/local/bin/sandbox-launcher" "$work/sandbox-launcher"
  docker run --rm -i --network none golang:1.26.11-trixie \
    sh -c 'cat > /tmp/sandbox-launcher && go version -m /tmp/sandbox-launcher' \
    < "$work/sandbox-launcher" > "$work/buildinfo"
  if grep -E '^[[:space:]]+build[[:space:]]+-tags=' "$work/buildinfo" | grep -qw dev; then
    echo "$image has a sandbox launcher built with the development runc backend" >&2
    failed=1
  fi
fi

if [ "$failed" -ne 0 ]; then exit 1; fi
echo "$image: no shell, package manager or runc"
