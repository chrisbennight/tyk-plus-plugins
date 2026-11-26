#!/usr/bin/env bash
# Runs the release workflow's image checks on this working tree, so a problem
# shows up before a tag is pushed. It builds the release images with an SBOM,
# pushes them to a temporary registry on this machine, and runs the same
# scripts the release workflow runs on each: the SBOM, the check for a shell,
# a package manager or runc, the vulnerability scan, and govulncheck. It runs
# every check on every image and exits nonzero if any failed.
#
# The images are built from the working tree, uncommitted changes included,
# where a release builds from the tagged commit. The Compose tests are not
# run here; they run on every push.
#
# Usage: release/check-local.sh [--platform PLATFORM] [--out DIR] [IMAGE...]
#
# IMAGE is gateway, admin or sandbox; the default is all three. PLATFORM is
# the one Docker runs natively unless given. Releases are linux/amd64; on an
# arm64 machine the images contain the same packages apart from a few that
# Go compiles in only for one architecture. Building for another platform
# runs under emulation, where the admin image's race-detector tests crash.
# Reports are written to DIR, a new temporary directory unless given.
#
# Needs Docker with the containerd image store, which can push images with
# SBOMs attached, plus jq and python3.
set -euo pipefail

platform=
out=
images=()
while [ $# -gt 0 ]; do
  case $1 in
    --platform) platform=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    gateway|admin|sandbox) images+=("$1"); shift ;;
    *) echo "usage: $0 [--platform PLATFORM] [--out DIR] [gateway|admin|sandbox...]" >&2; exit 2 ;;
  esac
done
if [ ${#images[@]} -eq 0 ]; then images=(gateway admin sandbox); fi
if [ -z "$platform" ]; then platform=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}'); fi

root=$(cd "$(dirname "$0")/.." && pwd)
release=$root/release
if [ -z "$out" ]; then out=$(mktemp -d); fi
mkdir -p "$out"
out=$(cd "$out" && pwd)
version=$(git -C "$root" describe --tags --always --dirty)

if ! docker info --format '{{json .DriverStatus}}' | grep -q io.containerd.snapshotter; then
  echo "Docker must use the containerd image store to push images with an SBOM attached." >&2
  echo "See https://docs.docker.com/engine/storage/containerd/" >&2
  exit 2
fi

registry=registry:3@sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c
container=
pushed=()
cleanup() {
  # Checking an image pulls it into Docker; remove what this run added.
  for ref in ${pushed[@]+"${pushed[@]}"}; do
    docker image rm "$ref" >/dev/null 2>&1 || true
  done
  if [ -n "$container" ]; then docker rm -f "$container" >/dev/null; fi
}
trap cleanup EXIT

container=$(docker run -d -p 127.0.0.1::5000 "$registry")
port=$(docker port "$container" 5000/tcp | head -n 1)
port=${port##*:}
host=localhost:$port
for _ in $(seq 50); do
  if curl -fsS -o /dev/null "http://$host/v2/"; then break; fi
  sleep 0.2
done
curl -fsS -o /dev/null "http://$host/v2/"

# The builder named after the Docker context uses the docker driver, which
# pushes through Docker itself and so reaches the registry on localhost.
bake_args=(--builder "$(docker context show)" -f "$root/docker-bake.hcl"
  --set "*.platform=$platform" --set "*.attest=type=sbom"
  --metadata-file "$out/build.json")
for name in "${images[@]}"; do
  bake_args+=(--set "$name.tags=$host/$name:check" --set "$name.output=type=registry")
done
echo "Building ${images[*]} for $platform"
(cd "$root" && docker buildx bake "${bake_args[@]}" "${images[@]}")

export IMAGE_PLATFORM=$platform
failures=()
for name in "${images[@]}"; do
  digest=$(jq -r --arg name "$name" '.[$name]["containerimage.digest"]' "$out/build.json")
  image=$host/$name@$digest
  pushed+=("$image" "$host/$name:check")
  echo
  echo "== $name ($digest)"

  if ! "$release/sbom.sh" "$image" "$version" > "$out/$name.spdx.json"; then
    failures+=("$name: could not write the SBOM")
    continue
  fi
  if ! "$release/check-image.sh" "$image" "$out/$name.spdx.json"; then
    failures+=("$name: contains a shell, a package manager or runc")
  fi
  status=0
  "$release/scan.sh" "$out/$name.spdx.json" "$out/$name.vulnerabilities.json" \
    | tee "$out/$name.vulnerabilities.txt" || status=$?
  case $status in
    0) ;;
    3) failures+=("$name: has a critical vulnerability, or a high one with a fix") ;;
    *) failures+=("$name: the vulnerability scan did not complete") ;;
  esac
  if ! "$release/govulncheck.sh" "$image"; then
    failures+=("$name: govulncheck found vulnerable code the binaries can call, or did not complete")
  fi
done

echo
echo "Reports: $out"
if [ ${#failures[@]} -ne 0 ]; then
  printf '%s\n' "${failures[@]}" >&2
  exit 1
fi
echo "All release checks passed for ${images[*]}."
