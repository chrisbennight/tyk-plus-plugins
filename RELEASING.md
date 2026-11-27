# Releases

A release publishes three container images to GitHub Container Registry, all
with the same version, and a GitHub release that describes them:

| Image | Contents |
|---|---|
| `ghcr.io/chrisbennight/tyk-plus-plugins/gateway` | Tyk Gateway, built from Tyk's source with the same Go release as the MCP policy plug-in, with the plug-in and the shipped policy store |
| `ghcr.io/chrisbennight/tyk-plus-plugins/admin` | The drift review dashboard |
| `ghcr.io/chrisbennight/tyk-plus-plugins/sandbox` | The Code Mode sandbox host, with the gVisor backend only |

The images are for `linux/amd64`. Each is built on a distroless Debian 13 base
with no shell or package manager. The GitHub release lists the image digests
and attaches each image's SBOM and vulnerability report, and the
`cedar-policy` command for managing policy stores.

Without a shell or HTTP client, container health checks run a command each
image ships. Each exits 0 when healthy and 1 otherwise; see
[health checks](README.md#health-checks) for what each one checks.

| Image | Health check command |
|---|---|
| `gateway` | `/opt/tyk-gateway/bin/cedar-policy health` |
| `admin` | `/cedar-admin -healthcheck` |
| `sandbox` (launcher) | `/usr/local/bin/sandbox-launcher -healthcheck` |
| `sandbox` (service) | `/usr/local/bin/sandbox-service -healthcheck` |

## Check a release locally

Before tagging, run the release workflow's image checks on your working tree:

```sh
release/check-local.sh
```

It builds the three images with an SBOM, pushes them to a temporary
registry on your machine, and runs the same checks a release runs on each
image (step 3 below). It keeps going after a check fails, prints what
failed, and keeps the SBOMs and vulnerability reports in the directory it
names. The content check and the vulnerability scan read the SBOM, so if an
image's SBOM cannot be written they are reported as not run. Pass image
names to check only some, and `--out DIR` to choose where the reports go.

The images are built for the platform Docker runs natively. Releases are
`linux/amd64`; on an arm64 machine the images contain the same packages apart
from a few that Go compiles in only for one architecture. `--platform`
chooses another platform, but that build runs under emulation, where the
admin image's race-detector tests crash. The script needs Docker with the
[containerd image store](https://docs.docker.com/engine/storage/containerd/),
`curl`, `column`, `jq` and `python3`. It does not run the Compose tests,
which run on every push.

## Cut a release

Push a tag on `main`: `vX.Y.Z` for a release, or `vX.Y.Z-rc.N` for a release
candidate.

```sh
git tag v0.1.0 origin/main
git push origin v0.1.0
```

Only the repository owner and the project's GitHub App can create `v*` tags,
and no one can move or delete one. Releases are immutable: once published,
neither a release nor its assets can change. If the workflow fails on a
passing problem such as a network error, use **Re-run failed jobs**, which
keeps the images already built; re-running all jobs would rebuild them, and
the workflow refuses to give a version tag to a different image. A release
that needs a code change gets the next version.

The release workflow publishes three packages to GitHub Container Registry
and links them to this repository. The packages take the repository's access
permissions but not its visibility. All three are public, so anyone can pull
and verify the images without signing in. If a release creates a new package
and it is private, make it public in the package's settings.

The [release workflow](.github/workflows/release.yml) then:

1. **Builds** each image once, from the tagged commit, with Docker's
   [reusable Bake workflow](https://github.com/docker/github-builder), which
   runs the build in its own job, records an SBOM and SLSA provenance, and
   signs them. Images are pushed only under a candidate tag,
   `sha-<commit>`.
2. **Tests** those images with the same Compose suites that run on every push.
3. **Checks** each image and blocks the release if:
   - it contains a shell, a package manager or `runc`, or the sandbox launcher
     was built with the development `runc` backend;
   - its SBOM has a critical vulnerability, or a high one that has a fix,
     that [`release/vex.json`](release/vex.json) does not cover;
   - `govulncheck` finds known-vulnerable functions compiled into one of this
     repository's executables. The Go linker leaves out code nothing can
     reach, so these are functions the program may call.
4. **Attests** each image's build provenance and SBOM with GitHub, and stores
   the attestations in the registry next to the image.
5. **Publishes**: gives the tested images the tag `X.Y.Z` without rebuilding
   them, and publishes the GitHub release. For a full release it then moves
   `X.Y` and `latest` to these images, if this is the newest published
   release in their range. Release candidates are marked as pre-releases and
   get only their own tag.

## Verify an image

Use the digest from the release notes. With the
[GitHub CLI](https://cli.github.com/):

```sh
image=ghcr.io/chrisbennight/tyk-plus-plugins/gateway@sha256:...
tag=v0.1.0

# Built by this repository's release workflow, from that tag.
gh attestation verify "oci://$image" \
  --repo chrisbennight/tyk-plus-plugins \
  --signer-workflow chrisbennight/tyk-plus-plugins/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag" \
  --predicate-type https://slsa.dev/provenance/v1

# The SBOM that release was scanned with.
gh attestation verify "oci://$image" \
  --repo chrisbennight/tyk-plus-plugins \
  --signer-workflow chrisbennight/tyk-plus-plugins/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag" \
  --predicate-type https://spdx.dev/Document/v2.3
```

Each check proves that this repository's release workflow, running for that
tag, signed a statement about this exact image: the first its build
provenance, the second its SBOM. The signatures do not record test or scan
results. That the image was tested and scanned first follows from the
workflow at that tag, which signs only after those jobs pass; read it to
confirm. Add `--format json` to see each statement, including the workflow
run that signed it.

The build also carries the provenance Docker's reusable workflow records and
signs inside the isolated build job.

Verify the `cedar-policy` command from the release assets with:

```sh
gh attestation verify cedar-policy-linux-amd64 \
  --repo chrisbennight/tyk-plus-plugins \
  --signer-workflow chrisbennight/tyk-plus-plugins/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag"
```

## Vulnerabilities

Every week, the [rescan workflow](.github/workflows/rescan.yml) scans the
latest release's SBOMs against a fresh vulnerability database with the same
rule as a release, and opens an issue when they no longer pass.

To release despite a finding that does not affect these images, add an
[OpenVEX](https://openvex.dev) statement to `release/vex.json` that names the
vulnerability, the affected package, and the reason it does not apply. The
scan then reports the finding as covered instead of failing. Prefer upgrading
the affected component when a fix exists.
