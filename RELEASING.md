# Releases

A release publishes three container images to GitHub Container Registry, all
with the same version, and a GitHub release that describes them:

| Image | Contents |
|---|---|
| `ghcr.io/chrisbennight/tyk-plus-plugins/gateway` | Tyk Gateway with the MCP policy plug-in and the shipped policy store |
| `ghcr.io/chrisbennight/tyk-plus-plugins/admin` | The drift review dashboard |
| `ghcr.io/chrisbennight/tyk-plus-plugins/sandbox` | The Code Mode sandbox host, with the gVisor backend only |

The images are for `linux/amd64`. Each is built on a distroless Debian 13 base
with no shell or package manager. The GitHub release lists the image digests
and attaches each image's SBOM and vulnerability report, and the
`cedar-policy` command for managing policy stores.

## Cut a release

Push a tag on `main`: `vX.Y.Z` for a release, or `vX.Y.Z-rc.N` for a release
candidate.

```sh
git tag v0.1.0 origin/main
git push origin v0.1.0
```

Only the repository owner and the project's GitHub App can create `v*` tags,
and no one can move or delete one. Releases are immutable: once published,
neither a release nor its assets can change. If the workflow fails before it
publishes, re-run it for a passing failure such as a network error; a release
that needs a code change gets the next version.

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
   - `govulncheck` finds vulnerable code that one of this repository's
     executables calls.
4. **Attests** each image's build provenance and SBOM with GitHub, and stores
   the attestations in the registry next to the image.
5. **Publishes**: gives the tested images the tags `X.Y.Z`, plus `X.Y` and
   `latest` for a release, without rebuilding them, then publishes the GitHub
   release. Release candidates are marked as pre-releases.

## Verify an image

Use the digest from the release notes. With the
[GitHub CLI](https://cli.github.com/):

```sh
image=ghcr.io/chrisbennight/tyk-plus-plugins/gateway@sha256:...

# Built by this repository's release workflow, from a tag.
gh attestation verify "oci://$image" \
  --repo chrisbennight/tyk-plus-plugins \
  --signer-workflow chrisbennight/tyk-plus-plugins/.github/workflows/release.yml

# The SBOM the release was scanned with.
gh attestation verify "oci://$image" \
  --repo chrisbennight/tyk-plus-plugins \
  --predicate-type https://spdx.dev/Document/v2.3
```

The first check proves the image was built by the release workflow from this
repository at the commit and tag it records, so it was tested and scanned
before it was published. The second proves the attached SBOM describes that
image. Add `--format json` to read either one.

The build also carries the provenance Docker's reusable workflow records and
signs inside the isolated build job.

Verify the `cedar-policy` command from the release assets with:

```sh
gh attestation verify cedar-policy-linux-amd64 --repo chrisbennight/tyk-plus-plugins
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
