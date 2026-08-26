# Release Process

This document defines the release requirements for k8s-breakglass. It is intended to meet OpenSSF Best Practices and Scorecard expectations for signed, verifiable releases.

The separate `Catalogue utility integration` workflow is the required
real-tool proof for the `network-debug` and `node-maintenance` images. It is a
matrix job, builds both `linux/amd64` and `linux/arm64` OCI artifacts, and
executes each image's command on the real runtime; it is not duplicated in the
ordinary controller CI suite.

## Goals

- Publish reproducible, verifiable release artifacts
- Provide provenance for supply-chain integrity
- Ensure releases are reviewed and auditable

## Release Requirements

1. **Release review**
   - All release PRs require at least one approving review.
   - CI checks must be green on the release commit.

2. **Checksums**
   - Publish SHA-256 checksums for every release payload artifact.
   - `release-<tag>-checksums.txt` covers manifests, all Helm chart packages, `bgctl` archives, and the SPDX SBOM.
   - Entries in `release-<tag>-checksums.txt` use downloaded asset filenames, without workflow staging directories.
   - `bgctl_<tag>_checksums.txt` and per-archive `.sha256` files are kept for CLI-only consumers.

3. **Release notes**
   - Include a summary of changes, security notes, and upgrade guidance.

4. **Provenance**
   - SLSA-compatible provenance is generated for every release image using `actions/attest-build-provenance` in the assemble job.
   - Provenance attestations are pushed to the container registry alongside the image.

5. **SBOM**
   - An SPDX-JSON SBOM is generated for each release image using Syft (`anchore/sbom-action`).
   - The SBOM is attached to the GitHub Release (via `GH_PUBLISH_TOKEN` when available, or as a workflow artifact otherwise).

6. **Artifact signing**
   - Release images are signed using keyless Sigstore Cosign (OIDC-based, no static keys).
   - An SPDX-JSON SBOM attestation is attached to each signed image via `cosign attest`.
   - Cosign signatures and attestations are mirrored to Artifactory on a best-effort basis via `cosign copy`.

7. **Helm chart publication**
   - `charts/escalation-config` and `charts/debug-session-catalogue` are packaged during release preparation.
   - Each packaged chart is pushed to GHCR as a Helm OCI artifact below `oci://ghcr.io/telekom/k8s-breakglass/charts/<chart-name>`.
   - Published catalogue charts are keylessly Cosign-signed and carry SPDX
     SBOM plus SLSA provenance attestations on the OCI manifest digest.
   - Chart `.tgz` packages are attached to the GitHub Release assets and included in release checksums.
   - Every release tag that changes a packaged chart `appVersion` must use a unique chart `version` in that chart's `Chart.yaml`. Release reruns may skip an already-published chart only when the remote chart `appVersion` matches the release tag.

## Multi-Architecture Builds

Release images are built as multi-arch manifests supporting both `linux/amd64` and `linux/arm64` platforms. Each architecture is built natively on a dedicated runner (no QEMU emulation), then assembled into a single multi-arch manifest list.

**Build pipeline:**

1. **Prepare** — generates Kustomize manifests, packages both Helm charts, cross-compiles `bgctl` binaries for all OS/arch combinations, and uploads them as artifacts.
2. **Build** (matrix: `amd64`, `arm64`) — builds and pushes a single-platform image by digest on a native runner for each architecture.
3. **Assemble** — downloads all per-arch digests and creates a unified multi-arch manifest tagged with the release version. Stable `vX.Y.Z` tags also update `latest`; prerelease tags such as `vX.Y.Z-rc.1` keep only their explicit version tag. Tags with SemVer build metadata (`+build`) are rejected because Docker image tags cannot contain `+`. Generates SLSA provenance attestation, signs the image with keyless Cosign, and attaches an SBOM attestation.
4. **Artifactory** — mirrors the multi-arch image and cosign artifacts (signatures + attestations) to the internal Artifactory OCI registry (best-effort).
5. **Publish charts** — pushes both charts to GHCR Helm OCI (`oci://ghcr.io/telekom/k8s-breakglass/charts`).
6. **Release** — creates a GitHub Release with manifests, Helm chart packages, `bgctl` binaries, release-wide checksums, CLI archive checksums, and SBOM (SPDX-JSON format via Syft).

> **Note:** Buildx layer caching (`cache-from`/`cache-to`) is intentionally omitted in
> release builds to ensure clean, reproducible images without layer reuse from prior
> development iterations.

## Utility image releases

Standalone utility images are built by the separate `Utility image release`
workflow. Its explicit `hack/utility-image-matrix.json` inventory selects
publishable images, so nested test fixtures are excluded and images may use
either colocated or shared Makefiles. Add each new utility's name, context, and
Dockerfile to that inventory. The workflow builds each image independently for
`linux/amd64` and `linux/arm64`, and publishes it at
`ghcr.io/telekom/k8s-breakglass/utils/<intent>`.

Every declared image and platform is built on pull requests and `main`, then
run with its inventory-declared reference smoke command. The release gate also
requires the explicit core checks in `hack/release-required-checks.json` and
each image's uniquely named dedicated behavior checks. A new network, collector,
or other utility becomes publishable only after its inventory entry, smoke
contract, and dedicated checks have reached `main` successfully.
Its dedicated workflow must retain an unfiltered `push` trigger for `main` so
that the exact release commit always has those required check results.
The separate `Utility image security` workflow rebuilds every declared image
for both supported platforms and scans the exact local image produced by that
build with Trivy. It fails on fixed or actionable `HIGH` and `CRITICAL` OS or
library vulnerabilities (`ignore-unfixed=true`); it is intentionally separate
from the controller-image scan in `security.yml` and is included in the release
required-check inventory.

On a controller release tag, every utility is published under a unique
`dev-<commit>-<run>-<attempt>` tag; the release version itself is deliberately
not assigned as a mutable registry tag. The weekly scheduled rebuild publishes
only the mutable `nightly` tag. Release artifacts are addressed by their
immutable digest, and their source must be on `main` with successful CI. The
workflow first publishes an untagged, digest-addressed staging image, resolves
its exact two platform subjects, generates and validates complete SPDX SBOMs,
publishes GitHub-native provenance, and signs/attests the index and platform
digests. `hack/publish-utility-tag.sh` then performs the full signature, SBOM,
provenance, platform, and reference-pull verification against those digests;
only a successful verification can reach the unique dev-tag assignment. The
tag binding is checked again after the write. Consumers should pin the digest,
and may retain the unique tag for discovery,
for example:

```yaml
image: ghcr.io/telekom/k8s-breakglass/utils/workload-debug:dev-<commit>-<run>-<attempt>@sha256:<manifest-digest>
```

This unique-tag-plus-digest form lets tooling discover the build while the
digest remains the immutable pull reference. A partial matrix rerun accepts
an existing unique tag only when its index and platform signatures, SBOMs,
provenance, source SHA/ref, and reference pulls all verify against this exact
workflow; a missing or competing claim fails closed rather than overwriting it.

Before a release is approved, maintainers may manually dispatch the workflow
from the `main` branch with `publish_rolling=true`. This publishes every
declared utility to the mutable `rolling` tag for integration testing. The
rolling channel is intentionally overwriteable and is never a release input;
consumers must use a signed digest and must not treat `rolling` as an immutable
deployment reference. A dispatch from another branch, or without the explicit
input, is rejected. The weekly `nightly` channel has the same mutable-tag
semantics.

The OCI Distribution API does not define an atomic create-only manifest PUT for
tags, and GHCR does not provide one for this workflow. The release path
therefore never assigns stable version tags: it uses a unique commit/run/attempt
tag only as a discovery handle and consumes the attested digest. `nightly` and
`rolling` remain intentionally mutable and use the overwrite-capable path with
post-write verification.

Release-matrix integration harnesses use the same ownership boundary. A Kind
cluster is removable only through the exact Docker node IDs captured after a
successful create; failed creates and same-name node replacement are leaked
for inspection. Kubernetes Pod, PVC, PV, namespace, and fixture cleanup uses
the API server's UID precondition on DELETE, so a replacement between
observation and cleanup is preserved. Locally built images are removed only when
the harness can prove ownership from the captured immutable image ID; otherwise
they are left for the runner's managed cleanup. The harness does not race a
mutable image tag during teardown.

## Release Checklist

- Verify CI success on the release commit.
- Ensure the changelog is up to date.
- Use `vX.Y.Z` tags for stable releases and `vX.Y.Z-rc.1` style tags for prereleases. Do not use SemVer build metadata in release tags.
- Bump the applicable chart's `version` before cutting a release whose chart `appVersion` has not already been published under that chart version. The catalogue's map-to-list migration is a breaking values-interface change recorded by its `0.2.0` chart version.
- Generate artifacts via the release workflow.
- Verify both chart publications in GHCR (`.../charts/escalation-config` and `.../charts/debug-session-catalogue`).
- For a catalogue release, verify every rendered utility image is a
  linux/amd64 + linux/arm64 digest reference and run
  `hack/verify-catalogue-supply-chain.sh` against the published chart digest.
- Publish checksums and update release notes.
- Verify provenance attestation was pushed to the registry.
- Verify SBOM is attached to the GitHub Release.
- Verify prerelease tags are marked as GitHub prereleases and do not become the repository's Latest release.
- Verify Cosign signature was pushed to the registry.

## Verification

Consumers should be able to:

- Confirm checksums match the downloaded artifacts.
- Verify provenance attestation via `gh attestation verify` or the GitHub attestation API.
- Verify SBOM contents match the release image.
- Verify Cosign signature: `cosign verify ghcr.io/telekom/k8s-breakglass@<digest> --certificate-identity-regexp='https://github.com/telekom/k8s-breakglass/' --certificate-oidc-issuer='https://token.actions.githubusercontent.com'`
- Verify Helm chart availability:
   ```bash
   helm show chart oci://ghcr.io/telekom/k8s-breakglass/charts/debug-session-catalogue \
      --version <chart-version>
   ```
  - Confirm the returned `version` is the expected chart version and `appVersion` is the release tag.
- Verify SBOM attestation:
  ```bash
  cosign verify-attestation ghcr.io/telekom/k8s-breakglass@<digest> \
    --type spdxjson \
    --certificate-identity-regexp='https://github.com/telekom/k8s-breakglass/' \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
    | jq -r '.payload' | base64 -d | jq
  ```
