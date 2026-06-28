# Release Process

This document defines the release requirements for k8s-breakglass. It is intended to meet OpenSSF Best Practices and Scorecard expectations for signed, verifiable releases.

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
   - `release-<tag>-checksums.txt` covers manifests, Helm chart package, `bgctl` archives, and the SPDX SBOM.
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
   - `charts/escalation-config` is packaged during release preparation.
   - The packaged chart is pushed to GHCR as a Helm OCI artifact at `oci://ghcr.io/telekom/k8s-breakglass/charts/escalation-config`.
   - The chart `.tgz` is attached to the GitHub Release assets.
   - Every release tag that changes the packaged chart `appVersion` must use a unique chart `version` in `charts/escalation-config/Chart.yaml`. Release reruns may skip an already-published chart only when the remote chart `appVersion` matches the release tag.

## Multi-Architecture Builds

Release images are built as multi-arch manifests supporting both `linux/amd64` and `linux/arm64` platforms. Each architecture is built natively on a dedicated runner (no QEMU emulation), then assembled into a single multi-arch manifest list.

**Build pipeline:**

1. **Prepare** — generates Kustomize manifests, packages `charts/escalation-config`, cross-compiles `bgctl` binaries for all OS/arch combinations, and uploads them as artifacts.
2. **Build** (matrix: `amd64`, `arm64`) — builds and pushes a single-platform image by digest on a native runner for each architecture.
3. **Assemble** — downloads all per-arch digests and creates a unified multi-arch manifest tagged with the release version. Stable `vX.Y.Z` tags also update `latest`; prerelease tags such as `vX.Y.Z-rc.1` keep only their explicit version tag. Tags with SemVer build metadata (`+build`) are rejected because Docker image tags cannot contain `+`. Generates SLSA provenance attestation, signs the image with keyless Cosign, and attaches an SBOM attestation.
4. **Artifactory** — mirrors the multi-arch image and cosign artifacts (signatures + attestations) to the internal Artifactory OCI registry (best-effort).
5. **Publish chart** — pushes `escalation-config` chart to GHCR Helm OCI (`oci://ghcr.io/telekom/k8s-breakglass/charts`).
6. **Release** — creates a GitHub Release with manifests, Helm chart package, `bgctl` binaries, release-wide checksums, CLI archive checksums, and SBOM (SPDX-JSON format via Syft).

> **Note:** Buildx layer caching (`cache-from`/`cache-to`) is intentionally omitted in
> release builds to ensure clean, reproducible images without layer reuse from prior
> development iterations.

## Release Checklist

- Verify CI success on the release commit.
- Ensure the changelog is up to date.
- Use `vX.Y.Z` tags for stable releases and `vX.Y.Z-rc.1` style tags for prereleases. Do not use SemVer build metadata in release tags.
- Bump `charts/escalation-config/Chart.yaml` `version` before cutting a release whose chart `appVersion` has not already been published under that chart version.
- Generate artifacts via the release workflow.
- Verify chart publication in GHCR (`oci://ghcr.io/telekom/k8s-breakglass/charts/escalation-config`).
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
   helm show chart oci://ghcr.io/telekom/k8s-breakglass/charts/escalation-config \
      --version <chart-version>
   ```
  Confirm the returned `version` is the expected chart version and `appVersion` is the release tag.
- Verify SBOM attestation:
  ```bash
  cosign verify-attestation ghcr.io/telekom/k8s-breakglass@<digest> \
    --type spdxjson \
    --certificate-identity-regexp='https://github.com/telekom/k8s-breakglass/' \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
    | jq -r '.payload' | base64 -d | jq
  ```
