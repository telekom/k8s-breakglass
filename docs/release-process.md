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
   - Publish SHA-256 checksums for every artifact.

3. **Release notes**
   - Include a summary of changes, security notes, and upgrade guidance.

### Planned (not yet active)

The following supply-chain security goals are defined but **not yet enforced** in CI. They are gated behind `if: ${{ false }}` in the release workflow pending infrastructure readiness (e.g., `id-token: write` permissions on all runners).

4. **Artifact signing** _(planned)_
   - Sign all published release artifacts using Sigstore Cosign.
   - Publish signatures alongside release artifacts.

5. **Provenance** _(planned)_
   - Provide SLSA-compatible provenance for all release artifacts.
   - Provenance must be publicly accessible and linked from the release notes.

6. **SBOM** _(planned)_
   - Generate an SPDX SBOM for each release image using Syft.
   - Attach the SBOM to the GitHub Release.

## Multi-Architecture Builds

Release images are built as multi-arch manifests supporting both `linux/amd64` and `linux/arm64` platforms. Each architecture is built natively on a dedicated runner (no QEMU emulation), then assembled into a single multi-arch manifest list.

**Build pipeline:**

1. **Prepare** — generates Kustomize manifests, cross-compiles `bgctl` binaries for all OS/arch combinations, and uploads them as artifacts.
2. **Build** (matrix: `amd64`, `arm64`) — builds and pushes a single-platform image by digest on a native runner for each architecture.
3. **Assemble** — downloads all per-arch digests and creates a unified multi-arch manifest tagged with the release version (and `latest` for tag pushes). Generates SLSA provenance attestation for supply-chain integrity.
4. **Artifactory** — mirrors the multi-arch image to the internal Artifactory OCI registry.
5. **Release** — creates a GitHub Release with manifests, `bgctl` binaries, checksums, and SBOM (SPDX-JSON format via Syft).

> **Note:** Buildx layer caching (`cache-from`/`cache-to`) is intentionally omitted in
> release builds to ensure clean, reproducible images without layer reuse from prior
> development iterations.

## Release Checklist

- Verify CI success on the release commit.
- Ensure the changelog is up to date.
- Generate artifacts via the release workflow.
- Publish checksums and update release notes.
- _(When enabled)_ Sign artifacts and publish provenance.
- _(When enabled)_ Attach SBOM to the release.

## Verification

Consumers should be able to:

- Confirm checksums match the downloaded artifacts.
- _(When signing is enabled)_ Verify signatures against published artifacts.
- _(When provenance is enabled)_ Verify provenance against the release commit.
