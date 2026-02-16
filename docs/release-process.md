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

2. **Artifact signing**
   - All published release artifacts must be signed using a transparent signing service such as Sigstore Cosign.
   - Signatures must be published alongside release artifacts.

3. **Provenance**
   - Provide SLSA-compatible provenance for all release artifacts.
   - Provenance must be publicly accessible and linked from the release notes.

4. **Checksums**
   - Publish SHA-256 checksums for every artifact.

5. **Release notes**
   - Include a summary of changes, security notes, and upgrade guidance.
   - Link to the provenance and checksum files.

## Multi-Architecture Builds

Release images are built as multi-arch manifests supporting both `linux/amd64` and `linux/arm64` platforms. Each architecture is built natively on a dedicated runner (no QEMU emulation), then assembled into a single multi-arch manifest list.

**Build pipeline:**

1. **Prepare** — generates Kustomize manifests, cross-compiles `bgctl` binaries for all OS/arch combinations, and uploads them as artifacts.
2. **Build** (matrix: `amd64`, `arm64`) — builds and pushes a single-platform image by digest on a native runner for each architecture.
3. **Assemble** — downloads all per-arch digests and creates a unified multi-arch manifest tagged with the release version (and `latest` for tag pushes).
4. **Artifactory** — mirrors the multi-arch image to the internal Artifactory OCI registry.
5. **Release** — creates a GitHub Release with manifests, `bgctl` binaries, checksums, and (when enabled) an SBOM.

> **Note:** Buildx layer caching (`cache-from`/`cache-to`) is intentionally omitted in
> release builds to ensure clean, reproducible images without layer reuse from prior
> development iterations.

## Release Checklist

- Verify CI success on the release commit.
- Ensure the changelog is up to date.
- Generate artifacts via the release workflow.
- Sign artifacts and publish provenance.
- Publish checksums and update release notes.

## Verification

Consumers should be able to:

- Verify signatures against published artifacts.
- Verify provenance against the release commit.
- Confirm checksums match the downloaded artifacts.
