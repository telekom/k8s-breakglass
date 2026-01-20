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
