# Release Process

This document defines the release requirements for k8s-breakglass. It is intended to meet OpenSSF Best Practices and Scorecard expectations for signed, verifiable releases.

The separate `Catalogue utility integration` workflow is the required
real-tool proof for the `network-debug` and `node-maintenance` images. It is a
matrix job, builds both `linux/amd64` and `linux/arm64` OCI artifacts, and
executes each image's command on the real runtime; it is not duplicated in the
ordinary controller CI suite.

Development image publication is a separate, opt-in path. Pushes to a
repository-owned, protected `dev-images/*` branch run
`utility-dev-publish.yml`; ordinary branches and forks cannot publish to the
canonical GHCR namespace. Repository administrators must configure the
`UTILITY_DEV_ALLOWED_ACTORS` repository variable and the protected
`utility-development` environment before using it. The environment itself
must have one or more required reviewers configured and GitHub's prevent
self-review setting enabled; these controls are not represented by repository
variables. An administrator can verify the live settings with
`GH_REPO=telekom/k8s-breakglass GH_TOKEN=... hack/verify-github-environment.sh utility-development`.
The workflow builds all six utility
images as multi-architecture manifests, uses a tag that
contains the complete source SHA and GitHub run identity, refuses to overwrite
an existing tag, and records the manifest digest in an uploaded reference
manifest. Each digest is keylessly signed and carries SPDX and SLSA v1
attestations (`slsaprovenance1`). The workflow supplies Cosign a bare SLSA v1
predicate and also requests GitHub's native build-provenance record. After both
producers complete, Cosign retrieval and the semantic verifier require exactly
one custom statement and exactly one GitHub-native Statement/v1 for the same
image digest, source commit, workflow, and OIDC identity; a missing or
unreadable native record fails closed before the reference is uploaded. The
workflow grants `artifact-metadata: write` solely so the official action can
store its registry attestation record. The pre-native custom Cosign output is
named `custom-slsa-attestation.json` and is used only as an intermediate gate;
it is not uploaded as final evidence. The uploaded
`verified-slsa-attestations.json` is captured after the native action and is
the authoritative mixed-producer evidence (the release assemble equivalent is
`release-image-verified-slsa-attestations.json`).
Consumers must mirror and deploy the digest reference, not the development tag.
The workflow's exact GitHub OIDC certificate identity is recorded in the
reference manifest and is required when verifying the source signature. The
publication approval environment must be configured with required reviewers
and must not permit the initiating publisher to approve their own run.

On a rerun, `github.actor` identifies the original event actor while
`github.triggering_actor` identifies the person requesting the rerun. Both must
be in `UTILITY_DEV_ALLOWED_ACTORS`; GitHub's protected environment performs the
independent approval check for the current run. An approval cannot be inferred
from either actor value or from repository variables.

Before the approval job can start, the pinned `actions/github-script` in
`environment-preflight` reads the live GitHub environment configuration with
the least-privilege `GITHUB_TOKEN` and fails closed unless
the environment exposes non-empty required reviewers and
`prevent_self_review=true`. The token must have permission to read repository
environments. If that token cannot read protection rules, the gate fails and
an administrator must correct the GitHub policy before publication is enabled;
no administrator token is injected into branch-controlled workflow code. An
administrator can separately verify the setup with the local
`hack/verify-github-environment.sh` using a short-lived, admin-readable token.
This bootstrap check is deliberately separate from the workflow's
protected-environment approval.

Development consumers download the uploaded reference manifest, verify each
Cosign signature and attestation, and mirror/deploy the `image@sha256:digest`
values. Never promote a `dev-*` tag by retagging it without first recording
and verifying its digest. To roll back, deploy the last known-good digest
manifest; the immutable development tag itself is never overwritten. A
missing digest, failed environment preflight, failed provenance check, or
registry authentication error is a stop condition. Inspect the workflow run
logs and retry only after the registry/API condition is corrected.

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
   - SLSA v1 provenance is generated for every release image using
     `actions/attest-build-provenance` and Cosign `slsaprovenance1` attestations;
     the assemble gate semantically verifies one attestation from each
     producer, including the native workflow identity and source commit.
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
3. **Assemble** — downloads all per-arch digests and creates a unified multi-arch manifest tagged with the release version. Stable `vX.Y.Z` tags also update `latest`; prerelease tags such as `vX.Y.Z-rc.1` keep only their explicit version tag. Tags with SemVer build metadata (`+build`) are rejected because Docker image tags cannot contain `+`. The final manifest digest is resolved with bounded fail-closed retries, receives GitHub and custom keyless SLSA provenance, and is semantically checked for exactly one attestation from each producer: exact subject digest, source repository, release workflow, source commit, custom builder identity, native workflow identity, and OIDC signer must all match before the assemble job completes. The action's `artifact-metadata: write` permission is scoped to this assemble job.
4. **Artifactory** — mirrors the multi-arch image and cosign artifacts (signatures + attestations) to the internal Artifactory OCI registry (best-effort).
5. **Publish charts** — pushes both charts to GHCR Helm OCI (`oci://ghcr.io/telekom/k8s-breakglass/charts`).
6. **Release** — creates a GitHub Release with manifests, Helm chart packages, `bgctl` binaries, release-wide checksums, CLI archive checksums, and SBOM (SPDX-JSON format via Syft).

> **Note:** Buildx layer caching (`cache-from`/`cache-to`) is intentionally omitted in
> release builds to ensure clean, reproducible images without layer reuse from prior
> development iterations.

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
