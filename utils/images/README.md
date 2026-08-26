<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Upstream utility images

This directory contains generic, standalone images intended for approved
Kubernetes debug sessions. Each image is multi-architecture (`linux/amd64`
and `linux/arm64`), runs without privilege as UID/GID 65532, pins its base
image and runtime dependencies, and carries signing/SBOM/provenance metadata.

| Image | Purpose | Source access | Writes |
| --- | --- | --- | --- |
| [`storage-debug`](./storage-debug/) | Bounded fio/ioping checks and stable reports | Configured test mount | Temporary benchmark file and report only |
| [`dump-reader`](./dump-reader/) | Existing-file metadata, SHA-256, and copy-out | Existing regular files | Separate configured output mount only |

Build from each image directory with `docker buildx build --platform
linux/amd64,linux/arm64`. Publish a manifest, generate an SBOM and provenance
attestation, then sign the manifest with keyless Cosign. Image metadata files
are signing-ready declarations; they do not contain a signing key.

The image runbooks are normative for bounds, mount permissions, and cleanup.
Do not add vendor-specific paths, credentials, host mounts, dump generators, or
unbounded workload commands to these images.
