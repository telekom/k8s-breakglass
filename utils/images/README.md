<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Upstream utility images

This directory contains generic, standalone images intended for approved
Kubernetes debug sessions. The `storage-debug` and `dump-reader` images are
multi-architecture (`linux/amd64` and `linux/arm64`), run without privilege as
UID/GID 65532, pin their base images and runtime dependencies, and carry
signing/SBOM/provenance metadata. The
`diagnostic-artifact-collector` is an explicit root-only exception for
crashdump collection and uploader operation; its metadata documents that
boundary.

| Image | Purpose | Source access | Writes |
| --- | --- | --- | --- |
| [`storage-debug`](./storage-debug/) | Bounded fio/ioping checks and stable reports | Configured test mount | Temporary benchmark file and report only |
| [`dump-reader`](./dump-reader/) | Existing-file metadata, SHA-256, and copy-out | Existing regular files | Separate configured output mount only |
| [`diagnostic-artifact-collector`](./diagnostic-artifact-collector/) | Collect and upload approved crashdump artifacts | Explicitly configured host crashdump paths | Staged archive and uploader state |

Build from each image directory with `docker buildx build --platform
linux/amd64,linux/arm64`. Publish a manifest, generate an SBOM and provenance
attestation, then sign the manifest with keyless Cosign. Image metadata files
are signing-ready declarations; they do not contain a signing key.

The image runbooks are normative for bounds, mount permissions, and cleanup.
Do not add vendor-specific paths, credentials, host mounts, dump generators, or
unbounded workload commands to these images.

## Why the other utilities stay purpose-built

`dump-reader` is the one utility whose contract is fully covered by a tiny,
well-maintained upstream BusyBox image. The other catalogue entries retain
their own images because their contracts are not generic base-image problems:

* `workload-debug` needs a deliberately allowlisted set of protocol and API
  probes; a broad network toolbox would weaken its non-root boundary.
* `storage-debug` packages pinned benchmark binaries and enforces bounded
  scratch/report paths; no upstream image provides that contract.
* `node-maintenance` contains reviewed recovery and repair dispatchers whose
  host-network and capability boundary must remain explicit.
* `cluster-validator` is a read-only report producer with a stable output
  schema and RBAC assumptions; a generic kubectl toolbox would add commands
  and credentials surface without implementing the schema.

These are functional and security-boundary decisions, not claims about any
particular external image digest. Each image must continue to carry its own
SBOM, provenance, signature, and immutable-base metadata.

The per-image `image-metadata.yaml` files include the machine-readable command
and intent contract used by release review. Run `make -C utils/images test`
for fast script tests and `make -C utils/images integration` for mandatory
Docker-backed proofs. The integration target builds all mandatory images for the local
Docker architecture, runs them as UID/GID 65532 with a read-only rootfs,
`--cap-drop=ALL`, and no network, then exercises the real packaged tools and all
safe-copy/report failure boundaries. It fails when Docker is unavailable; it
does not silently skip. `make -C utils/images multiarch` performs a real
BuildKit OCI build for both declared platforms and removes its temporary
archives; CI enables QEMU for this validation while runtime proofs stay native.
