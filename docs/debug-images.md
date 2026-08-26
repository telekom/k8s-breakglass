<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Generic debug utility images

The upstream utility images under [`utils/images`](../utils/images/) are
optional building blocks for approved `DebugSession` templates. They are
deliberately independent of the Breakglass controller and use only generic
mount paths supplied by the operator.

## Selection

* Use [`storage-debug`](../utils/images/storage-debug/) only for a bounded
  benchmark against an approved writable test mount. Its report has a stable
  key order and excludes raw command output and timestamps.
* Use [`dump-reader`](../utils/images/dump-reader/) when an existing regular
  file needs metadata, a SHA-256 checksum, or copy-out to a separate volume.
  It rejects symlinks and refuses to overwrite an output file.

Both images support `linux/amd64` and `linux/arm64`, run as UID/GID 65532,
require no capabilities, and have no network requirement. Mount source data
read-only whenever the workflow does not require a write test. Use a separate
output volume for copy-out and constrain sessions with the usual DebugSession
duration, storage, and authorization policy.

## Release and signing checklist

For each image directory:

1. Run `./tests/test.sh` and `shellcheck` over the scripts.
2. Build both platforms from the digest-pinned Dockerfile and inspect the
   resulting manifest.
3. Generate an SBOM and SLSA provenance attestation for the manifest.
4. Sign the immutable digest with keyless Cosign and verify the signature and
   attestations before adding the image to an allowlist.

Do not use `latest` in a DebugPodTemplate. Record the immutable image digest,
the approved purpose, and the owner in the template's change record.

## Incident runbooks

### Storage check

1. Confirm owner approval and that the target mount is a scratch/test area.
2. Mount it at a generic path such as `/scratch`, set an ephemeral-storage
   limit, and use a short DebugSession duration.
3. Run `storage-report --dry-run` first. Then run the bounded defaults or
   explicitly select values within the documented limits.
4. Save the report from `/reports`, remove the session, and review the test
   file cleanup. A read-only mount supports dry-run only.

### Existing dump inspection

1. Mount the artifact directory read-only at `/input` and a separate empty
   output volume at `/output`.
2. Run `dump-reader inspect /input/FILE`, then `checksum` when integrity
   evidence is needed.
3. Run `copy /input/FILE` only when copy-out is approved. The destination is
   never overwritten and must remain under `DUMP_OUTPUT_DIR`.
4. Preserve the checksum with the incident record, remove the pod, and apply
   the incident retention policy to the output artifact.

These images do not create kernel dumps, invoke debuggers, alter source files,
or assume internal host paths. Any workflow that needs those capabilities must
be separately reviewed and approved.
