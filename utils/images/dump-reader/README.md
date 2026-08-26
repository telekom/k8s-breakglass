<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Dump reader image

`dump-reader` is a standalone, multi-architecture image for controlled
inspection of existing dump artifacts. Its command surface is intentionally
small:

* `inspect FILE` prints deterministic metadata (basename, size, mode, UID,
  GID, and epoch mtime).
* `checksum FILE` prints a SHA-256 checksum.
* `copy FILE [OUTPUT_NAME]` copies an existing regular file beneath
  `DUMP_OUTPUT_DIR`, refuses to overwrite, limits the source to
  `DUMP_MAX_COPY_BYTES` (1 GiB by default), and reports the copied checksum.

It rejects missing files, directories, unreadable files, and symbolic links.
The resolved source must remain beneath `DUMP_INPUT_DIR` (default `/input`),
which also prevents `..` and symlink-directory escape paths. Copy-out uses a
private temporary file and an exclusive hard-link, so a pre-existing or
concurrently-created destination is never replaced.
There is no dump generator, debugger, host mount, or privileged capability in
the image. The process runs as UID/GID 65532.

Build a multi-architecture manifest from this directory:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --tag registry.example/dump-reader:VERSION --push .
```

## Kubernetes runbook

Mount an incident artifact directory read-only at `/input` and a separate
empty output volume at `/output`:

```sh
kubectl exec POD -- dump-reader inspect /input/existing.dump
kubectl exec POD -- dump-reader checksum /input/existing.dump
kubectl exec POD -- dump-reader copy /input/existing.dump
```

Set `DUMP_OUTPUT_DIR` to another absolute, writable mount when `/output` is not
appropriate. `OUTPUT_NAME` is a basename only, preventing path traversal and
keeping copy-out beneath the configured output directory. Copy-out never
overwrites an existing destination; choose a new output name instead.

Keep the source mount read-only and scope access to approved debug sessions.
The command reports only generic basenames and configured mount paths; it does
not assume a vendor, cluster, or internal filesystem layout. Remove the pod
and output artifact according to the incident retention policy.

## Tests and release metadata

Run `./tests/test.sh` from this directory. `image-metadata.yaml` records the
supported platforms, non-root runtime, and required SBOM, provenance, and
keyless Cosign signature attestations. The image has no mutable package
dependency beyond its digest-pinned BusyBox base. BusyBox is used only for the
small POSIX utility set needed by the helper; no package manager or additional
runtime package is installed. The resulting image includes BusyBox under its
GPL-2.0-only license, which must remain represented in the generated SBOM.
