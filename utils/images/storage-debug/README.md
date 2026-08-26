<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Storage debug image

`storage-debug` is a standalone, multi-architecture diagnostic image for a
mounted filesystem. It contains only version-pinned `fio` and `ioping` plus
the wrapper needed to enforce safe bounds and emit a deterministic,
line-oriented report.

The Alpine base supports `linux/amd64` and `linux/arm64`. Build and publish a
manifest with your normal OCI builder:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --tag registry.example/storage-debug:VERSION --push .
```

Run the image with a workload-specific mount. The default workload is 16 MiB
for five seconds and five ioping requests. Every bound is validated before a
benchmark starts: size is 1..1024 MiB, runtime is 1..60 seconds, and ioping
requests are 1..20.

```sh
docker run --rm --mount type=bind,src="$PWD/test-volume",dst=/scratch \
  registry.example/storage-debug:VERSION \
  --path /scratch --size-mb 16 --runtime-seconds 5 --ioping-count 5
```

The report has a stable schema and key order and deliberately omits raw tool
output and timestamps. A non-zero exit status means either check failed. Use
`--dry-run` to review the exact bounded commands without touching the mount.
Each run creates a private, randomly named scratch file and refuses to replace
an existing report path. `--output` must resolve beneath
`STORAGE_REPORT_DIR` (default `/reports`), preventing report path traversal.
The scratch file is removed on every exit path.

## Kubernetes runbook

1. Use a pre-approved `DebugPodTemplate` and mount only the target PVC at a
   generic path such as `/scratch`; do not mount host filesystems.
2. Set a short session duration and a pod-level ephemeral-storage limit. The
   image runs as UID/GID 65532 and does not require privilege or capabilities.
3. Execute `storage-report --output /reports/storage-report.txt`. Collect that
   report as an incident artifact and remove the debug session when finished.
4. For a read-only volume, use `--dry-run`; fio's read/write workload requires
   a writable test directory by design.

Do not point the image at a production data directory unless the owner has
approved a bounded write test. The temporary fio file is removed on exit, but
the filesystem can still observe the write workload.

## Tests and release metadata

Run `./tests/test.sh` from this directory. `image-metadata.yaml` records the
supported platforms, labels, SBOM/provenance expectations, and keyless Cosign
signing command. The release pipeline should attach an SBOM and provenance
attestation before signing the resulting manifest.
