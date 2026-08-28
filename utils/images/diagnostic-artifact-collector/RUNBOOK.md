<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Diagnostic artifact collector runbook

The image includes this runbook at
`/usr/share/breakglass/runbooks/upstream/diagnostic-artifact-collection/RUNBOOK.md`;
the companion operator-facing README is beside it at `README.md`. Sites may
mount a downstream OCI image-volume bundle read-only, without `subPath`, at
`/usr/share/breakglass/runbooks/internal`. Treat that bundle as documentation
only: this image does not source or execute it.

## Controller contract

Create a Job from a reviewed DebugSessionTemplate recipe entry. Pass exactly
collect --recipe <allowlisted-id> --output /output/artifact.tar.gz and never
change the fixed output literal. For crashdump collection, pass only the
validated Kubernetes node name as DIAGNOSTIC_NODE and its bounded
DIAGNOSTIC_MAX_AGE_MINUTES input. Mount the selected
node's coredump directory at /host-coredumps read-only. Do not allow the
requester to set commands, arguments, paths, images, mounts, or output names.
The controller may set `BREAKGLASS_ARTIFACT_MAX_BYTES` to a positive decimal
cap no greater than 536870912; the image rejects malformed, zero, and larger
values before creating output. The same cap is enforced by the uploader. Set
`BREAKGLASS_ARTIFACT_UPLOAD_TIMEOUT` only when needed; it must be a positive
Go duration no longer than 1 hour.

The controller must also inject the bounded identity variables
`BREAKGLASS_ARTIFACT_ID`, `BREAKGLASS_ARTIFACT_SESSION_NAMESPACE`,
`BREAKGLASS_ARTIFACT_SESSION_NAME`, `BREAKGLASS_ARTIFACT_SESSION_UID`,
`BREAKGLASS_ARTIFACT_REDACTION_PROFILE`, and
`BREAKGLASS_ARTIFACT_REDACTION_VERSION`. The resulting manifest contains
those values as `artifact_id`, `session`, and `redaction`, plus the sorted
recipe-owned `declared_outputs`. The collector fails closed when any identity
value is missing or malformed. The controller independently matches every
identity, recipe/input, and output value against the one-time lease and live
DebugSession; these fields are not trusted as authorization claims.
The complete manifest is capped at 32 KiB; identity strings and the sorted
output list have fixed byte bounds enforced by the image.

The uploader is invoked as upload --archive /output/artifact.tar.gz. It checks
that the marker, manifest sidecar, and archive are regular files with one of the two
approved hand-off identities (UID/GID 65532 mode 0600, or root:65532 mode
0640), opens them with no-follow semantics, enforces the manifest's immutable
per-recipe ceiling, and verifies archive bytes and identity before and after
transfer. It then performs bounded HTTPS PUT attempts to the
exact controller-assigned URL, with a bounded retry budget for HTTP 408/429,
5xx, request timeouts, and explicitly classified connection
reset/refused/broken-pipe failures. Redirects, URLs containing queries/fragments,
non-TLS URLs, empty
tokens, arbitrary headers, and methods are rejected. The URL and token are
never logged. Only the image-pinned CA bundle is trusted; ambient
`SSL_CERT_FILE`, `SSL_CERT_DIR`, and proxy variables are ignored. The
controller should always issue a non-empty HMAC token. A per-attempt request
timeout is retried only while the total operation context remains live; a
completed operation deadline is terminal. The controller rejects an upload at
or after session expiry with a terminal authorization response (including HTTP
410); the uploader does not retry it.
Before a PUT and after each successful response, the uploader streams the
gzip/tar archive and verifies the embedded manifest, payload paths, duplicate
members, source counts/bytes, and raw payload checksum against the private
sidecar. Corrupt, forged, or changed content is terminal.
The controller claims a durable, session-status upload lease before accepting
bytes. A `409` means another attempt is active or the create-only object was
already consumed; do not mint a new command or bypass the endpoint.

## Recipes

| Recipe | Use, inputs, and categories | Access and egress | Limits and outputs | Non-goals and fallback |
|---|---|---|---|---|
| `system-summary.v1` | No-privilege first-line triage. Optional `detailLevel=basic\|extended` (default `basic`). Requires `diagnostic-artifact-upload-egress`. | UID/GID 65532, no host mount, Kubernetes identity, or capabilities. The collector is offline; only the uploader may reach the exact controller endpoint and DNS. | 2 minutes, 64 files, 14 MiB source and 16 MiB archive. Emits `manifest.json`, redacted `stdout.log`, `stderr.log`, and `files/system-summary.json`. | Not hostname, timestamps, command lines, environment, mounted secrets, workload/Kubernetes inspection, arbitrary commands, or packet capture. Local/PVC is explicit, never an S3 fallback. |
| `crashdump-collection.v1` | Authorized recent coredump collection from one identified non-protected node. Required exact `nodeName`; optional `maxAgeMinutes` integer `1..10080` (default `1440`). Requires `diagnostic-artifact-upload-egress` and `diagnostic-artifact-hostpath-exception`. | UID 0 only for root-readable files, all capabilities dropped; exact node placement; read-only `/host-coredumps` from `/var/lib/systemd/coredump`; no host namespaces or service-account token. The collector is offline; only the uploader may reach the exact controller endpoint and DNS. | 15 minutes, at most 8192 total filesystem entries and 4096 regular candidates before sorting (stale files included), 512-byte printable-ASCII source paths, 4096 accepted files, 480 MiB source/per-file and 512 MiB archive. Emits `manifest.json`, redacted `stdout.log`, `stderr.log`, and `files/coredumps/`; an empty directory is valid (`included=none`). | Not arbitrary paths/scripts, live dumping, binary redaction, privilege escalation, SR-IOV/Multus, or attestation. If host access is not covered, use the reviewed escalation flow; never broaden the mount or silently fall back. |

Both recipes reject symlinks, hardlinks, devices, FIFOs, sockets, traversal,
control-character names, and bounds violations. Crashdump collection rejects
source paths longer than 512 bytes, non-printable-ASCII paths, more than 8192
total entries, and more than 4096 regular candidates before sorting. It does
not traverse nested mounts. Descriptor-relative, no-follow source access stays
beneath the fixed mount and rejects files whose link count is not one. It
detects inode/size/mtime changes and hashes the same descriptor during and
after copying so same-size in-place mutation fails closed. Binary
dumps are not redacted; treat them as sensitive. Normalized inputs are recorded
in `manifest.json`.

## Failure handling and cleanup

The process exits 0 only after the archive, manifest sidecar, and final ready
marker are completely handed off with create-only links. It exits 2 for an invalid recipe/input or
collection failure. Private temporary staging is removed on success and
failure. Create-only publication links the ready marker last. An interrupted
partial hand-off has no ready marker, is never uploaded, and is removed with
the Job's operation-scoped output volume; the collector does not race another
writer by unlinking public paths during failure cleanup. The controller must delete the storage object
idempotently on session termination, expiration, explicit deletion, and
restart recovery. A failed cleanup remains observable and is retried.
Crashdump enumeration has its own 30-second deadline within the 15-minute
recipe lease. The collector starts `find` in a separate process group; deadline
and signal cleanup send TERM and then KILL to that group. A timeout exits 2 with
`coredump enumeration deadline exceeded`, leaves
no ready marker, and does not permit a traversal descendant to survive.
The controller's durable upload lease is at most 15 minutes, further bounded
by the resolved `uploadTimeout` (default 10 minutes) and session expiry. A
larger timeout cannot extend the 15-minute lease. Storage receives the upload
context; cancellation is cooperative and does not prove that a provider has
aborted or rolled back a PUT. Cleanup keeps the DebugSession finalizer while an
upload lease is live. After lease expiry it waits an additional 30-second
provider-drain window before clearing the lease, then deletes the object.
Each cleanup reconciliation performs Delete followed by a strong Stat absence
check, and the next reconciliation repeats the pair; two successful absence
probes are required before finalizer removal.

For an interrupted Job, remove its private temporary output before retrying;
never reuse an existing artifact path. Verify that the storage backend has no
incomplete multipart upload left behind. The image itself uses one bounded
single archive stream and does not initiate multipart uploads.

## Security checks

Run the portable summary collector and uploader as UID/GID 65532, with a
read-only root filesystem and no capabilities. The controller runs the
host-mounted crashdump collector as UID 0:GID 65532 only when necessary for
root-only coredump files; it still drops every capability, forbids host
namespaces, and uses a read-only mount. Its archive, manifest, and ready marker
are root:65532 mode 0640, so no CAP_CHOWN or ownership-reassignment step is
needed before the UID/GID 65532 uploader starts. The collector has no network access.
The uploader is
the sole network consumer and may egress only to the exact controller upload
endpoint. Verify the image digest and keyless Cosign
signature before use, and retain the SBOM and provenance attestations.
Crashdump Jobs must be rejected on control-plane/master nodes and on every
deployment-owned protected/SR-IOV label. The host-path admission resource must
come from a configured `providerContractRef`; never put a PolicyException body
or arbitrary admission manifest in the DebugSessionTemplate.
