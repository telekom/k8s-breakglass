<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Diagnostic artifact collector

diagnostic-artifact-collector is a standalone Job utility for the
diagnostic-artifact-collection intent. The image defaults to UID/GID 65532.
Its public repository is
`ghcr.io/telekom/k8s-breakglass/utils/diagnostic-artifact-collector`.
Deployments must use the reviewed immutable manifest digest; shared release
automation publishes the multi-architecture image and its attestations.
The in-image operator documentation is installed at
`/usr/share/breakglass/runbooks/upstream/diagnostic-artifact-collection/README.md`
and the operational runbook beside it at `RUNBOOK.md`. An optional downstream
OCI image-volume bundle may be mounted read-only, without `subPath`, at
`/usr/share/breakglass/runbooks/internal`; this image never sources or executes
content from that mount.
The controller runs only the host-mounted `crashdump-collection.v1` collector
init container as UID 0 (with all Linux capabilities dropped), because host
coredump files commonly retain root-only permissions. The portable
`system-summary.v1` collector and the uploader remain UID/GID 65532.
The crashdump collector runs as UID 0:GID 65532 and publishes its archive,
manifest, and ready marker as root:65532 mode 0640; the uploader accepts this
handoff without CAP_CHOWN. The summary collector publishes all three files as
UID/GID 65532 mode 0600.
It has two immutable recipes:

* crashdump-collection.v1 reads regular files from the read-only
  /host-coredumps mount. The node name is metadata supplied by the session
  controller through DIAGNOSTIC_NODE; it is never interpreted as a path.
* system-summary.v1 creates files/system-summary.json from harmless kernel
  metadata. Its detailLevel input is the bounded basic or extended enum; this
  recipe is the portable CI smoke test and requires no host mount.

## Recipe contract

| Recipe | Use and fixed behavior | Inputs and capability category | Access and egress | Limits and outputs | Non-goals, cleanup, and fallback |
|---|---|---|---|---|---|
| `system-summary.v1` | First-line, provider-neutral triage; emits a bounded kernel/architecture summary, with bounded memory/CPU facts only in `extended` mode. | `detailLevel`: optional `basic` or `extended`, default `basic`; category `diagnostic-artifact-upload-egress`. | UID/GID 65532, no host mount, no Kubernetes identity, no Linux capabilities; collector is offline. Only the UID/GID 65532 uploader may egress to the exact controller upload endpoint (and DNS required to resolve it). | 2 minutes; 64 files; 14 MiB source and 16 MiB archive ceilings. Outputs: `manifest.json`, redacted `stdout.log`, `stderr.log`, and `files/system-summary.json`. | Not workload inspection, Kubernetes queries, arbitrary commands, logs, packet capture, or attestation. Temporary staging is removed on every exit; the controller deletes the Job, Secret, capability, and object. Local/PVC is explicit configuration, never an S3 fallback. |
| `crashdump-collection.v1` | Authorized collection of recent regular systemd coredump files from one identified, non-protected node; copies bytes without interpreting them. | `nodeName`: exact required Kubernetes node name; `maxAgeMinutes`: optional integer `1..10080`, default `1440`; categories `diagnostic-artifact-upload-egress` and `diagnostic-artifact-hostpath-exception`. | Collector UID 0 only for root-readable files, all capabilities dropped; exact node placement; read-only `/var/lib/systemd/coredump` at `/host-coredumps`, no host namespaces or service-account token. Collector is offline; only UID/GID 65532 uploader egresses to the exact controller endpoint (and DNS). | 15 minutes; at most 4096 regular candidates (including stale files) and 512-byte printable-ASCII source paths; 480 MiB source/per-file and 512 MiB archive ceilings. Outputs: `manifest.json`, redacted `stdout.log`, `stderr.log`, and `files/coredumps/`. | Not arbitrary paths/scripts, live process dumping, redaction of binary dumps, privilege escalation, SR-IOV/Multus, or source-node attestation. Staging is removed on every exit and the controller deletes all tracked resources/object. If host access is not covered, use the reviewed escalation flow; never broaden the mount or silently fall back. |

The capability categories are controller-owned contracts, not image inputs. The
upload category is a session-scoped NetworkPolicy; the host-path category is a
controller-configured provider contract reference. The image cannot choose
either policy, a node, a mount, an endpoint, or a credential. The controller
must create capabilities before the Job and delete them after termination,
expiry, failure, or explicit deletion.

The runtime intentionally builds on the maintained, digest-pinned BusyBox
image and a statically compiled Go uploader. A general toolbox such as
netshoot is the right base for the separate interactive network-diagnostics
intent, but would add packet, socket, and shell tooling that no artifact recipe
is permitted to invoke. Add a broader upstream base only when a new reviewed
recipe needs its behavior and the registry, image tests, limits, and threat
model are updated together.

The only accepted collection command is collect --recipe <recipe-id> --output
/output/artifact.tar.gz. The only accepted upload command is upload --archive
/output/artifact.tar.gz. The output arguments are fixed literals, not
requester-controlled paths. There is no command, script, image, mount, or
output declaration input. The image writes a deterministic-entry-order tar.gz
archive, an identical manifest sidecar, and finally /output/artifact.ready as
the uploader hand-off. Existing destinations are rejected.

Every manifest also carries the controller-supplied `artifact_id`, the
`session` object (`namespace`, `name`, and immutable `uid`), the
`redaction` profile/version, and a sorted `declared_outputs` list baked into
the selected recipe. These values are bounded and required; the collector
rejects missing or malformed `BREAKGLASS_ARTIFACT_*` identity variables and
the uploader rejects unknown, duplicate, or replay-shaped manifest fields.
The complete manifest is capped at 32 KiB; session strings are DNS-bounded,
the artifact ID is `dsa-` plus 24 lowercase hex characters, and the immutable
session UID is capped at 128 bytes.
The sidecar is copied byte-for-byte into the archive, and the uploader sends
that same immutable manifest. The controller must independently compare the
artifact ID, session UID/namespace/name, recipe and inputs, redaction profile,
and declared outputs with the one-time lease and live session; manifest values
are bindings to check, not authorization by themselves.

## Deployment-owned output volume

The controller or chart owns the `/output` emptyDir hand-off. Its pod-level
security context must set `runAsUser: 65532`, `runAsGroup: 65532`, and
`fsGroup: 65532` (with `fsGroupChangePolicy: OnRootMismatch`) so the non-root
collector can create its private hand-off on a fresh volume. The image does not
assume that a bind mount or host directory is writable. The checked-in
`tests/kind-emptydir.sh` creates the reference pod in Kind and proves this
contract with the real image and an emptyDir.

The archive includes manifest.json, redacted stdout.log and stderr.log, and
only the recipe's declared files. It enforces a 15-minute duration and a
separate 30-second crashdump enumeration deadline, at most
8192 total filesystem entries and 4096 regular candidates before sorting
(including stale files), and a 512-byte
maximum printable-ASCII source path for crashdump collection. It also enforces 4096
accepted files, 480 MiB per file, and 480 MiB total source-file bound
(maximum duration 15 minutes). The 480 MiB source ceiling leaves
room for tar headers, manifests, logs, and hand-off files inside the separate
512 MiB archive/output ceiling. System summary is limited to 64 files, 14 MiB
of source data below its 16 MiB archive ceiling, and 2 minutes. Crashdump names
containing control characters
are rejected before archive list generation. Nested mounts are not traversed. Symlinks,
hardlinks, devices, FIFOs, sockets, traversal, and non-regular source entries
are rejected, including files with a hardlink outside the mounted tree.
Descriptor-relative source access stays beneath `/host-coredumps`; every file
is hashed during copy and re-hashed from the same descriptor before it is
accepted, detecting same-size in-place mutation. Summary archives and all
their hand-off files are mode 0600;
root crashdump collection uses root:65532 mode 0640 for the archive, manifest,
and ready marker. The uploader accepts only those two ownership/mode pairs,
opens the marker, manifest, and archive without following links, enforces the
manifest's immutable per-recipe ceiling, and verifies archive content and
identity remain unchanged across transfer.
PAX extension lengths are checked against the already buffered extension before
they are converted to a native slice index, so an oversized signed length is
rejected on every supported image architecture.
The traversal runs in its own process group with fixed directory and regular-file
filters; each private NUL path spool is file-size limited. Enumeration expiry
and collector cleanup send TERM followed by KILL to that group, so a stuck finder
descendant cannot outlive the failed collection. The collector exits 2 and
emits the bounded diagnostic without publishing an archive, manifest, or ready
marker. After the direct finder wrapper exits, the collector also verifies that
its process group is gone before consuming a spool; a surviving FD-holding
descendant is terminated and fails the collection instead of racing publication.
If the 30-second watchdog expires while that cleanup is in progress, its
deadline diagnostic deterministically takes precedence over the descendant
diagnostic.
`BREAKGLASS_ARTIFACT_MAX_BYTES` can narrow the selected recipe archive ceiling
for a session. The summary recipe is always capped at 16 MiB and crashdump at
512 MiB; a deployment cap can only narrow those immutable ceilings. When
present the value must be a positive decimal integer no greater than 536870912.
The effective cap is recorded as `inputs.maxArchiveBytes` in the manifest and
is enforced by both collector and uploader. The optional
`BREAKGLASS_ARTIFACT_UPLOAD_TIMEOUT` uses Go duration syntax and is bounded to
1 hour.

The collector never opens a network connection. Only the uploader performs
bounded PUT attempts to the controller-issued HTTPS endpoint. The uploader
rejects redirects, URLs with queries/fragments or
credentials, empty tokens, symlinked archives, and archives whose private
regular-file identity or size changes during transfer. Retries are limited to
HTTP 408/429, 5xx, request timeouts, and explicitly classified connection
reset/refused/broken-pipe failures; TLS, DNS, authorization, and caller
cancellation are terminal. The controller rejects an upload at or after session
expiry with its terminal authorization response (including HTTP 410); the image
does not retry that response. The image carries the pinned builder's CA bundle
for normal certificate verification and ignores
ambient `SSL_CERT_FILE`, `SSL_CERT_DIR`, and proxy variables. HTTP endpoints
are never accepted; development fixtures must use certificate-verified HTTPS
with an injected test transport. A per-attempt request timeout is retryable
only while the total operation context still has budget; once that context is
done, cancellation/deadline is terminal.

Before the first PUT and again after every successful response, the uploader
streams and validates the gzip/tar contract: exactly one embedded manifest
matching the private sidecar byte-for-byte, only expected regular files and
directories, no duplicate or unsafe members, recipe-specific payload paths,
manifest `file_count`/`bytes`, and the raw payload SHA-256. A malformed gzip,
truncated stream, changed payload, forged manifest, or post-response mutation
fails closed and cannot be retried as a transient transport error.

Private staging is deleted on every exit. Publication uses create-only hard
links and writes the ready marker last. If publication is interrupted after an
archive or manifest link, that incomplete hand-off is never uploaded and is
removed with the Job's operation-scoped output volume. Cleanup deliberately
does not unlink a public path that another process could have replaced.

The crashdump recipe intentionally does not claim to redact arbitrary binary
core contents. Access must therefore be authorized by the DebugSession API,
the storage object must be private, and cleanup must delete it when the
session terminates or expires. The controller must provide the mount read-only
and a narrowly targeted node placement policy.

Build the image for linux/amd64 and linux/arm64 using the digest-pinned
BusyBox base and its pinned builder CA bundle. Release automation must attach an SPDX SBOM and provenance
attestation and sign the immutable manifest with keyless Cosign. Never put
credentials or signing keys in this image.
