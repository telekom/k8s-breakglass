<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Diagnostic artifact backend

Diagnostic artifacts are created from an immutable, allowlisted recipe. The
`DebugSessionArtifact` resource binds the artifact to the exact debug-session
UID, target identity digest, recipe plan digest, redaction policy, bounded
inputs, size limit, and expiry. Its specification cannot be changed after
creation.

The controller renders a fixed collector Job. The Job has a private emptyDir,
fixed collector and uploader commands, a pinned image digest, and the least
privilege security context required by the selected recipe. The crashdump
recipe additionally pins the Job to its selected node and mounts only the
read-only `/var/lib/systemd/coredump` host path. Collector Jobs receive a
short-lived, one-time controller upload token and route. They never receive
storage-provider credentials, bucket names, object keys, or provider URLs.

The artifact record is stored in the hub, while its upload Secret and collector
Job are created in the live session's target spoke namespace through the
target-cluster client. The controller rechecks the session, target UID, and
expiry before each spoke write. Because Kubernetes owner references do not
perform garbage collection across clusters, the hub status stores the exact
spoke resource UIDs and resource versions. Cleanup deletes only those exact
objects and leaves a replacement with the same name untouched; an outage or
resource finalizer keeps the artifact finalizer pending for retry.

Uploads are staged in a bounded private file and validated against the exact
recipe manifest, output set, archive framing, size, and SHA-256 digest before
the configured create-only storage backend is used. S3 requires an
administrator-provisioned versioned bucket and sentinel identity; local/PVC
storage remains an explicit configuration choice and is never an automatic
fallback. Public artifact responses contain only the opaque artifact ID,
recipe/version, lifecycle state, validated size and digest, and expiry. The
authenticated API exposes metadata at
`GET /api/debugSessionArtifacts/:namespace/:session` and streams bytes at
`GET /api/debugSessionArtifacts/:namespace/:session/:artifactID`. The host
application supplies the live-session binding resolver and authentication
middleware; an artifact token is accepted only by the collector upload route.

Every upload, download, expiry, revoke, and cleanup operation checks the live
session UID, target identity, operation epoch, and retention deadline. Cleanup
deletes only versions matching the immutable artifact binding. Provider
ambiguity is retained as `Unknown` until two independent empty inventory
observations or an exact matching deletion provide evidence. Provider errors
and credentials are not returned in API responses.

The upload path repeats token and live-session checks after local archive
validation and after provider publication. Download readers repeat the same
check before each read, so revocation or expiry closes an in-flight stream.
The collector runs as an init container before the uploader and shares a
non-root output filesystem group; the full plan digest is carried in an
annotation because Kubernetes labels cannot hold a 64-character digest.

The feature remains disabled until the CRD, controller wiring, RBAC, storage
configuration, API integration, fault matrix, and exact-head CI gates are
reviewed together.

When enabled, the host initializer requires an explicit `backend` of `s3` or
`local`, a pinned collector image, an HTTPS controller URL, a bounded upload
limit, and a token Secret name. Secret names are resolved only in the
configured Breakglass namespace using exact uncached `get` calls. S3 uses the
fixed `accessKeyID`, `secretAccessKey`, and optional `sessionToken` keys; local
storage must satisfy its one-replica RWO/Recreate contract and is never an
automatic fallback. The host reads the live session's persisted connection
lease with an uncached API reader and validates lease UID, holder, target UID,
epoch, and expiry before each artifact operation. The binding source reads the
immutable artifact record in the configured backend namespace, so request
parameters cannot select a different target or session.

Artifact creation must commit the one-time upload JTI commitment before the
collector Secret is issued. The creation route must provide that commitment
through a controller-owned seam rather than asking the collector or API caller
to expose the raw token; replacing the current random JTI issuance with that
durable handoff is still required before enabling the feature.

Provider object keys are 64 lowercase hexadecimal SHA-256 characters derived from the immutable artifact resource UID with a domain separator. Public artifact IDs remain unchanged. Same-named artifacts with different resource UIDs occupy separate provider objects, including during upload recovery and cleanup.

### Durable collection admission and recording evidence

An administrator enables collection explicitly in the approved template with
`artifactCollection.allowedRecipes` (`system-summary.v1` and/or
`crashdump-collection.v1`). Active participants may POST a recipe, `podNamespace`
and `podName` to `/api/debugSessionArtifacts/:namespace/:session`. The Pod must
match the approved UID. Only `detailLevel` or `maxAgeMinutes`, as appropriate to
the recipe, are accepted as additional inputs. The controller selects the image,
credentials, target identity, operation epoch, limits and digests. Unknown fields
are rejected. Crashdump node identity comes from the live approved Pod and Node.

Two retained collector reservations per session bound both concurrent Jobs and
reserved bytes. A separate pool permits at most 128 retained recording
reservations. Kubernetes Create arbitrates finite reservation slots across
replicas. Slots become reusable only when provider and owned-resource cleanup
finishes and the artifact CRD is deleted; this is deliberately stricter than a
count checked before creation.

A fresh random reservation incarnation and an existing signing-key identifier
are immutable inputs to a domain-separated upload nonce. Only its hash is
persisted. Restart can reproduce the correct nonce, while an old token cannot
upload to a recreated slot. Removing a referenced signing key causes issuance
to fail closed. Legacy records lacking that handoff cannot obtain a new token.

The internal `terminal-recording.v1` path reserves before streaming and persists
validated framing, size and digest before provider writes. It does not use the
collector upload route. Finalization and exact inventory recovery may retain
previously admitted evidence after access expires. The fixed reservation
retention deadline is independent of the stream deadline; consumer policy may
set it to the stream deadline plus retention, so early completion can retain
bytes longer than completion plus retention. Replay still requires current
explicit authorization, a matching live session UID and an unexpired artifact;
a deleted session does not grant access from an old participant snapshot.

Recording consumers use the shared reserve/finalize/recover and guarded replay
methods. An independent artifact controller retries recovery and owns retention
cleanup even when session mirror publication fails. Provider metadata and tokens
are excluded from public artifact responses.

Artifact admission, upload, download, and collector writes also enforce the
session's optional idle deadline. The controller's generated RBAC includes
artifact resource, status, and finalizer operations. Signing and provider
credentials are read by exact Secret name in the configured hub namespace;
this feature adds no cluster-wide Secret permission.

A publication intent with no observed provider version remains `Unknown` during
cleanup: an empty inventory cannot prove that a paused publication will not
finish. The reservation and finalizer remain for recovery or operator review.
S3 publication makes one SDK attempt; a lost response is resolved by inventory,
not by retrying a write after cleanup might have deleted its first version.
Recording recovery never promotes an artifact already marked for ambiguous
cleanup back to Available. Collector downloads revalidate both the requesting
participant and the opened artifact UID before and after each provider read.

Collector reservations bind the exact admitted connection Lease UID as well as
its epoch. Recreating a same-name Lease with a reset epoch cannot revive an old
upload token or download. Legacy records without this lease incarnation cannot
grant collection access; their cleanup evidence remains usable.
