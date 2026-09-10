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
