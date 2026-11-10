<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# DebugSession terminal recording

`DebugSessionTemplate.spec.audit.enableTerminalRecording` is served through the
controller-owned terminal proxy. The proxy resolves the live target Pod UID,
acquires a controller-owned connection lease, and streams Kubernetes exec or
attach bytes through the bounded recorder. A configured artifact backend and
lease provider are required; missing either dependency rejects activation and
the API request. The lease adapter requires a published credential generation;
an ownership epoch alone is never accepted as readiness. Claims are created
only in the configured controller execution namespace. This is distinct from the narrated/demo recordings under
`e2e/` and `docs/demos/`.

Recording uses the shared [diagnostic artifact backend](diagnostic-artifacts.md),
including its administrator-configured local or S3 store, keyring, staging
limits, and independent artifact controller. No separate recording environment
variables or store are used. The connection provider must also have a published
credential generation; configuring storage alone does not establish readiness.

### Credential generation

The controller executes the recorded exec/attach with its own ClusterConfig
credentials, so readiness is bound to every hub input of that client: the
kubeconfig Secret, the OIDC client, refresh-token, CA and token-exchange
Secrets, and for `oidcFromIdentityProvider` the IdentityProvider object and its
Keycloak service-account Secret (also used as refresh-token fallback). When a
stream is requested, the serving replica reads these inputs live and computes a
digest over their resourceVersions. The connection Lease stores the primary
credential Secret UID (`connection-secret-uid`) and that digest
(`connection-secret-resource-version`). If no generation is published yet, or
either value differs, the replica stages generation `n+1` and publishes it with
the Lease staged/ready compare-and-swap, re-reading the inputs as the readiness
proof. No Secret name or value is stored on the Lease.

Concurrent replicas cannot both publish. A request that loses the race (or sees
the inputs change while publishing) executes nothing and gets `503` with
`Retry-After: 1`; the client retries.

A credential change therefore fails closed in two ways: the active stream's
target check compares the inputs captured when the stream started and aborts
within one check interval, and the next stream publishes a new generation that
invalidates any stream still bound to the previous one. Any write to a bound
input changes its resourceVersion, including metadata-only updates such as
labels or annotations added by GitOps tooling or secret operators, and
therefore also aborts active recorded streams. Avoid unnecessary writes to
these objects while recorded sessions run. ClusterConfigs without a credential
Secret (for example in-cluster or exec plugin credentials) are never ready for
terminal recording.

Without an artifact backend the template fails closed: sessions whose template
requires recording are marked `Failed` with "terminal-byte transport is not
configured" before any debug workload is deployed, and the terminal endpoints
return `503`.

### Audit events

Recording requires a running audit pipeline (an enabled `AuditConfig`). Without
one, the terminal endpoint returns `503` and no stream starts, so retained
evidence always has an audit index. Each stream and each read emits audit
events through the configured sinks, including Kafka. Events of one request
share its correlation ID and never contain terminal bytes:

| Event | When | Details |
|---|---|---|
| `debug_session.terminal_recording_started` | Evidence reserved, before target execution | `recordingId`, pod namespace/name/UID, container, operation, `formatVersion`, lease UID, generation, `retentionExpiresAt` |
| `debug_session.terminal_recording_finalized` | Evidence published | the above plus `sha256`, `bytes`, `frames`, `complete` |
| `debug_session.terminal_recording_failed` | Reservation or publication failed | `stage` (`reserve` or `finalize`) and the identifiers known at that point |
| `debug_session.terminal_recording_accessed` | An authorized reader listed or replayed recordings | `access` (`list` or `replay`), `recordingIds` or `recordingId`, `sha256`, `bytes`; the actor is the reader |

These events ignore the template's `audit.enabled` switch, because they index
the retained evidence, and they are never sampled.

Terminal stream and replay responses use `application/octet-stream` and
`X-Content-Type-Options: nosniff`. Terminal bytes, including HTML-like text and
control sequences, remain unchanged; they are never HTML-escaped. Frame sizes
are checked against the native allocation limit before arithmetic or allocation.

### Framing and timing

New recordings use framing version 2:
`version (2) | direction | monotonic offset ns (8) | length (8) | previous SHA-256 | payload`.
Directions are `i` (input), `o` (output) and `r` (resize, JSON
`{"width":W,"height":H}`). Offsets come from the monotonic clock relative to the
stream start and never decrease; the artifact backend rejects non-monotonic
artifacts. Version 1 artifacts (`version | direction | length | previous SHA-256`,
no timing) remain verifiable. `formatVersion` in the recording metadata names
the framing. The last frame is covered by the published artifact SHA-256, not
by the chain, so verification always compares the published digest.
`bgctl debug recordings export` converts recordings to asciicast v2.

### Terminal protocol

Without a protocol header the request body is raw stdin (no resize). Clients
that send `X-Breakglass-Terminal-Protocol: framed.v1` frame the body as
`type (1) | length (4, big endian) | payload`: type `0` is stdin, type `1` a
JSON terminal size. Frames are limited to 64 KiB; a malformed frame ends the
stream. Any other protocol value is rejected with `400` before evidence is
reserved. The response body remains raw terminal output with recording
trailers. `bgctl debug terminal` uses `framed.v1`.

The recorder uses a bounded framed stream with separate input and output
directions. Each frame carries the previous frame's SHA-256 digest, so a
finalized artifact can be verified without placing terminal bytes or
credentials in DebugSession status or audit details. `POST
/debugSessions/:name/terminal` is the only recording transport and
`GET /debugSessions/:name/terminal` lists retained recordings, and
`GET /debugSessions/:name/terminal/:id` replays an unexpired exact artifact
version for an authorized session reader. The replay path pins backend
identity, runtime binding digest, and version ID. The private transport binding
keeps ClusterConfig UID, target Pod UID, and Lease UID distinct; none is inferred
from a numeric generation. Finalized framing records its actual frame count.

The bounded artifact volume is 512 MiB (`defaultTerminalRecordingMaxBytes`),
with at most two concurrent streams per serving process. The HTTP transport
requires full duplex: output is flushed before further input is supplied.
Detection of expiry or revocation also aborts blocked HTTP input/output;
see the in-flight output limits below.
Each input/output call rechecks the live session identity, participant
issuer, allowed target Pod UID, profile, expiry, and connection lease. Target
lookup is bracketed by live session checks. Rejected input is never forwarded
to the target. Replay similarly rechecks live reader authorization and artifact
retention before and after backend reads.
The controller finalizes publication with a bounded detached context after a
client disconnect or a remote stream failure, preserving any bytes already
captured, and closes the lease in a separate bounded context. Detected lease
expiry or revocation cancels active capture; reserved partial evidence can still
be finalized afterward. Direct
target `pods/exec` and `pods/attach` authorization is denied while recording is
required for an authorized current participant; unrelated or former participants
do not cause another user’s access to be denied. Clients subject to recording
must use the controller endpoint. Retention metadata is
stored in an independent `DebugSessionArtifact` before target execution. Captured
bytes and final metadata are published through that reservation even after
stream expiry or revocation; incomplete streams are marked `complete: false`. A final live-authority check
classifies completion without discarding evidence after revocation.
The shared artifact controller recovers ambiguous publication and performs
exact-version cleanup without depending on the session status or its lifetime.
Replay permits retained terminal sessions, but requires the original live session
UID and current reader authorization. Deleting or replacing the session denies
replay even while its independent evidence remains retained.

The immutable retention deadline is the admitted stream expiry plus
`audit.recordingRetention` (default 90 days). Ending a stream early does not
shorten this deadline. Reservation uses a bounded shared set of 128 artifact slots
per session; a slot is reusable only after its artifact has been fully cleaned up.
An interrupted process can leave a pending reservation without captured content;
such a record is not advertised as a completed recording.

When terminal recording is enabled, a supplied retention value is validated as
a positive duration at admission. The controller does not copy template
webhook headers, bearer tokens, Secret values, or recording bytes into status,
audit details, or failure messages.

The server assigns the `terminal-recording.v1` metadata policy to recording
reservations and records the framing in `formatVersion` (2 for new recordings,
1 for recordings made before timing was added). This identifies framing and
metadata; it does not redact or alter the authorized terminal stream bytes.

### Revocation and in-flight output

Authorization is checked before each transport write. Kubernetes revocation and
an irreversible socket write cannot form one atomic operation: bytes already
admitted to a write may complete while revocation is being detected. The next
write is denied after a failed check. The stream also checks authorization every
500 milliseconds (each check has a two-second timeout) and aborts blocked I/O;
these are detection intervals, not a guaranteed end-to-end delivery bound under
scheduler or network delays. Hard expiry sets transport deadlines. Buffering or
a post-write check cannot retract bytes already delivered to the client.

Each ready target Lease admits one recording stream through a resource-version
protected claim with a unique identity. A second stream cannot borrow that claim.
Closing a stream removes only its own claim; a delayed close cannot release a
successor. A crashed stream remains exclusive until its recorded expiry, bounded
by the session deadline. Lease or generation replacement and session revocation
invalidate the active stream through the existing live authorization checks.

Active sessions without a hard expiry are rejected before target access. If
acquisition fails before claiming a stream, only an unchanged Lease newly created
by that call may be removed, using UID and resource-version preconditions under a
bounded cleanup context. Existing ready leases are preserved on admission failure.
