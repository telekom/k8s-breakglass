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
The default lease adapter does not publish credential generations. Until an
approved production generation publisher is wired, terminal recording remains
fail closed even with storage configured.

Terminal stream and replay responses use `application/octet-stream` and
`X-Content-Type-Options: nosniff`. Terminal bytes, including HTML-like text and
control sequences, remain unchanged; they are never HTML-escaped. Frame sizes
are checked against the native allocation limit before arithmetic or allocation.

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

The server assigns the `terminal-recording.v1` metadata policy and version 1 to
recording reservations. This identifies framing and metadata; it does not redact
or alter the authorized terminal stream bytes.

### Revocation and in-flight output

Authorization is checked before each transport write. Kubernetes revocation and
an irreversible socket write cannot form one atomic operation: bytes already
admitted to a write may complete while revocation is being detected. The next
write is denied after a failed check. The stream also checks authorization every
500 milliseconds (each check has a two-second timeout) and aborts blocked I/O;
these are detection intervals, not a guaranteed end-to-end delivery bound under
scheduler or network delays. Hard expiry sets transport deadlines. Buffering or
a post-write check cannot retract bytes already delivered to the client.
