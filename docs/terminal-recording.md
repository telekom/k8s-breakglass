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

Concurrent replicas cannot both publish. A request that loses the race (an
optimistic-lock conflict, a generation staged or published by another replica,
a Lease retired concurrently, or inputs changing while publishing) executes
nothing and gets `503` with `Retry-After: 1`; the client retries. Any other
publication failure, such as an expired or foreign-held Lease, is a denial
(`403`).

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

Recording requires a running audit pipeline: an enabled `AuditConfig` with at
least one sink that confirms delivery (webhook or Kafka; log and chat sinks do
not). Recording events are delivered synchronously to every sink. The target never
runs unless the `terminal_recording_started` event was delivered, and list and
replay return `503` without data unless their `terminal_recording_accessed`
event was delivered. Without a pipeline, or when an `AuditConfig` event-type
filter excludes these events, the endpoints return `503`. Retained evidence
therefore always has an audit index. A start whose event cannot be delivered
releases its evidence reservation. Because delivery can take seconds, stream
authority is checked again after the start event and reader authority after
the access event, before anything runs or is returned. Delivery failures of
`finalized` and `failed` events, which happen after the stream ran, are logged. Events of one request
share its correlation ID and never contain terminal bytes:

| Event | When | Details |
|---|---|---|
| `debug_session.terminal_recording_started` | Evidence reserved, before target execution | `recordingId`, pod namespace/name/UID, container, operation, `formatVersion`, lease UID, generation, `retentionExpiresAt` |
| `debug_session.terminal_recording_finalized` | Evidence published | the above plus `sha256`, `bytes`, `frames`, `complete`; for an aborted stream `abortReason` (`credential_changed`, `cluster_config_changed`, `target_changed`, `session_authority_changed`, `lease_changed`, `expired`, `client_disconnected`, `recording_limit`, `authority_check_failed`, `transport_failed`, `output_truncated`, `stream_failed`) |
| `debug_session.terminal_recording_failed` | Reservation or publication failed | `stage` (`reserve` or `finalize`) and the identifiers known at that point |
| `debug_session.terminal_recording_accessed` | An authorized reader listed or replayed recordings | `access` (`list` or `replay`), `recordingIds` or `recordingId`, `sha256`, `bytes`; the actor is the reader |

Their schema is in [Audit event schema](audit-event-schema.md#terminal-recordings-terminalrecording-terminalrecordingaccess).
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
stream. The request body of a terminal stream is bounded by the 512 MiB
recording budget instead of the 1 MiB limit for JSON requests. Any other protocol value is rejected with `400` before evidence is
reserved. The response body remains raw terminal output with recording
trailers. `bgctl debug terminal` uses `framed.v1`.

### Ingress and proxies

The terminal is one long-lived `POST` whose request body (input) and response
body (output) stream at the same time. It is not a protocol upgrade: no
`Upgrade`/`Connection` handling or WebSocket support is involved. The controller
serves full duplex over HTTP/1.1 (chunked bodies) and HTTP/2; `bgctl` uses
HTTP/1.1. Every proxy between `bgctl` and the controller must:

- forward the request body as it arrives (no request buffering): a buffering
  proxy waits for the end of a body that only ends when the shell exits;
- forward output as it is written (no response buffering);
- keep the connection open for the whole session: the controller holds the
  stream until the session expires and sends no keepalive traffic, so idle
  read/send timeouts end idle shells;
- accept request bodies up to the 512 MiB recording budget;
- pass the response trailers `X-Breakglass-Recording-ID`,
  `X-Breakglass-Recording-SHA256` and `X-Breakglass-Recording-Status`. Without
  them `bgctl` falls back to the recording listing (below); other clients must
  do the same or exit non-zero. The recording is finalized either way.

With kustomize, add the opt-in component instead of writing the annotations by
hand. It sets the ingress-nginx annotations below on the `breakglass-ingress`
Ingress and, when `../gateway-api` is listed before it, `timeouts.request` and
`timeouts.backendRequest` of `0s` (disabled, GEP-1742) on the HTTPRoute. Order
matters: listed after `streaming-ingress`, `gateway-api` renders the HTTPRoute
without the timeouts, silently. HTTPRoute `timeouts` needs Gateway API v1.2 or
later on the standard channel. The default renders are unchanged. This
repository ships no Helm chart for the controller, so there is no chart value;
the charts under `charts/` only render custom resources.

```yaml
components:
  - ../../components/gateway-api          # only when using Gateway API
  - ../../components/streaming-ingress
```

The annotations (timeouts in seconds, sized to the longest session; override
them with a patch in your overlay):

```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/proxy-request-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-http-version: "1.1"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-body-size: "512m"
```

ingress-nginx also cuts a request whose body is idle for longer than
`client-body-timeout` (default 60 seconds), for example a shell left without
typing. There is no annotation for it: set `client-body-timeout` in the
ingress-nginx controller ConfigMap, sized to the longest session (this applies
to every Ingress of that controller).

No `Upgrade`/`Connection` headers are needed. Gateway implementations may keep
their own idle timeouts (Envoy Gateway `BackendTrafficPolicy`, Istio
`DestinationRule`); raise those separately.

nginx does not forward upstream response trailers. The server therefore also
names the recording in a regular response header,
`X-Breakglass-Recording-Pending-ID`, before the stream starts. When `bgctl`
receives no trailers it looks that recording up in `GET
/debugSessions/:name/terminal` (the server finalizes before it ends the stream)
and reports `completed` or `incomplete` and the digest from the listing, or
`finalization-pending` when the recording is not listed (publication failed;
the artifact controller may still recover an upload that had started). The
lookup is a regular, audited listing
(`debug_session.terminal_recording_accessed`, `access: list`, naming the
session's recording IDs) and needs the caller to be an authorized reader, which
the stream's owner is; if it fails, `bgctl` exits non-zero with the reason.
Clients that do not know the header are unaffected.

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

A recording is bounded by `artifacts.uploadMaxBytes` by default; set
`artifacts.terminalRecordingMaxBytes` (1..`uploadMaxBytes`) to lower it. At most
two concurrent streams run per serving process by default; set
`artifacts.terminalRecordingMaxConcurrent` (1..32) to change that. Each stream
buffers its recording in memory (about one segment with incremental flush,
below), so budget memory as concurrency x byte limit, with headroom for buffer
growth. A stream whose next input or output would
exceed the byte limit ends at once; the bytes recorded so far are published as
incomplete evidence and the rest is neither delivered nor recorded.
Invalid values are rejected at startup; see the
[configuration reference](configuration-reference.md). The HTTP transport
requires full duplex: output is flushed before further input is supplied.
Detection of expiry or revocation also aborts blocked HTTP input/output;
see the in-flight output limits below.
Input and output are admitted on a live check of the session identity,
participant issuer, allowed target Pod UID, profile, expiry, and connection
lease that started at most one second earlier (see
[revocation and in-flight output](#revocation-and-in-flight-output)). Target
lookup is bracketed by live session checks. Rejected input is never forwarded
to the target. A failed check, or a failed read or write of the client
transport, ends the whole stream: the recording is published incomplete with
the reason audited, never as complete with output missing. Replay similarly rechecks live reader authorization and artifact
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
classifies completion without discarding evidence after revocation. It is
checked up to three times within 5 seconds, so one slow API read does not mark
a cleanly ended stream incomplete; a periodic in-stream check that the
stream's own clean end interrupts is not treated as a revocation.
The target's streaming server ends every exec and attach with a final status
after the command and all of its output. A stream whose connection ends
without that status (for example torn down while output was still in flight
when the command exited) is published incomplete with `output_truncated`.
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

### Incremental flush (opt-in)

By default a stream's framed bytes are held in memory (up to the recording
limit) and published when the stream ends, so a controller crash, OOM kill or
node loss mid-stream leaves only an empty reservation. Set
`artifacts.terminalRecordingSegmentBytes` (65536 to 67108864; `0`/unset keeps
the default behavior) to persist the recording while it runs:

- Once about that many bytes are buffered, they are flushed at a frame boundary
  before the next frame is recorded. Per-stream memory is bounded by one
  segment plus one frame. The flush happens while output waits, so a slow
  backend slows the terminal (each flush is bounded by 10 seconds).
- Each segment is a separate create-only object in the configured artifact
  backend (local PVC or S3). After each segment a numbered manifest object is
  written with the segment count, total size and SHA-256 chain head; the frame
  hash chain commits to every earlier byte, so manifests stay small. The latest
  manifest is the commit point; bytes after it are unproven and ignored.
- At most 4096 segments are written per recording, so 4096 x segment size must
  be at least the recording byte limit (`terminalRecordingMaxBytes`, else
  `uploadMaxBytes`); a smaller segment size is rejected at startup.
- If a flush fails, the stream is stopped: the frame that needed the flush and
  everything after it are neither recorded nor delivered.
  `debug_session.terminal_recording_failed` is emitted with `stage: flush` (and
  `stage: finalize` if publication fails as well). At the end of the stream the
  buffered, already delivered tail is flushed once more; if that also fails, up
  to one segment of output the user already saw is missing from the evidence.
  The committed part is published as incomplete.
- At the end of a stream the controller publishes the committed segments as
  the usual single recording artifact, after checking their size, frame hash
  chain and chain head, so listing, replay and retention are unchanged. The
  segment objects are then deleted. Publication stages the recording once in
  `stagingDir`, so the local backend briefly holds the segments, the staged copy
  and the published object (about three times the recording size).
- If the controller dies mid-stream, the artifact controller publishes the
  committed prefix as an incomplete recording (`complete: false`) one minute
  after the stream's binding expired, so a handler that is still finishing is
  never overtaken. It audits `debug_session.terminal_recording_finalized` with
  `recovered: true` and actor `system`; if the committed segments cannot be
  published (damaged or missing), it audits `terminal_recording_failed` with
  `stage: recover` once and keeps retrying until retention expiry. As with the
  stream's own events, an undelivered audit event is logged, not retried. Up to one segment of output delivered
  before the crash is not in that prefix. Until then the segments and manifests
  stay in the backend; segments of recordings that are never published are
  removed with the reservation at retention expiry (a retention shorter than
  that minute removes them unpublished).

### Revocation and in-flight output

Every transport read and write is admitted only on a successful live
authority check that started less than one second earlier. The stream checks
its authority live every 500 milliseconds, and a read or write runs its own
live check when the last one is older, so recorded output is not throttled by
API reads (#1761). Live checks run one at a time, each bounded at two seconds.
A failed check ends the stream and stops admission at once. Revocation bound:
once a revocation is visible to the controller's live reads, no further input
or output is admitted after at most one second; the periodic check also
cancels the stream within 500 milliseconds plus at most two checks (one it
waits for and its own). Kubernetes
revocation and an irreversible socket write cannot form one atomic operation:
one write admitted before the bound may still complete. These are detection
intervals, not a guaranteed end-to-end delivery bound under scheduler or
network delays.

`artifacts.terminalRecordingStrictAuthorization: true` restores the previous
strict mode: a live check (a few API reads) before every transport read and
write. Revocation then takes effect on the next read or write, but output is
limited by the API reads: about 20 KiB/s in Kind, against several MiB/s with
the default. Hard expiry sets transport deadlines. Buffering or
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
