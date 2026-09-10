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
the API request. This is distinct from the narrated/demo recordings under
`e2e/` and `docs/demos/`.

The artifact backend is enabled explicitly with `BREAKGLASS_RECORDING_STORAGE_ENABLED=true`,
`BREAKGLASS_RECORDING_ARTIFACT_ROOT`, `BREAKGLASS_RECORDING_STAGING_ROOT`, and
`BREAKGLASS_RECORDING_INSTANCE_ID`,
plus the private-root, encryption, and single-writer acknowledgements described
by the startup configuration. Without that explicit configuration, templates
requesting recording remain fail closed.

The recorder uses a bounded framed stream with separate input and output
directions. Each frame carries the previous frame's SHA-256 digest, so a
finalized artifact can be verified without placing terminal bytes or
credentials in DebugSession status or audit details. `POST
/debugSessions/:name/terminal` is the only recording transport and
`GET /debugSessions/:name/terminal/:id` replays an unexpired exact artifact
version for an authorized session reader. The replay path pins backend
identity, runtime binding digest, and version ID.

The bounded artifact volume is 512 MiB (`defaultTerminalRecordingMaxBytes`),
with at most two concurrent streams per serving process. The HTTP transport
requires full duplex: output is flushed before further input is supplied.
Every input/output boundary rechecks the live session identity, participant
issuer, allowed target Pod UID, profile, expiry, and connection lease. Target
lookup is bracketed by live session checks. Rejected input is never forwarded
to the target. Replay similarly rechecks live reader authorization and artifact
retention before and after backend reads.
The controller finalizes publication with a bounded detached context after a
client disconnect or a remote stream failure, preserving any bytes already
captured, and closes the lease in a separate bounded context. A lease expiry or
revocation cancels the stream before publication. Direct
target `pods/exec` and `pods/attach` authorization is denied while recording is
required; clients must use the controller endpoint. Retention metadata is
stored with the exact artifact reference and expired objects are eligible for
exact-version cleanup by the configured backend. Status publication conflicts
retain the immutable artifact for later inventory and retry.

When terminal recording is enabled, a supplied retention value is validated as
a positive duration at admission. The controller does not copy template
webhook headers, bearer tokens, Secret values, or recording bytes into status,
audit details, or failure messages.
