<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# DebugSession terminal recording

`DebugSessionTemplate.spec.audit.enableTerminalRecording` controls terminal
session recording. It is distinct from the narrated/demo recordings under
`e2e/` and `docs/demos/`.

When enabled, the DebugSession controller requires the deployment to configure
`BREAKGLASS_TERMINAL_RECORDING_IMAGE` (or call its equivalent constructor
option). The image must implement the sidecar contract and be pinned to a full
sha256 digest, with signing enforced by the platform's image policy. No image is selected by
the controller, so installations do not inherit an unreviewed registry or
internal naming assumption.

The sidecar receives only metadata environment variables:

- `BREAKGLASS_RECORDING_SESSION`, `..._NAMESPACE`, `..._CLUSTER`, and
  `..._TEMPLATE` identify the session;
- `BREAKGLASS_RECORDING_CORRELATION_ID` joins sidecar, audit, and artifact
  events;
- `BREAKGLASS_RECORDING_FORMAT` is `asciicast-v2`;
- `BREAKGLASS_RECORDING_OUTPUT` is `/var/run/breakglass/recording/session.cast`;
- `BREAKGLASS_RECORDING_RETENTION` defaults to `90d`; and
- `BREAKGLASS_RECORDING_REDACT_SECRETS` is always `true`.

The controller never copies template webhook headers, bearer tokens, Secret
values, or recording bytes into the pod spec, status, audit details, or failure
messages. A missing image, invalid retention, or pod without a workload
container fails the DebugSession rather than silently running without the
requested recording.

The sidecar writes to the private, size-limited `emptyDir` recording volume and
is the only container granted access to that volume. It is responsible for
uploading/finalizing the artifact in an external store. The
DebugSession status exposes metadata only (`sha256`, size, expiry, and an
opaque URI). Deployments may provide a `RecordingReplayReader` to stream
  authorized artifacts through `GET /api/debugSessions/:name/recording/replay`;
without one the endpoint returns `503`.

Recording metadata is available at
`GET /api/debugSessions/:name/recording` and uses the same requester,
participant, invitee, and approver authorization as the session detail route.
The artifact must be retained until the configured retention deadline; normal
DebugSession cleanup removes workloads but does not delete an external
recording.

## Signed-image build hook

Use the repository Makefile hooks with a deployment-owned image and registry:

```sh
make terminal-recording-image-build TERMINAL_RECORDING_IMAGE=registry.example/terminal-recorder:VERSION
make terminal-recording-image-sign TERMINAL_RECORDING_IMAGE=registry.example/terminal-recorder@sha256:DIGEST
```

The hooks intentionally require an explicit image and delegate signing to
`cosign`; registry credentials, signing identity, and admission policy remain
outside this repository.
