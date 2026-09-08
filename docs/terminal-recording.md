<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# DebugSession terminal recording

`DebugSessionTemplate.spec.audit.enableTerminalRecording` is reserved for a
future terminal-byte transport. The controller currently rejects a template
that enables it because the workload I/O hooks are not wired; it never creates
a metadata-only sidecar that could be mistaken for a recording. This is
distinct from the narrated/demo recordings under `e2e/` and `docs/demos/`.

When the transport is implemented, its planned bounded artifact volume will
use `BREAKGLASS_RECORDING_MAX_BYTES=536870912` (512 MiB). Until then, no
recording image, artifact route, replay route, or external cleanup contract is
provided by this repository.

Retention values are validated as positive durations at admission. The
controller does not copy template webhook headers, bearer tokens, Secret
values, or recording bytes into status, audit details, or failure messages.
