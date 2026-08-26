<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Storage-debug runbook

Mount only an approved test filesystem at `/scratch` and a separate writable
report volume at `/reports`. Run `storage-report --dry-run` first, then use
the bounded defaults or explicit values within 1–1024 MiB, 1–60 seconds, and
1–20 ioping requests. The fio workload writes a temporary file; use dry-run
for read-only mounts. Collect the report, verify scratch cleanup, and remove
the debug session after the incident.
