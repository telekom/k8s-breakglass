<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Network-debug runbook

Use `net-report` for a deterministic overview, then invoke only the helper
needed for the incident. `net-debug --help` and `net-debug tools` list the
supported commands; `curl`, `nc`, `dig`, `ip`, `ss`, `tcpdump`, `mtr`, and the
pinned `kubestr`/`pwru` tools are available for approved investigations.

Join only the target pod or node network namespace. Grant the minimum
capabilities required by the selected operation (`NET_RAW`, `NET_ADMIN`, or
the reviewed BPF permissions); never use blanket privilege by default. Save
pcaps and reports only to an approved mount, redact addresses and payloads,
and remove the session when the investigation is complete. Read the README
for the integration and supply-chain constraints before publishing output.
