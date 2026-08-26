<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Dump-reader runbook

Mount approved existing artifacts read-only at `/input` and a separate empty
output volume at `/output`. Run `dump-reader inspect /input/FILE`, then
`checksum`; use `copy /input/FILE [OUTPUT_NAME]` only when copy-out is
approved. Sources must be regular files beneath `/input`, output names stay
beneath `/output`, copies are limited by `DUMP_MAX_COPY_BYTES` (1 GiB by
default), and existing destinations are never overwritten. Preserve the
checksum, remove the session, and apply the incident retention policy.
