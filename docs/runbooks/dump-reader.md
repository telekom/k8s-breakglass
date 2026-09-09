<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Dump-reader runbook

Mount approved existing dump files read-only at `/input` and a separate output
volume at `/output` only when copying is approved. Use `inspect` or `checksum`
first, then `copy` to a basename under `/output`; the image never generates,
overwrites, or deletes dumps. Remove the temporary session and output volume
after transfer verification.
