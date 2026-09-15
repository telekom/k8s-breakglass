<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Cluster-validator runbook

1. Verify the exact image digest, signature, and SBOM. Bind a dedicated
   read-only ServiceAccount with `get/list` on nodes, namespaces, and pods and
   read-only discovery access. Mount an empty writable volume at `/reports`.
2. Run `cluster-validator --mode one-time` before a change and archive stdout
   plus `/reports/one-time.json`. For an upgrade gate, run
   `cluster-validator --mode post-upgrade` and require exit `0` and
   `status: ready`.
3. Treat exit `1` as a failed readiness gate, inspect the named check, and
   remediate through the normal change process. Exit `2` means configuration or
   usage must be corrected. Never treat a skipped check as ready.
4. Remove the pod and report volume according to the incident retention policy.

The image is read-only with no remediation capability. Keep kubeconfig or
service-account credentials out of command arguments and captured reports.
Use `cluster-validator --help` for the complete flag and environment surface.
