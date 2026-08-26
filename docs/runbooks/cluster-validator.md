<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Cluster-validator runbook

This runbook is intentionally generic. It can be used by an operator before a
change and after an upgrade without relying on an internal platform service.

## One-time baseline

1. Confirm that the validator image digest has an accepted signature and SBOM.
2. Use a read-only ServiceAccount and the minimal RBAC in
   [`cluster-validator.md`](../cluster-validator.md).
3. Run with `--mode one-time` and archive both stdout and
   `/reports/one-time.json`.
4. Stop if the process exits `1`; inspect the named check before proceeding.

## Post-upgrade gate

1. Wait for the API endpoint to become reachable, then run with
   `--mode post-upgrade`.
2. Require exit code `0`, `status: ready`, and the expected report API version.
3. Keep the report with the change record. Compare check names and statuses to
   the baseline; messages contain observations and are not parser keys.
4. If a check is intentionally unavailable (for example pod list permission),
   rerun explicitly with `--skip-pods` and record that exception in the change
   record. Do not treat an omitted check as ready.

## Failure handling

* `api-server` or `api-discovery`: verify network policy, service-account
  credentials, and API endpoint health.
* `nodes-ready`: inspect node conditions and remediation status.
* `namespaces-healthy`: find terminating namespaces and complete or roll back
  their deletion safely.
* `pods-ready`: inspect the failing pod's events, scheduling, image pulls, and
  readiness probe. A `Succeeded` pod is deliberately ignored.

The validator is read-only and cannot remediate a failure. Escalate using the
cluster's normal incident process and rerun the same mode after remediation.
