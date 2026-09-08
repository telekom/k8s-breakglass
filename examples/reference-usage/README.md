<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Public reference usage

[`reference-usage.sh`](./reference-usage.sh) is the executable reference check for the public
auth-operator, k8s-breakglass, and debug-session-catalogue artifacts. When a
`REFERENCE_SETUP_SCRIPT` is supplied, it creates a clean Kind cluster, installs
the three upstream artifacts, and configures
separate requester and approver identities, and proves both the normal
restricted lifecycle and real catalogue DebugSessions:

- access is denied before approval and requester self-approval is rejected;
- a distinct approver activates a bounded session;
- a second request is denied by an approver;
- a catalogue DebugSession is requested and approved by the distinct approver;
- a restricted catalogue Job runs the packaged workload-debug command;
- audit recording contains request, start, deployment, termination, and cleanup events;
- the session is terminated and its workload/policy resources are removed.

The elevated node-repair profile is intentionally unavailable in this example.
The catalogue contract does not carry the controller-issued immutable approval
tuple required by `node-maintenance`, so the profile remains disabled even when
`REFERENCE_RUN_ELEVATED=true` is supplied. The script logs that limitation and
continues to support the restricted reference path.

## Running it

Source mode builds the checked-out OSS image:

```sh
REFERENCE_MODE=source ./examples/reference-usage/reference-usage.sh
```

Published mode pulls the public release image and verifies its keyless Cosign
signature, SPDX SBOM attestation, and SLSA provenance before creating the
cluster. It also requires `CATALOGUE_CHART_DIGEST` and verifies the chart's
keyless signature, SPDX SBOM, and SLSA provenance:

```sh
CATALOGUE_CHART_DIGEST=sha256:<published-chart-digest> \
  REFERENCE_MODE=published ./examples/reference-usage/reference-usage.sh
```

The workflow supplies a disposable bootstrap and token helper for its own
fixtures. Standalone consumers can set `REFERENCE_SETUP_SCRIPT` (or provide
`REFERENCE_API_BASE` and `REFERENCE_KUBECONFIG`), `REFERENCE_ENV_FILE`, and
`REFERENCE_TOKEN_HELPER` for equivalent upstream fixtures. The executable does
not require a checked-out chart or audit YAML. It does not accept credentials
or print tokens; identity values are supplied through the selected fixture.

## Catalogue release contract

The catalogue branch publishes the `charts/debug-session-catalogue` Helm chart
at version `0.2.0`. The reference flow does not require that source branch to
be merged: source mode builds the checked-out Breakglass image and consumes
the public OCI chart. Published mode verifies the chart's signed immutable
reference. Both modes consume the OCI chart, keeping the reference check
independent of chart source files and chart-runtime work in progress.
Published mode installs the public OCI chart at:

`oci://ghcr.io/telekom/k8s-breakglass/charts/debug-session-catalogue`

`CATALOGUE_VERSION` defaults to the chart's `0.2.0` version for source mode.
Published mode uses the OCI reference with `@${CATALOGUE_CHART_DIGEST}`.
Override
`CATALOGUE_CHART` and `CATALOGUE_VERSION` only for another public chart
publication; no private registry login or secret is part of the contract.

The chart is configured by the executable with the selected requester group,
approver email, tenant cluster, and a pre-created debug namespace. The
consumer-defined `workload-diagnostics` profile is the restricted case.
The `network-repair` profile is reserved for a future release that wires the
controller-issued immutable approval tuple into the catalogue. Setting
`REFERENCE_RUN_ELEVATED=true` records that the unsupported profile was
requested; it does not enable or execute node repair.

This README intentionally points to the executable flow rather than copying
its Kubernetes YAML, so examples cannot drift from the tested path.
