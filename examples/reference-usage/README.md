<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Public reference usage

[`reference-usage.sh`](./reference-usage.sh) is the executable reference check for the public
auth-operator, k8s-breakglass, and debug-session-catalogue artifacts. It creates
a clean kind cluster, installs the three upstream artifacts, configures
separate requester and approver identities, and proves both the normal
restricted lifecycle and a real catalogue DebugSession:

- access is denied before approval and requester self-approval is rejected;
- a distinct approver activates a bounded session;
- a second request is denied by an approver;
- a catalogue DebugSession is requested and approved by the distinct approver;
- a restricted catalogue workload runs a representative `kubectl exec` command;
- audit recording contains request, start, deployment, termination, and cleanup events;
- the session is terminated and its workload/policy resources are removed.

The elevated group is never enabled by default. Run
`REFERENCE_RUN_ELEVATED=true ./examples/reference-usage/reference-usage.sh` only
when an environment explicitly opts into that additional case.

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

The script uses the existing `e2e/kind-setup-single.sh` stack for Keycloak,
OIDC test users, the audit receiver, and the simulated tenant. It does not
accept credentials or print tokens. The default test identities are local
Keycloak fixtures created by that setup; override the `REFERENCE_*` identity
variables only when using an equivalent public fixture.

## Catalogue release contract

The catalogue branch publishes the `charts/debug-session-catalogue` Helm chart
at version `0.2.0`. The reference flow does not require that source branch to
be merged: source mode builds the checked-out Breakglass image and consumes
the public OCI chart. Published mode verifies the chart's signed immutable
reference. To exercise a chart checkout explicitly, set
`REFERENCE_CATALOGUE_SOURCE=true` and optionally `CATALOGUE_SOURCE_DIR`.
Published mode installs the public OCI chart at:

`oci://ghcr.io/telekom/k8s-breakglass/charts/debug-session-catalogue`

`CATALOGUE_VERSION` defaults to the chart's `0.2.0` version. Published mode
uses the OCI reference and `--version ${CATALOGUE_VERSION}`. Override
`CATALOGUE_CHART` and `CATALOGUE_VERSION` only for another public chart
publication; no private registry login or secret is part of the contract.

The chart is configured by the executable with the local requester group,
approver email, tenant cluster, and a pre-created debug namespace. The
consumer-defined `network-diagnostics` profile is the restricted case. Setting
`REFERENCE_RUN_ELEVATED=true` additionally enables and exercises the chart's
explicit `network-repair` and `node-recovery` elevated profiles, including
their workloads and representative commands.

This README intentionally points to the executable flow rather than copying
its Kubernetes YAML, so examples cannot drift from the tested path.
