<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Convergence installation coverage

`e2e_convergence` now has an additional Helm installation fixture at
`e2e/fixtures/convergence-installation`. It installs one reconciled
`DebugPodTemplate` and representative `DebugSessionTemplate` modes through
Helm, then waits for their Ready conditions:

- workload diagnostics using a referenced pod template;
- normal and emergency `kubectl-debug` node diagnostics;
- Job-based templates named after the etcd snapshot and defrag recipes; they
  reuse the workload pod template and contain no etcd tooling.

The existing `TestConvergenceBindingHelmRelease` remains the stronger Flux
HelmRelease proof for the bindings, empty target transitions, disabled
providers, and authenticated diagnostic session lifecycle. Neither test
executes node repair, etcd snapshot, or defrag operations.

## Inventory checked

At clusters reference commit `a0be2c81ce8ad170417e5cb5640419dd9f304cb3`, six
management cluster definitions configure `k8s-breakglass`. Five supply a
cluster-specific hostname and a named ClusterIssuer; one explicitly enables
`enableDebugSessionCatalog` and supplies the same type of issuer override.
The definitions reference four distinct management Bundle releases.

At bundles reference commit `19a0e0401defb8165ce15148a2383315e781b9a4`, the
inventory contains 22 distinct Breakglass Function pins: `0.1.0`, `0.2.0`,
and `0.3.0-rc.1`, `rc.4`, `rc.8` through `rc.17`, `rc.19` through `rc.21`,
and `rc.23` through `rc.27`. The current convergence fixture is based on
`0.3.0-rc.27`; it does not execute the other Function versions.

## Limit of this test

The fixture proves the public Breakglass API controllers accept and reconcile
these representative rendered resource modes when installed by Helm. It does
not prove that the private T-CaaS Function rendered those resources from its
inputs, that the T-CaaS Bundle operator installed a historical pin, or that
the catalog opt-in output matches the private renderer. Closing those gates
requires each pinned Function artifact and a disposable environment running
the matching T-CaaS Bundle/Function operators. The public reference checkout
does not provide those installable runtime dependencies.
