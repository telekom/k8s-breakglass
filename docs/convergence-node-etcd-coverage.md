<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Convergence node and etcd coverage

The tagged E2E `TestConvergenceNodeDiagnosticsE2E` exercises the real
requester, approver, node-debug API, pod scheduling, and exec path on the
disposable Kind node. It reads the node kernel release and `/host/etc/os-release`
through the generated debugger pod. This establishes basic node diagnostics
execution; it does not validate internal identity mappings, private toolbox
content, or any repair action.

Snapshot and defrag execution remain uncovered. The internal recipes use a
digest-pinned Artifactory-only toolbox image with `etcdctl` and `etcdutl`,
mount the target node's etcd PKI, and mutate etcd state. The existing convergence
Helm fixture substitutes netshoot, which does not provide those tools. Running
the recipes against the shared E2E cluster's etcd would also perturb that
cluster and could interfere with concurrently running tests.

To close this gate, provide an isolated target cluster and an accessible
immutable image containing the matching etcd client binaries. The acceptance
case should create and approve a real DebugSession, run the fixed health,
snapshot, snapshot-status, and defrag commands against only disposable etcd,
assert the emitted revision/status and Job completion, and clean up all
test-owned resources. Until then, do not count recipe rendering as runtime
coverage.
