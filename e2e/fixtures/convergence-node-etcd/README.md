<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Convergence node and etcd execution coverage

`e2e/api/convergence_node_etcd_test.go` runs the node-debug API against the
disposable E2E Kind cluster. It verifies approval, node targeting, readiness,
and read-only execution of kernel and host OS diagnostics through the created
debug pod. The test uses a digest-pinned BusyBox image and does not alter the
node.

This fixture does not run the internal etcd snapshot or defrag recipes. Those
recipes use a private Artifactory toolbox image and host-mounted etcd PKI; the
upstream convergence fixture currently has neither. Do not substitute
mocked etcdctl commands or the netshoot image and report those as execution
coverage. Add recipe execution only with an isolated etcd target and an
accessible immutable client image.
