<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to the standalone workload-debug image are documented here.

## 2026-08-26

- TCAAS-1617: replace host-network integration checks with a disposable kind
  proof covering real DNS, TLS, HTTP, and Kubernetes API behavior under the
  restricted runtime policy.
- Add deterministic JSON readiness status (`ready` or `not-ready`) and verify
  token secrecy, semantic reports, and zero-cluster cleanup.
