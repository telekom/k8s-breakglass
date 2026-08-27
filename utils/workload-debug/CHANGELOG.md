<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to the standalone workload-debug image are documented here.

## Unreleased

- Require the real projected service-account bearer token in the Kubernetes
  API integration fixture and verify authenticated output, process arguments,
  and logs do not disclose it.
- Keep the temporary bearer header explicitly mode `0600` until cleanup.
- Bound token-authenticated Kubernetes API responses even when the server uses
  chunked transfer encoding or omits `Content-Length`; remove the temporary
  bearer-header file on every exit path.
- Bound response headers through the same streaming limiter, reject oversized
  headers before emission, and verify the behavior with HTTP and Kubernetes
  API fixtures.
- Make the Kind integration harness fail closed on name collisions and verify
  the created or partially created cluster can be removed without touching
  caller-owned clusters; verify exact image tags and IDs are removed too.

## 2026-08-26

- TCAAS-1617: replace host-network integration checks with a disposable kind
  proof covering real DNS, TLS, HTTP, and Kubernetes API behavior under the
  restricted runtime policy.
- Add deterministic JSON readiness status (`ready` or `not-ready`) and verify
  token secrecy, semantic reports, and zero-cluster cleanup.
