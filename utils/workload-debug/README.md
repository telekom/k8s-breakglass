<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Workload-debug image

This is the restricted generic diagnostics image for TCAAS-1617. It is
standalone: it works in a Breakglass `DebugSession`, a Docker or Podman
container, and a Kubernetes Pod without relying on controller metadata.

Included helpers:

| Command | Purpose |
| --- | --- |
| `debug-dns` | DNS resolution, with an optional resolver server |
| `debug-tls` | TLS handshake and endpoint summary |
| `debug-http` | Bounded HTTP(S) request with response headers |
| `debug-kube-api` | Read-only Kubernetes API request using standard Pod files |
| `debug-report` | Non-invasive host and optional target checks |

`workload-debug <command>` is a convenient dispatcher. The shell remains the
default command for interactive sessions. See the [runbook](../../docs/runbooks/workload-debug.md)
for build, signing, SBOM, and deployment guidance.

The image is pinned to a multi-architecture Alpine base digest, runs as
non-root UID/GID `65532`, drops all capabilities, and does not write during
normal operation. `IMAGE-METADATA.yaml` is the source of truth for OCI,
provenance, signing, and SBOM metadata.
