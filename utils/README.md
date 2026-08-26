<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Standalone utility images

Each directory is an independently buildable operator utility. The image
packages its own README, runbook, MOTD, helper commands, and security
boundary; read the in-image runbook before starting a debug session.

| Utility | Purpose | Runtime boundary |
| --- | --- | --- |
| [`workload-debug`](./workload-debug/) | Bounded DNS, TLS, HTTP, and Kubernetes API checks | Non-root, no capabilities |
| [`network-debug`](./network-debug/) | Connectivity, routes, captures, and approved tool probes | Root only for reviewed network/BPF capabilities |
| [`images/storage-debug`](./images/storage-debug/) | Bounded fio/ioping checks on an approved test mount | Non-root, no capabilities |
| [`images/dump-reader`](./images/dump-reader/) | Inspect, checksum, and copy existing dump files | Non-root, no capabilities |
| [`node-maintenance`](./node-maintenance/) | Allowlisted node recovery and network repair | Host network; `NET_ADMIN` only for repair |
| [`cluster-validator`](./cluster-validator/) | Read-only one-time and post-upgrade readiness reports | Non-root, read-only Kubernetes RBAC |

Use immutable image digests and verify the release signature, SBOM, and
provenance before deployment. Keep mounts generic and session-specific; these
images do not infer controller metadata, vendor paths, credentials, or
platform-specific services.
