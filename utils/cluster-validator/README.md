<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Cluster-validator image

`cluster-validator` is a provider-neutral, read-only Kubernetes readiness
client. It runs the `one-time` or `post-upgrade` mode and writes a stable
`cluster-validator.telekom.com/v1alpha1` report to stdout and, by default,
`/reports/{mode}.json`.
Custom report paths must remain below `/reports`; traversal and symlink
escapes are rejected, and persisted reports are owner-readable only.

The built-in checks cover API discovery, API-server reachability, nodes,
terminating namespaces, and active pods. Use `--skip-pods` only when the
dedicated read-only identity cannot list pods and record that exception.
Exit codes are `0` ready, `1` not-ready, and `2` usage/configuration error.
The image never creates, patches, or deletes Kubernetes objects.

The image is built from the repository root with
`-f utils/cluster-validator/Dockerfile`, supports `linux/amd64` and
`linux/arm64`, and runs as UID/GID `65532`. Read
`/usr/share/cluster-validator/RUNBOOK.md` before operating it.
