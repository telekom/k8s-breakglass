<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Workload-debug runbook

Use this image for short, read-only workload checks. Start with the bounded
`debug-report`, then run only the helper needed for the incident:
`debug-dns`, `debug-tls`, `debug-http`, or `debug-kube-api`. The dispatcher
also provides `workload-debug --help`.

Run as UID/GID `65532` with all capabilities dropped and a read-only root
filesystem. HTTP and Kubernetes API requests are GET/HEAD/OPTIONS only, do
not follow redirects, and are bounded by `WORKLOAD_DEBUG_TIMEOUT` and
`WORKLOAD_DEBUG_MAX_BYTES` for both response headers and body. The bounded
response helper uses a private,
ephemeral directory: it prefers `TMPDIR`, then `/dev/shm`, then `/tmp`. If
the runtime makes all three read-only, provide an `emptyDir`/tmpfs at `/tmp`.
Temporary response and authentication-header files are removed on success,
failure, and interruption. `debug-kube-api` reads the service-account token
from a file and passes only a temporary header-file path to curl, so the token
does not appear in process arguments. Never put tokens, cookies, or private
keys in arguments or captured output. End the session and retain only approved
output.
