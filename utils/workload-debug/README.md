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

HTTP and Kubernetes API helpers only allow GET, HEAD, and OPTIONS requests,
do not follow redirects, and cap each response at 1 MiB by default. Set
`WORKLOAD_DEBUG_TIMEOUT` (1–300 seconds) or `WORKLOAD_DEBUG_MAX_BYTES` (1–10
MiB) when a different bounded limit is required.

The image is pinned to a multi-architecture Alpine base digest, runs as
non-root UID/GID `65532`, drops all capabilities, and does not write during
normal operation. `IMAGE-METADATA.yaml` is the source of truth for OCI,
provenance, signing, and SBOM metadata.

Run `make test` for fast validation and `make integration-test` for the real
container proof. The integration proof builds the image, runs every helper
under the restricted policy, checks DNS/TLS/HTTP against disposable fixtures,
uses a kind service-account token for a read-only Kubernetes API request, and
verifies cleanup. Missing Docker/kind prerequisites are reported as failures.
`make build` creates a local image;
`make build-multiarch` uses BuildKit for both supported platforms and requests
in-toto provenance plus an SPDX SBOM (`--provenance=true --sbom=true`), writing
a local OCI archive (`workload-debug.oci.tar` by default; override with
`OCI_ARCHIVE=...`). Release automation resolves and retains the immutable
registry digest, then runs `make sign DIGEST=...` and
`make sbom DIGEST=... SBOM=...`.

`tool-contract.json` is the machine-readable contract for the shared
`workload-diagnostics` intent. `debug-report --json` emits a stable
`schema_version`, semantic `status` (`ready` or `not-ready`), check names and
statuses (without host timestamps or command output), making it suitable for
one-time and post-upgrade readiness comparisons. The HTTP helper does not follow
redirects and the Kubernetes helper reads a token from a file so credentials
never appear in command arguments.
