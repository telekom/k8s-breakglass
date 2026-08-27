<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Node-maintenance image

The standalone [`utils/node-maintenance`](../utils/node-maintenance/) image is
for a narrowly scoped node-network incident workflow. It supports a read-only
`node-recovery` preflight and three explicitly selected `network-repair`
actions. It is not a
replacement for a host-debug image and intentionally does not document an
unrestricted shell or ship a general-purpose network toolbox.

See the utility README and its [preflight](../utils/node-maintenance/runbooks/node-recovery-preflight.md)
and [repair](../utils/node-maintenance/runbooks/network-repair.md) runbooks for
the required separate no-capability preflight and `NET_ADMIN`-only repair
contexts, controller-provided exact target, confirmation, and evidence
workflow. Workload templates must inject `BREAKGLASS_NODE_NAME` from Downward
API `spec.nodeName`; hostname is not a trust input.

Built-in runbooks remain under
`/usr/share/breakglass/runbooks/upstream/node-maintenance/`. A downstream
deployment may mount an optional, digest-pinned runbook bundle read-only at the
shared `/usr/share/breakglass/runbooks/internal` root, without `subPath` and
with an optional `INDEX.md`; the image does not hardcode, source, or execute
bundle content. That wiring is an external immutable-template/admission
responsibility.

Builds target `linux/amd64` and `linux/arm64`, pin the Alpine manifest and APK
package versions, request BuildKit provenance/SBOM attestations, and sign only
the resulting immutable registry digest. No image is pushed by the local
Makefile.

The Linux-only integration target (`make -C utils/node-maintenance integration`)
builds and runs the image in disposable `--network none` namespaces with the
separate preflight/repair capability boundaries. It executes every allowlisted action,
checks real before/after evidence and denial guards, and verifies container and
volume cleanup. Missing Docker, namespace support, or security flags fails the
job with diagnostics; the proof never silently skips.
