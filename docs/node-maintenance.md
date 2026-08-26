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
the required host-networked pod, minimal `NET_ADMIN` capability, exact target,
confirmation, and evidence workflow.

Builds target `linux/amd64` and `linux/arm64`, pin the Alpine manifest and APK
package versions, request BuildKit provenance/SBOM attestations, and sign only
the resulting immutable registry digest. No image is pushed by the local
Makefile.

The Linux-only integration target (`make -C utils/node-maintenance integration`)
builds and runs the image in disposable `--network none` namespaces with the
intended `NET_ADMIN` capability boundary. It executes every allowlisted action,
checks real before/after evidence and denial guards, and verifies container and
volume cleanup. Missing Docker, namespace support, or security flags fails the
job with diagnostics; the proof never silently skips.
