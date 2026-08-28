<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Node-maintenance image

The standalone [`utils/node-maintenance`](../utils/node-maintenance/) image is
for a narrowly scoped node-network incident workflow. It supports a read-only
`node-recovery` preflight, exact-entry neighbor and bridge-FDB repair alongside
the interface actions, and fail-closed `kexec-recovery-validate`. The kexec
interface verifies fixed provider-owned read-only files and immutable digests;
it cannot execute or claim bootability. It is not a
replacement for a host-debug image and intentionally does not document an
unrestricted shell or ship a general-purpose network toolbox.

See the utility README and its [preflight](../utils/node-maintenance/runbooks/node-recovery-preflight.md)
and [repair](../utils/node-maintenance/runbooks/network-repair.md) runbooks for
the required separate no-capability preflight, `NET_ADMIN`-only repair, and
[kexec validation](../utils/node-maintenance/runbooks/kexec-recovery-validation.md)
contexts. Workload templates must inject exact controller-owned node,
operation, recording, approval, and approved-action bindings. The node comes
from Downward API `spec.nodeName`; hostname is not a trust input. Confirmation
is not authorization, and approval for one operation cannot authorize another.
Network repair binds the complete approved tuple to a SHA-256 digest in a
process-held evidence-volume-root `flock` record. Kernel release on process
death, not a timestamp or PID, controls liveness. The lock holder also recovers
owned stale evidence candidates left by a killed operation.

Compatibility with pre-volume-root images is intentionally limited. A new
image checks and retains an already-live legacy child lock, but an older image
can still start on a different child after that check because it does not join
the new root-lock domain. Rollouts sharing an evidence volume must therefore
drain old workloads before admitting the new image; this is a
controller/admission deployment precondition, not a runtime compatibility
guarantee.

Built-in runbooks remain under
`/usr/share/breakglass/runbooks/upstream/node-maintenance/`. A downstream
deployment may mount an optional, digest-pinned [OCI runbook bundle](runbook-bundle-contract.md)
read-only at the shared `/usr/share/breakglass/runbooks/internal` root,
without `subPath`. When selected, the bundle must follow that contract,
including its required `bundle.yaml` and `INDEX.md`; the image does not
hardcode, source, or execute bundle content. That wiring is an external
immutable-template/admission responsibility.

Builds target `linux/amd64` and `linux/arm64`, pin the Alpine manifest and APK
package versions, request BuildKit provenance/SBOM attestations, and sign only
the resulting immutable registry digest. No image is pushed by the local
Makefile.

The Linux-container integration target (`make -C utils/node-maintenance integration`)
builds and runs the image against a Linux Docker daemon in disposable
`--network none` namespaces with the
separate preflight/repair capability boundaries. It executes every allowlisted action,
including real veth neighbor and VLAN bridge-FDB replacement, checks exact-
target and injection denials, all approved-tuple mismatches, interface-name
replacement, bridge reparenting after preflight, active-holder clock age, and
immediate crash release. It verifies fixed-path kexec inputs without invoking
even a fixture executable. Tests also exercise recording evidence,
shared-volume concurrency denial, read-only recovery assets, digest mismatch,
container and volume cleanup, and fixed timeout/output quotas. Missing Docker,
namespace support, or security flags fails the job with diagnostics; the proof
never silently skips. SIGKILL lock release and stale-candidate recovery are
exercised in separate behavioral scenarios; the suite does not claim to model
power loss at every filesystem instruction between candidate creation and its
atomic rename.

The controller remains responsible for pinning the image by digest, enforcing
one active workload per node, expiring approvals independently, bounding pod
and evidence-volume lifetimes, and recording cleanup. An actual kexec executor
is deliberately unresolved: a provider must separately define immutable
signed assets, platform/kernel compatibility, lockdown and measured-boot
policy, health/rollback behavior, node quiescence, its own approval, and a
bounded cleanup contract before execution can be considered.

Network mutations use pinned kernel ifindexes. Linux does not expose an atomic
FDB add that also asserts the expected master ifindex, a persistent netdevice
handle preventing ifindex reuse, or an ifindex-based legacy auto-negotiation
ioctl. The helper checks bridge identity around the kernel request and derives
the ioctl name from the pinned index, but admission/controller policy must still
exclude other privileged host-network writers. The shared evidence volume must
provide local Linux advisory-lock semantics and its persistent lock file must
not be replaced while workloads may run.
