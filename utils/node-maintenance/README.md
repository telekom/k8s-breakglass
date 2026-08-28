<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Kubernetes node-maintenance image

This digest-pinnable, multi-architecture image provides three controller-
targeted incident interfaces:

* `node-recovery` collects read-only link, address, route, neighbor, NIC,
  resolver, and kernel evidence for one exact interface;
* `network-repair` performs one independently approved allowlisted action:
  `link-cycle`, `restart-autonegotiation`, `neighbor-replace`, or
  `bridge-fdb-replace`;
* `kexec-recovery-validate` validates fixed provider-owned recovery files and
  digests. It never loads or executes a kernel.

Broad neighbor flushing is not supported. Neighbor replacement requires one
exact IP/MAC/interface tuple. FDB replacement requires one exact
bridge/port/MAC/VLAN tuple and verifies bridge membership and VLAN presence
before mutation. The mutation helper resolves the approved names once, then
addresses links, neighbors, and FDB ports by kernel ifindex. It revalidates the
exact bridge master ifindex immediately around an FDB request. There is no
caller-selected shell, command, command argument,
path, recovery image, route, or sysctl interface. The image has no kexec
executable, package manager, compiler, packet capture tool, or port scanner.

## Controller and approval contract

Every invocation requires `BREAKGLASS_NODE_NAME`, `BREAKGLASS_OPERATION_ID`,
and `BREAKGLASS_RECORDING_ID` from the controller-owned immutable workload.
The requested node must exactly equal `BREAKGLASS_NODE_NAME`, which must come
from Downward API `spec.nodeName`; hostname discovery is not trusted.

Every mutating repair and kexec validation additionally requires
`BREAKGLASS_APPROVAL_ID` and an exact `BREAKGLASS_APPROVED_ACTION` match.
Network repair also requires the controller-owned
`BREAKGLASS_APPROVED_NETWORK_REQUEST` canonical tuple covering target node,
interface, action, every action-specific target, and confirmation. The image
compares it byte-for-byte before evidence or mutation; it is not a substitute
for controller/admission protection of the environment. The command
confirmation string is an operator error guard, not authorization. Node names
are checked as Kubernetes RFC 1123 DNS subdomains, including the 253-byte
total and 63-byte per-label limits; the complete canonical tuple has its own
fixed 1 KiB bound so a valid maximum-length Node name is not rejected by a
per-value limit. Linux interface and bridge names are
independently limited to 15 bytes, so the largest accepted public
network-repair tuple is 442 bytes; the 1 KiB ceiling is defense in depth for
controller-provided serialized data.
Preflight, each network action, kexec validation, and any future provider
executor need independent approval decisions; approval for one must never be
reused as approval for another.

Each command creates `metadata` plus `events.jsonl` recording hooks correlated
by operation and recording IDs. Repair captures before/action/after evidence;
kexec validation records fixed-file digests and an explicit
`execution_performed=false`. Validated request values and captures have fixed
limits: values are at most 256 bytes, captures have fixed 10-second, 32 KiB per-file,
and 384 KiB per-bundle bounds. Captures, metadata, and JSONL event updates are
prepared outside the bundle and atomically renamed only after their final
disk-usage quota is accepted; a full bundle fails without a partial event or
metadata write. A process-held Linux `flock` on the persistent
evidence-volume lock file serializes those quota calculations and commits and
permits one operation at a time; the controller must not share that evidence
volume with an uncoordinated writer. The owner record
contains the operation, recording, approval, and SHA-256 digest of the exact
approved tuple. Its timestamp and PID are audit context only, never liveness
signals. The kernel releases exclusivity when the holder exits, is killed, or
its container dies, so there is no active-holder timeout and no clock-jump
recovery path. The lock file remains for reuse and must not be deleted or
replaced while any maintenance workload can run. The controller must also enforce
one active workload per node because separate volumes cannot coordinate.
Containers, evidence volumes, and controller leases must have bounded
lifetimes and deterministic cleanup.

## Invocation

Use the complete runbooks in [`runbooks/`](runbooks/). Representative commands
are:

```text
node-recovery \
  --target-node NODE --interface IFACE \
  --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT

network-repair \
  --target-node NODE --interface IFACE --action neighbor-replace \
  --neighbor-address IP --entry-mac MAC \
  --evidence-dir /evidence --confirm NETWORK-REPAIR

network-repair \
  --target-node NODE --interface BRIDGE_PORT --bridge BRIDGE \
  --action bridge-fdb-replace --entry-mac MAC --vlan VLAN \
  --evidence-dir /evidence --confirm NETWORK-REPAIR

kexec-recovery-validate \
  --target-node NODE --recovery-profile PROVIDER_PROFILE \
  --evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
```

Evidence is restricted to `/evidence` or one safe child. System paths,
symlinks, rename substitutions, and unbounded output are rejected. Unsupported
or action-irrelevant options are rejected instead of ignored.

## Runtime security contexts

Use separate immutable workloads and pin this image by digest. All contexts
run with a read-only root, `allowPrivilegeEscalation: false`, RuntimeDefault
seccomp, and capabilities dropped. Add only `NET_ADMIN` for `network-repair`;
`node-recovery` and `kexec-recovery-validate` add none. Blanket privileged
mode, `SYS_BOOT`, host PID, and host-root mounts are outside this contract.

Kexec validation consumes only a distinct read-only `/recovery` mount with
fixed files `kernel`, `initrd`, and `cmdline`. Exact provider profile and
SHA-256 values come from immutable controller fields. The validator does not
evaluate cmdline contents or establish bootability. Kernel signature,
lockdown/measured-boot compatibility, device quiescence, rollback, health
checking, and execution remain unresolved provider responsibilities documented
in [`runbooks/kexec-recovery-validation.md`](runbooks/kexec-recovery-validation.md).

The Alpine runtime contains `/bin/sh` because the fixed helpers are POSIX
scripts. An entrypoint override is an external admission-policy boundary, not
a supported feature.

The Linux FDB add ABI identifies the port by ifindex but does not accept an
expected bridge-master identity in the same atomic request. The helper checks
the approved master before and after the request, while the kernel checks that
the port is currently bridged and that the VLAN is currently configured during
the request. A separate privileged host-network actor can still reparent a port
inside that narrow interval; controller/admission policy must exclude such
concurrent writers. Linux also has no persistent userspace netdevice handle
that prevents ifindex reuse after delete/recreate. Auto-negotiation's legacy
ioctl requires a name, so the helper derives that name from the pinned ifindex
immediately before the ioctl and verifies the mapping afterwards. These kernel
ABI limits are why per-node workload exclusivity remains mandatory.

Upgrades from the short-lived directory-lease implementation may encounter an
old `.node-maintenance-operation.lock` directory. After proving that no old or
new maintenance workload is active, remove that obsolete directory once; the
new implementation creates a persistent regular lock file in its place.

## Runbook bundle, build, and proof

Built-in runbooks are image-owned at
`/usr/share/breakglass/runbooks/upstream/node-maintenance/`. A deployment may
mount a digest-pinned downstream documentation bundle read-only at
`/usr/share/breakglass/runbooks/internal`; it is never sourced or executed.

`make test` runs fast behavioral denial checks. `make integration` uses a
Linux Docker daemon and exercises every action in disposable Docker network
namespaces, including real veth neighbor and VLAN bridge-FDB changes, exact-
target adversarial cases, every approved-tuple mismatch, interface-name
replacement, changed bridge membership, an arbitrarily old live lock holder,
crash release, immutable kexec input checks, recording evidence, and cleanup.
The proof refuses to skip when its
Linux/Docker prerequisites are absent.

`make build-multiarch` requests provenance and an SPDX SBOM for amd64/arm64.
Release automation must sign and attest only an immutable registry digest via
`make sign DIGEST=...` and `make sbom DIGEST=... SBOM=...`; local targets do
not push images. Pinned packages are recorded in [`deps.lock`](deps.lock).
