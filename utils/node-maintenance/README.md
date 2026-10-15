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
  digests. It never loads or executes a kernel;
* `kexec-recovery` repeats that validation, re-checks the approved Node boot ID
  and the controller deadline, then copies each file into a sealed private
  memfd, verifies the copied bytes and loads exactly those with
  `kexec_file_load` before rebooting into them. It re-checks the deadline before
  loading and before rebooting. On any failure it unloads the kernel and exits
  non-zero, and every exit reports `kexec_loaded=0|1|unknown` as the
  termination message; a successful kexec never returns;
* `hotfix-action` plans, applies or rolls back one controller-rendered
  platform hotfix on its node (see [Platform hotfix executor](#platform-hotfix-executor)).

The `node-recovery` preflight invokes `ethtool` against the exact controller-
selected interface and records its result as `ethtool.txt`; the integration
proof exercises this against a real loopback interface. The image does not
advertise an operation that its behavioral proof does not execute.

Broad neighbor flushing is not supported. Neighbor replacement requires one
exact IP/MAC/interface tuple. FDB replacement requires one exact
bridge/port/MAC/VLAN tuple and verifies bridge membership and VLAN presence
before mutation. The mutation helper resolves the approved names once, then
addresses links, neighbors, and FDB ports by kernel ifindex. It revalidates the
exact bridge master ifindex immediately around an FDB request. There is no
caller-selected shell, command, command argument,
path, recovery image, route, or sysctl interface. The image has no general
`kexec` tool, package manager, compiler, packet capture tool, or port scanner;
the fixed `kexec-action` helper accepts only the three verified `/recovery`
files and an approved boot ID.

The former `flush-neighbors` operation is intentionally unavailable. Use the
intent-specific `network-repair --action neighbor-replace` for one approved
neighbor tuple, `network-repair --action bridge-fdb-replace` for one approved
FDB tuple, and `node-recovery` when evidence is required without mutation.

## Controller and approval contract

Every invocation requires `BREAKGLASS_NODE_NAME`, `BREAKGLASS_OPERATION_ID`,
and `BREAKGLASS_RECORDING_ID` from the controller-owned immutable workload.
The requested node must exactly equal `BREAKGLASS_NODE_NAME`, which must come
from Downward API `spec.nodeName`; hostname discovery is not trusted.
All three helpers reject duplicate options, including repeated identical or
empty values, before execution; node-recovery preflight does not silently
replace an earlier target, interface, evidence directory, or confirmation.

The typed DebugSession executor also fixes `BREAKGLASS_ACTION_DEADLINE_UNIX`.
When supplied, this absolute deadline must be a future integer Unix timestamp;
network repair checks it before preflight and immediately before mutation.
It cannot extend the immutable session approval. See the
[controller contract](../../docs/node-maintenance-controller.md) for the
fixed Job, independent approval, live Node UID and per-node Lease fences.

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
network-repair tuple is 442 bytes, or 475 bytes with the optional VRF and
preview segments; the 1 KiB ceiling is defense in depth for
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
evidence-volume-root lock file serializes those quota calculations and commits,
including operations using different safe child directories, and permits one
operation at a time; the controller must not share that evidence volume with
an uncoordinated writer. After acquiring the root lock, the helper removes only
its owned stale `.capture-*`/`.evidence-*` candidates from the root or one safe
child, recovering files left by a killed container.
For a safe child, it also acquires and retains that child's legacy lock while
holding the root lock; a live pre-volume-root writer therefore blocks before
cleanup or evidence mutation, and its legacy artifacts are never removed.
This is a migration guard, not a mixed-version coordination protocol: an old
image can begin a different-child operation after the new image has taken and
checked the root lock, because that old image does not participate in the root
lock domain. Drain old workloads and do not overlap old and new image versions
on a shared evidence volume during rollout. The controller/admission layer
must enforce that deployment precondition.
The owner record
contains the operation, recording, approval, and SHA-256 digest of the exact
approved tuple. Its timestamp and PID are audit context only, never liveness
signals. The kernel releases exclusivity when the holder exits, is killed, or
its container dies, so there is no active-holder timeout and no clock-jump
recovery path. The lock file remains for reuse and must not be deleted or
replaced while any maintenance workload can run. The controller must also enforce
one active workload per node because separate volumes cannot coordinate.
Containers, evidence volumes, and controller leases must have bounded
lifetimes and deterministic cleanup.

The Docker integration contract separately demonstrates that an arbitrarily
old informational lock record does not override a live `flock`, that SIGKILL
releases that lock for a subsequent operation, and that a later operation
removes helper-owned stale temporary candidates. It deliberately does not
claim a power-loss proof for every instruction between candidate creation and
atomic rename; filesystem and storage-backend crash semantics remain an
operational validation responsibility.

## Invocation

Use the complete runbooks in [`runbooks/`](runbooks/). Representative commands
are:

```text
node-recovery \
  --target-node NODE --interface IFACE \
  --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT

network-repair \
  --target-node NODE --interface IFACE --action neighbor-replace \
  --neighbor-address IP --entry-mac MAC [--vrf VRF] [--dry-run] \
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
`node-recovery` and `kexec-recovery-validate` add none. Only `kexec-recovery`
adds `SYS_BOOT`, and it needs the host PID namespace (the kernel refuses a kexec
reboot from a child PID namespace) and an unconfined seccomp profile (runtime
default profiles deny `kexec_file_load`). Blanket privileged mode, host
network for kexec, and host-root mounts are outside this contract. The
separately approved host-namespace shape of `hotfix-action` is described below.

Kexec validation consumes only a distinct read-only `/recovery` mount with
fixed files `kernel`, `initrd`, and `cmdline`. Exact provider profile and
SHA-256 values come from immutable controller fields. The validator does not
evaluate cmdline contents or establish bootability. Kernel signature and
lockdown/measured-boot compatibility, the bundle itself and its rollback remain
provider responsibilities. The typed controller drains the Node before
`kexec-recovery` and proves the reboot by a new boot ID; see
[`runbooks/kexec-recovery-validation.md`](runbooks/kexec-recovery-validation.md).

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

## Platform hotfix executor

`hotfix-action` is the per-node executor of the typed platform hotfix
(`docs/hotfix.md`). It takes no arguments: the controller renders one JSON
request into `BREAKGLASS_HOTFIX_REQUEST` with the stage (`plan`, `apply`,
`rollback`), the payload, the profile allowlists, the planned hashes and the
session deadline. The executor repeats the API validation that matters on the
node (path denylist and allowlist, digest and SHA-256 pinning, sed command
shape, restartable units) so a tampered Pod spec cannot widen it, and writes
one JSON result to the termination message.

It has two runtime shapes, chosen by the controller:

| Shape | Used for | Contract |
|---|---|---|
| Mount-only | `node-file` without restarts | Not privileged, read-only root, capabilities `CHOWN`, `FOWNER`, `DAC_OVERRIDE` only. The target's parent directory is mounted at `/host<dir>` and `/var/lib/breakglass-hotfix` at `/host/var/lib/breakglass-hotfix` (`BREAKGLASS_HOST_ROOT=/host`); for a `url` source also `/etc/ssl/certs` read-only, for the node CA bundle. |
| Host namespace | `node-deb`, `static-pod-image`, `host-container-image`, any restart | Privileged with host PID. Host tools (`dpkg`, `systemctl`, `crictl`, `ctr`, `nerdctl`) run through `nsenter -t 1` (`BREAKGLASS_HOST_EXEC=nsenter`, `BREAKGLASS_HOST_ROOT=/proc/1/root`). A deb hotfix is root code execution on the node; the four-eyes plan review, pinning and allowlists are the controls. |

Safety rules of the executor:

- Files: every path component is checked with `lstat` and symlinks are
  refused; only regular files up to 64 MiB. The first pre-image is kept in
  `/var/lib/breakglass-hotfix/<id>/` with its mode, owner and hashes. The new
  content is written to a hidden temporary file in the same directory (kubelet
  ignores dot files in the static Pod directory), synced and renamed, the
  directory is synced, and the result hash is verified.
- `sed` runs the image's GNU sed with `--sandbox` on stdin only. Unified
  diffs are applied in Go without fuzz or offset.
- Apply refuses a node whose pre-image hash differs from the plan and skips a
  node that already has the planned result. Rollback restores only from the
  hotfix backup and only while the file still has the hotfix content.
- Debs: downloaded over HTTPS with the node's CA bundle and checked by SHA-256
  before use; `dpkg-deb -f` must match the package and version; `/usr` must
  be writable; `dpkg --dry-run -i` must pass in the plan. Apply installs with a
  temporary `policy-rc.d` that denies service starts,
  `--force-hold --force-confold`, re-asserts previous holds, checks
  `dpkg --audit` and the installed versions, then restarts only the requested
  units. Rollback installs `rollbackDebs` and purges packages the hotfix added.
- Static Pods: the image is pre-pulled with `crictl pull` and must carry the
  pinned digest; the single `image:` line of the kubeadm manifest is replaced;
  the executor waits until the static Pod runs the new image ID. For `etcd`,
  every member must answer and agree on one leader before the change, and
  again after it.
- Host containers: the image is pulled into the container's containerd
  namespace (`ctr ... images pull --hosts-dir /etc/containerd/certs.d`), the
  image reference file is replaced, the unit is restarted and `nerdctl
  inspect` must show the new image running. For cra-vsr this interrupts the
  node's network while the container restarts.
- Deadlines: each step has a fixed budget (for example 30 s for a file write,
  10 min for a dpkg transaction, 5 min for a pull) and is never started when
  that budget no longer fits before the session deadline. Mutating stages
  ignore SIGTERM; the controller sets the Pod grace period to the remaining
  deadline. No hotfix step runs under the 10 s capture timeout of the shell
  helpers.

Plan `nodeDeadlineSeconds` per payload type: a file change needs a few
seconds; a deb apply needs the downloads (up to 5 min each), up to 10 min for
dpkg, 1 min for `dpkg --audit` and 2 min per restart; a static Pod needs 5 min
for the pull and 5 min to come back; a host container needs 5 min for the pull
and 3 min for the restart. A step that does not fit the remaining time is
never started. Pulls use `/etc/containerd/certs.d` as the containerd hosts
directory.

`make test` runs the executor's unit tests (requires GNU sed).
`make hotfix-image` runs the mount-only shape of the real image against a
disposable directory.

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

## Platform hotfix executor

`hotfix-action` is the per-node executor of the typed platform hotfix
(`docs/hotfix.md`). It takes no arguments: the controller renders one JSON
request into `BREAKGLASS_HOTFIX_REQUEST` with the stage (`plan`, `apply`,
`rollback`), the payload, the profile allowlists, the planned hashes and the
session deadline. The executor repeats the API validation that matters on the
node (path denylist and allowlist, digest and SHA-256 pinning, sed command
shape, restartable units) so a tampered Pod spec cannot widen it, and writes
one JSON result to the termination message.

It has two runtime shapes, chosen by the controller:

| Shape | Used for | Contract |
|---|---|---|
| Mount-only | `node-file` without restarts | Not privileged, read-only root, capabilities `CHOWN`, `FOWNER`, `DAC_OVERRIDE` only. The target's parent directory is mounted at `/host<dir>` and `/var/lib/breakglass-hotfix` at `/host/var/lib/breakglass-hotfix` (`BREAKGLASS_HOST_ROOT=/host`); for a `url` source also `/etc/ssl/certs` read-only, for the node CA bundle. |
| Host namespace | `node-deb`, `static-pod-image`, `host-container-image`, any restart | Privileged with host PID. Host tools (`dpkg`, `systemctl`, `crictl`, `ctr`, `nerdctl`) run through `nsenter -t 1` (`BREAKGLASS_HOST_EXEC=nsenter`, `BREAKGLASS_HOST_ROOT=/proc/1/root`). A deb hotfix is root code execution on the node; the four-eyes plan review, pinning and allowlists are the controls. |

Safety rules of the executor:

- Files: every path component is checked with `lstat` and symlinks are
  refused; only regular files up to 64 MiB. The first pre-image is kept in
  `/var/lib/breakglass-hotfix/<id>/` with its mode, owner and hashes. The new
  content is written to a hidden temporary file in the same directory (kubelet
  ignores dot files in the static Pod directory), synced and renamed, the
  directory is synced, and the result hash is verified.
- `sed` runs the image's GNU sed with `--sandbox` on stdin only. Unified
  diffs are applied in Go without fuzz or offset.
- Apply refuses a node whose pre-image hash differs from the plan and skips a
  node that already has the planned result. Rollback restores only from the
  hotfix backup and only while the file still has the hotfix content.
- Debs: downloaded over HTTPS with the node's CA bundle and checked by SHA-256
  before use; `dpkg-deb -f` must match the package and version; `/usr` must
  be writable; `dpkg --dry-run -i` must pass in the plan. Apply installs with a
  temporary `policy-rc.d` that denies service starts,
  `--force-hold --force-confold`, re-asserts previous holds, checks
  `dpkg --audit` and the installed versions, then restarts only the requested
  units. Rollback installs `rollbackDebs` and purges packages the hotfix added.
- Static Pods: the image is pre-pulled with `crictl pull` and must carry the
  pinned digest; the single `image:` line of the kubeadm manifest is replaced;
  the executor waits until the static Pod runs the new image ID. For `etcd`,
  every member must answer and agree on one leader before the change, and
  again after it.
- Host containers: the image is pulled into the container's containerd
  namespace (`ctr ... images pull --hosts-dir /etc/containerd/certs.d`), the
  image reference file is replaced, the unit is restarted and `nerdctl
  inspect` must show the new image running. For cra-vsr this interrupts the
  node's network while the container restarts.
- Deadlines: each step has a fixed budget (for example 30 s for a file write,
  10 min for a dpkg transaction, 5 min for a pull) and is never started when
  that budget no longer fits before the session deadline. Mutating stages
  ignore SIGTERM; the controller sets the Pod grace period to the remaining
  deadline. No hotfix step runs under the 10 s capture timeout of the shell
  helpers.

Plan `nodeDeadlineSeconds` per payload type: a file change needs a few
seconds; a deb apply needs the downloads (up to 5 min each), up to 10 min for
dpkg, 1 min for `dpkg --audit` and 2 min per restart; a static Pod needs 5 min
for the pull and 5 min to come back; a host container needs 5 min for the pull
and 3 min for the restart. A step that does not fit the remaining time is
never started. Pulls use `/etc/containerd/certs.d` as the containerd hosts
directory.

`make test` runs the executor's unit tests (requires GNU sed).
`make hotfix-image` runs the mount-only shape of the real image against a
disposable directory.

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
