<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Allowlisted network repair

Use this procedure only after reviewing preflight evidence and obtaining an
approval for this exact action and tuple. A confirmation token is not approval.
Do not reuse approval for another repair, node, interface, bridge, entry, or
kexec validation.

The four actions are:

* `link-cycle` for the named interface;
* `restart-autonegotiation` for the named interface;
* `neighbor-replace` for one IP/MAC/interface tuple;
* `bridge-fdb-replace` for one bridge/port/MAC/VLAN tuple.

Broad neighbor flush, FDB flush, delete-all, inferred interfaces, and inferred
bridges are intentionally absent. Run exactly one action:

```text
network-repair \
  --target-node NODE_NAME \
  --interface IFACE_NAME \
  --action link-cycle \
  --evidence-dir /evidence \
  --confirm NETWORK-REPAIR

network-repair \
  --target-node NODE_NAME \
  --interface IFACE_NAME \
  --action neighbor-replace \
  --neighbor-address IP_ADDRESS \
  --entry-mac MAC_ADDRESS \
  --evidence-dir /evidence \
  --confirm NETWORK-REPAIR

network-repair \
  --target-node NODE_NAME \
  --interface BRIDGE_PORT \
  --bridge BRIDGE_NAME \
  --action bridge-fdb-replace \
  --entry-mac MAC_ADDRESS \
  --vlan VLAN_ID \
  --evidence-dir /evidence \
  --confirm NETWORK-REPAIR
```

The immutable controller template must inject `BREAKGLASS_NODE_NAME` from
Downward API `spec.nodeName`, unique operation/recording/approval identifiers,
`BREAKGLASS_APPROVED_ACTION`, and
`BREAKGLASS_APPROVED_NETWORK_REQUEST`. The latter is an exact canonical tuple
of target node, interface, action, neighbor, bridge, MAC, VLAN, and
confirmation; the helper compares it before any evidence or mutation and binds
the evidence lock record to its SHA-256 digest. It must
pin the image by digest and enforce one active operation per node. The helper
also holds a kernel `flock` on the shared evidence-volume-root lock for its
process lifetime, including when a safe child evidence directory is selected;
that cannot coordinate distinct volumes. No timestamp reclaims a live holder.
Container death releases the lock immediately; its regular lock file persists
and must not be deleted or replaced while operations can run. After taking that
lock, the helper recovers only its owned stale temporary candidate files from
the volume root or selected safe child.
The tuple is separately bounded at 1 KiB so Kubernetes-valid 253-byte node
names remain usable; this bound is not a caller input. Linux interface and
bridge names are limited to 15 bytes, so the largest public network-repair
tuple is 442 bytes; the 1 KiB serialized-input limit is defense in depth for
controller-provided data, not a caller choice.

Run with `hostNetwork: true`, a read-only root, RuntimeDefault seccomp,
`allowPrivilegeEscalation: false`, all capabilities dropped except
`NET_ADMIN`, no host PID, and no host filesystem mount. The helper verifies the
exact interface and performs mutations through a fixed helper using the pinned
kernel ifindex, not the caller's interface name. Neighbor repair also verifies
the address routes through that interface. FDB repair verifies the exact bridge
exists, the port is enslaved to its pinned master ifindex, and the exact VLAN is
configured before changing one entry; the kernel validates port and VLAN again
during the FDB request.

Preserve `metadata`, `events.jsonl`, and all before/action/after captures even
on non-zero exit. Each command and capture has a fixed timeout and quota. A
full evidence bundle rejects the final metadata or event update before rename,
leaving the previous complete file intact rather than emitting a partial audit
record. A link cycle makes one bounded attempt to bring the interface up after
bringing it down. Verify node and application health through normal platform
controls, then allow the controller to clean up the workload, evidence volume,
and node-scoped lease within their configured deadlines.

This helper cannot run caller commands or arguments, select paths or images,
replace routes, mutate sysctls, capture traffic, reboot, or execute kexec.

Linux does not provide one FDB-add request containing both a port ifindex and
an asserted master ifindex, nor a persistent userspace handle that prevents
ifindex reuse after delete/recreate. The helper therefore checks master
identity immediately before and after the fixed FDB request, and derives the
legacy auto-negotiation ioctl name from the pinned ifindex immediately before
use. A concurrently privileged actor outside the controller lock could still
race those kernel ABI boundaries. Admission and controller policy must enforce
one host-network writer per node. If upgrading from the former directory
lease, remove an obsolete `.node-maintenance-operation.lock` directory only
after proving that no maintenance workload is active; leave the new regular
lock file in place for reuse.
