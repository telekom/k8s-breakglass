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
and `BREAKGLASS_APPROVED_ACTION` equal to the requested action. It must pin the
image by digest and enforce one active operation per node. The helper also
takes an atomic evidence-volume lease, but that cannot coordinate distinct
volumes.

Run with `hostNetwork: true`, a read-only root, RuntimeDefault seccomp,
`allowPrivilegeEscalation: false`, all capabilities dropped except
`NET_ADMIN`, no host PID, and no host filesystem mount. The helper verifies the
exact interface. Neighbor repair also verifies the address routes through that
interface. FDB repair verifies the exact bridge exists, the port is enslaved
to it, and the exact VLAN is configured before changing one entry.

Preserve `metadata`, `events.jsonl`, and all before/action/after captures even
on non-zero exit. Each command and capture has a fixed timeout and quota. A
link cycle makes one bounded attempt to bring the interface up after bringing
it down. Verify node and application health through normal platform controls,
then allow the controller to clean up the workload, evidence volume, and
node-scoped lease within their configured deadlines.

This helper cannot run caller commands or arguments, select paths or images,
replace routes, mutate sysctls, capture traffic, reboot, or execute kexec.
