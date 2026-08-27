<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Allowlisted network repair

Use this procedure only after preflight evidence has been reviewed and the
incident ticket has explicit approval. Repairs can interrupt traffic.

Allowed actions are `link-cycle` (take the named interface down/up),
`flush-neighbors` (flush neighbor entries for the interface), and
`restart-autonegotiation` (ask the NIC to restart auto-negotiation).

Run exactly one action, replacing every uppercase placeholder:

```text
network-repair \
  --target-node NODE_NAME \
  --interface IFACE_NAME \
  --action ACTION \
  --evidence-dir /evidence \
  --confirm NETWORK-REPAIR
```

The helper refuses a target node that does not exactly match the controller-
provided `BREAKGLASS_NODE_NAME` (from Downward API `spec.nodeName`) and refuses
evidence paths other than `/evidence` or one safe child, including symlink or
rename changes. Run with
`hostNetwork: true`, `allowPrivilegeEscalation: false`, all capabilities
dropped except `NET_ADMIN`, and a read-only root filesystem; blanket
`privileged: true` is not required.

The helper captures link, address, route, and neighbor state before and after
the action. Preserve the bundle even if the action exits non-zero. Verify node
readiness and application health through the normal platform process; this
image has no unrestricted shell or general-purpose diagnostic toolbox.
Every action and probe has a fixed time/output budget. This command cannot
perform route replacement, sysctl changes, capture, crashdump collection,
node discovery, arbitrary commands, kexec, or reboot. An entrypoint override
is outside the external immutable-template and admission-control boundary.
