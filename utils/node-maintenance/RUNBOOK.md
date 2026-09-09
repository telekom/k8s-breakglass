<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Node-maintenance runbook

Use `node-recovery` first to collect read-only evidence. Only after that
evidence and an incident approval are recorded may `network-repair` run one
allowlisted action: `link-cycle`, `restart-autonegotiation`,
`neighbor-replace`, or `bridge-fdb-replace`. Both helpers require an exact target node,
interface, evidence directory, and confirmation token. Read the detailed
guides in `/usr/share/node-maintenance/runbooks/` before invoking either
helper. Repairs require host networking and only `NET_ADMIN`; never use an
unrestricted shell or blanket privileged mode.

The former `flush-neighbors` operation is rejected because it lacks an exact
input tuple. Use `neighbor-replace` with one address and MAC, or
`bridge-fdb-replace` with one bridge, port, MAC, and VLAN.
