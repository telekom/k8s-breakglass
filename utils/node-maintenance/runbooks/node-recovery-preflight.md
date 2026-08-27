<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Node recovery preflight

Use this read-only procedure before changing a node network interface.

1. Confirm the incident ticket, approval, exact node name, exact interface
   name, and a writable evidence destination. Ensure the controller's
   immutable template injects `BREAKGLASS_NODE_NAME` from the Downward API
   `spec.nodeName`; never proceed with a hostname-derived value or a guess.
2. Run a host-networked pod using the image. Mount an empty,
   operator-controlled directory at `/evidence`; do not mount the host root.
   Drop all capabilities and add none. Use a separate repair workload context
   if a mutation is approved later.
3. Execute the fixed command, replacing every uppercase placeholder:

   ```text
   node-recovery \
     --target-node NODE_NAME \
     --interface IFACE_NAME \
     --evidence-dir /evidence \
     --confirm NODE-RECOVERY-PREFLIGHT
   ```

4. Preserve the printed evidence bundle and ticket it before proceeding. A
   missing interface is a hard stop; an unsupported probe is recorded.
5. Review `interface.txt`, `addresses.txt`, `routes.txt`, `neighbors.txt`,
   `ethtool.txt`, `resolver.txt`, `kernel.txt`, and `metadata` with the
   incident responder. Timeout and quota status are explicit in the files.
   The helper does not decide whether repair is safe.

The image does not provide an interactive shell. If this preflight is
insufficient, stop and follow the separately approved host-debug process.
It does not provide node discovery, crashdump collection, capture, arbitrary
commands, kexec/reboot, sysctl changes, or route replacement.
