<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# SR-IOV re-provision

Use `sriov-reprovision` when a worker Node lost the SR-IOV virtual functions
(VFs) of one physical function (PF) that its netplan configuration defines,
for example because the VFs were not created at boot (`sriov_numvfs` is 0 and
the SR-IOV device plugin advertises no devices). A reboot or a replacement can
hit the same boot-order problem, so re-applying the configuration is the
repair.

Before you request it:

* The Node must be a worker. The controller cordons and drains it before the
  run and refuses control-plane Nodes. A Pod that holds an SR-IOV device must
  be evicted; DaemonSet Pods stay on the Node.
* The template `maxDuration` must cover `drainTimeoutSeconds` plus 600 s
  (both netplan steps, the VF check and the controller post-checks).
* The allowlist names the Node, its UID, the PF and the approved VF count.
  The count must equal what the node's netplan configuration creates for that
  PF (`virtual-function-count`); otherwise the post-check fails.
* `netplan apply --sriov-only` applies the SR-IOV settings of all PFs in the
  netplan configuration, not only the allowlisted one. It does not change
  other network settings. `netplan rebind` acts only on the allowlisted PF.
* Use the template's `restartPods` for the SR-IOV device plugin Pod on the
  Node, so that it advertises the new VFs.

What the helper checks (evidence under `/evidence/sriov-reprovision-*`):

1. the PF is an SR-IOV PF with at least the approved number of VFs
   (`before-vfs.txt`, `before-links.txt`);
2. systemd ran `netplan apply --sriov-only` and then `netplan rebind <PF>` as
   transient host units, each within 120 s (a unit that runs longer is
   stopped) and with exit status 0
   (`action-netplan-*.txt`; the command output is in the host journal of
   the units `breakglass-netplan-sriov-apply.service` and
   `breakglass-netplan-rebind.service`);
3. within at most 120 s and the session deadline: `sriov_numvfs` equals the
   approved count and each VF exists and is bound to a driver
   (`after-vfs.txt`).

The controller then requires a Ready Node and a new Ready Pod for each
`restartPods` selector before it reports success and uncordons the Node.

If the result is `failed` or `unknown`, the Node stays cordoned. Do not retry
in a loop: check the netplan configuration and the PF driver on the console,
or replace the Node. Nothing the helper does is persistent: the next boot
creates the VFs from netplan again.
