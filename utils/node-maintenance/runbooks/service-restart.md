<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Service restart

Use `service-restart` when a host service on a node is degraded but the kubelet
and containerd can still start the executor Pod, for example a router container
(`cra.service`) that lost its sessions, or a containerd or kubelet that needs a
re-exec. It restarts one unit: `containerd.service`, `kubelet.service` or
`cra.service` (the CRA/vSR router container). The executor is a Pod: if the
kubelet or containerd hangs so that no Pod starts, the session ends
`interrupted` at its deadline and the controller uncordons the unchanged Node;
recover such a node out of band.

Before you request it:

* The Node must be a worker. The controller cordons and drains it before the
  restart and refuses control-plane Nodes.
* On a CRA node (`cra.service` exists) restarting `containerd.service` also
  restarts `cra.service` (`Requires=containerd.service`). Both remove the
  node's network (`hbn`, `oam0`) for seconds to minutes while the router
  container and its sessions come back. Plan this like a short network outage
  of that Node.
* A restarted router container starts from its base configuration. The
  template's `restartPods` must recreate the network agent on the Node so it
  re-applies the node network configuration.

What the helper checks (evidence under `/evidence/service-restart-*`):

1. the unit is loaded (`before-unit.txt`) and, on a CRA node, `cra.service`
   (`before-cra.txt`) and the host links (`before-links.txt`);
2. `RestartUnit` was accepted (`action-restart.txt`);
3. within at most 240 s and the session deadline: the unit is active with a
   new activation time; for CRA, `cra.service` too, `hbn` and `netconf`
   exist, and `oam0` (if present) has a global address (`after-*.txt`).

The controller then requires a Ready Node and a new Ready Pod for each
`restartPods` selector before it reports success and uncordons the Node.

If the result is `failed` or `unknown`, the Node stays cordoned. Do not retry
in a loop: replace the Node (node replacement runbook of your platform) or
investigate on the console. Nothing the helper does is persistent.
