<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Platform hotfix

A platform hotfix rolls out one critical node-level fix across a cluster when
a regular release or a node image rebuild is too slow. It is a bridge: the
regular release must still ship the fix. Every stage is a separate session
with an independent approver; self-approval is never possible.

## 1. Decide

| Situation | Use |
|---|---|
| The fix can wait for the next release or node image | The regular release. No hotfix. |
| A Helm/Flux-managed workload image (DaemonSet, Deployment) | The owning release. Hotfixes do not change workload images. |
| A node config file, a Debian package, kubelet/containerd binaries, a control-plane static Pod image (incl. etcd), or a host container image such as cra-vsr | Platform hotfix (this runbook). |
| A fix that fits no payload type, or the hotfix executor itself is broken | Emergency node debug session as the last resort (four-eyes, audit, incident ID). It is not tracked as drift: open a follow-up to replace it with a release or a hotfix. |

## 2. Prepare the source

- Mirror the image, deb or file into the cluster's registry or repository
  **by digest** first. Nodes may not reach arbitrary sources, and the plan
  fails if a source is unreachable.
- Note the exact digest or SHA-256, and the release that will contain the fix
  (`fixedIn`).

## 3. Plan (dry run)

Request a `plan` session with the payload, the node selection, the rollout
and `fixedIn`. The plan changes nothing on the node except caching debs in
`/var/lib/breakglass-hotfix/<id>/` and restoring a `policy-rc.d` that an
earlier, killed hotfix executor left behind.

The approver of the **apply** stage checks the plan:

- the source and digest are the mirrored, expected ones;
- the node list (name and UID) and batch layout are right; control-plane
  nodes run one at a time;
- every per-node diff and before/after hash is expected; nodes marked `skip`
  already have the result;
- debs: package names and versions; new packages are listed and will be
  purged on rollback; `rollbackDebs` exist for upgraded packages;
- `all-at-once` has a reason that justifies skipping the canary.

## 4. Apply

Request an `apply` session with `planRef` and the reviewed `planHash` within
2 hours of the plan. Each node runs one executor Pod, once. Any failure stops
further batches; the failed node is reported and done nodes keep the fix.

Effects to expect:

- containerd or kubelet restart: short disruption of the node's workloads;
- static Pod image: the component on that node restarts; etcd only with all
  members healthy;
- cra-vsr: the node's network is interrupted while the container restarts.

If a deb apply fails half-way, run `dpkg --audit` and `dpkg --configure -a`
on the node (emergency node debug session) before a rollback. A
`/usr/sbin/policy-rc.d` that a killed executor left behind is restored by the
next hotfix run on that node.

## 5. Revoke at any time

- **No new hotfixes:** set `spec.hotfix.suspended: true` on the template, or
  remove the template. Rollback, reconfirm and close stay possible.
- **Stop a running rollout:** terminate the apply session. Started nodes
  finish within their deadline; no further batch starts. The HotfixRecord
  shows which nodes have the fix.
- **Revert:** request a `rollback` session for the HotfixRecord.
  - files and static Pod manifests: restored from the node backup, only while
    the file still has the hotfix content;
  - debs: `rollbackDebs` are installed and new packages purged; without
    `rollbackDebs`, replace the node;
  - host containers: the previous image reference is restored and the unit
    restarted.
- **Controller unavailable:** no further batch starts. Running executors stop
  at their deadline. The record stays; continue with rollback once the
  controller is back, or replace affected nodes.

## 6. Track and close

The HotfixRecord shows the hotfix as drift and alerts until it is closed.
Nodes created later without the hotfix are `uncovered` (critical alert):
apply the hotfix to them or close it. At expiry the alert becomes critical; it
never rolls back on its own. Reconfirm (four-eyes), roll back, or close after
the regular release with the fix is rolled out.

## Supply-chain warning

A deb hotfix is root code execution on every selected node. Two colluding or
compromised approvers, a typo-squatted registry or a poisoned URL can still
roll out a malicious change. Use only mirrored, reviewed sources.
