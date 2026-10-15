<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Platform hotfix sessions

`DebugSessionTemplate.spec.hotfix` opts a template into the typed platform
hotfix executor. It rolls out one critical fix to the nodes of a cluster when a
regular release or a node image rebuild is too slow. A hotfix is a bridge: the
regular release must still ship the fix, and the hotfix is tracked as drift
until it is closed.

The field is absent by default. This controller version serves the `plan`,
`apply` and `rollback` stages; `reconfirm` and `close` are refused at request
time until the record lifecycle is served.

## Scope

Payload types (`payloadTypes` in the template, `payload.type` in the request):

| Type | Change on each node |
|---|---|
| `node-file` | Replace one regular file (`replace`), or patch it in place with GNU sed `-E` substitution commands (`sed`) or a single-file unified diff (`diff`). Optionally restart allowlisted units. |
| `node-deb` | Install 1..16 pinned `.deb` files in one dpkg transaction. New packages are allowed; `dpkg --dry-run` must show no unmet dependency. |
| `static-pod-image` | Pre-pull a digest-pinned image and patch the image of one kubeadm control-plane static Pod (`kube-apiserver`, `kube-controller-manager`, `kube-scheduler`, `etcd`). Control-plane nodes run one at a time. |
| `host-container-image` | Swap the image of a container that systemd runs on the host with nerdctl, outside Kubernetes, for example `cra-vsr`. |

Kubelet and containerd binaries are changed with `node-file` or `node-deb`.
Workload images that Helm or Flux manage (DaemonSets, Deployments) are out of
scope: change them through the owning release.

If a fix does not fit any payload type, use the emergency node debug session
as the last resort. It can change the host directly, with four-eyes approval,
an audit record and an incident ID, but it is not tracked as drift.

## Lifecycle and four-eyes approval

Every stage is a separate DebugSession with its own independent approval.
Self-approval is always blocked, in every environment.

| Stage | Request fields | Effect |
|---|---|---|
| `plan` | `payload`, `nodes`, `rollout`, `lifetime`, `fixedIn` | Read-only dry run on every selected node. Resolves the selection to Node name and UID, records the pre-image hash, the planned result hash and a per-node diff, and computes `planHash`. |
| `apply` | `planRef`, `planHash` | Executes exactly the referenced plan. The plan must have succeeded less than 2 h ago, for the same cluster and template, its hash must equal `planHash`, it must still fit the template as it is now, and it is applied at most once. Creates a `HotfixRecord`. |
| `rollback` | `recordName` | Reverts the recorded nodes: file restore, `rollbackDebs` (new packages are purged), previous image. |
| `reconfirm` | `recordName`, `lifetime` | Extends the expiry, at most to the template `maxLifetime` (at most 30 days). |
| `close` | `recordName` | Ends drift tracking after the regular release contains the fix. |

The template must set `blockSelfApproval: true`, and a binding cannot relax
it. Production approval routing (for example FLM or a platform peer, never the
requester) is configured with the template or binding approvers and the
ClusterConfig `blockSelfApproval` contract.

## Template profile

```yaml
spec:
  mode: workload
  targetNamespace: breakglass-node-maintenance
  blockSelfApproval: true
  constraints:
    maxDuration: 4h        # at most 6h; idleTimeout is rejected
  approvers:
    groups: [YOUR_INDEPENDENT_APPROVER_GROUP]
  hotfix:
    executorImage: ghcr.io/telekom/k8s-breakglass/utils/node-maintenance@sha256:...
    payloadTypes: [node-file, node-deb, static-pod-image, host-container-image]
    allowedPaths:
      - /etc/containerd/config.toml
      - /etc/ssh/                    # directory prefix
    restartableServices: [containerd.service, kubelet.service, ssh.service, chrony.service]
    staticPods: [kube-apiserver, kube-controller-manager, kube-scheduler, etcd]
    hostContainers:
      - name: cra-vsr
        containerdNamespace: hbr
        unit: cra.service
        imageRefFile: /etc/cra/image
    allowAllAtOnce: true
    maxBatchPercent: 25    # default 25
    minSoakSeconds: 60     # default 60
    maxNodes: 500          # default 500, at most 1000
    nodeDeadlineSeconds: 900
    maxLifetime: 30d       # default and maximum 30d
```

Do not allow `/etc/kubernetes/manifests/` for `node-file` unless you need to
change flags of a static Pod: a file payload there can change any part of the
Pod, while `static-pod-image` changes only the digest-pinned image.

`systemd-networkd.service` can be restarted only if the template lists it.

## Validation rules

The API rejects a request before approval when any rule fails:

- **Pinning.** Images are `registry-host/repository@sha256:<64 hex>` without a
  tag; the registry host is required so the reference is not normalised to
  `docker.io` on the node. Files and
  debs are pinned by lowercase SHA-256. The executor image is digest-pinned.
- **Sources.** URLs must be `https` without credentials, query string or
  fragment (presigned URLs would put tokens into the audit trail). Any
  pinned source is allowed; the plan, approval, audit trail and record show the
  exact source and digest. Inline content is at most 64 KiB and is recorded in
  the audit trail, so it must not contain secrets.
- **Paths.** Absolute, clean, no `..`, characters `[A-Za-z0-9._@+/-]` only,
  inside `allowedPaths` (exact path or directory prefix ending in `/`). The
  executor also refuses symlinks and non-regular files. A hard denylist applies
  even if `allowedPaths` covers it. The executor checks every component of the
  path on the node with `lstat` and refuses any symlink, so a symlinked
  directory inside an allowed prefix cannot redirect the write. Use canonical
  paths: on merged-/usr systems `/bin`, `/sbin` and `/lib` are symlinks, so
  name `/usr/bin/...`. Denylist: `/etc/kubernetes/pki/`, kubeconfigs in
  `/etc/kubernetes/*.conf` and `/var/lib/kubelet/kubeconfig`,
  `/var/lib/kubelet/pki/`, `/etc/shadow*`, `/etc/gshadow*`, `/etc/sudoers*`,
  `/root/`, any `.ssh/` directory, `/etc/ssh/*_key*`, `/proc/`, `/sys/`,
  `/dev/`, `/run/secrets/`, `/var/lib/breakglass-hotfix/` and Breakglass and
  Kyverno state.
- **replace** needs `beforeSHA256` (accepted current hashes) and `afterSHA256`;
  inline content must hash to `afterSHA256`.
- **sed** accepts only single-line `s<d>regex<d>replacement<d>` commands with
  flags `g`, `I` and a number. The executor runs `sed --sandbox`, which also
  rejects `e`, `r` and `w`.
- **diff** accepts exactly one `---`/`+++` header pair followed by hunks; it is
  applied to this one file only, without fuzz or offset. The file must end
  with a newline (no `\ No newline at end of file` marker).
- For `sed` and `diff`, the plan computes the result per node. The approver of
  the apply stage reviews the per-node diff and hashes. Apply refuses a node
  whose pre-image hash changed since the plan, and the result hash must equal
  the planned hash.
- **Nodes.** Exactly one of `names` or a non-empty `selector`; select all
  nodes explicitly with an `Exists` expression.
- **Rollout.** `canary` (default): `canaryNodes` (default 1), then batches of
  `maxUnavailable` (a count, or 1..100%; default 10%, capped by
  `maxBatchPercent`), each followed by at least `soakSeconds` (default and
  minimum: the template `minSoakSeconds`, or 60 s if unset). `all-at-once` needs `allowAllAtOnce` in the template
  and an `allAtOnceReason` of 30..700 characters, and is never allowed for
  `static-pod-image`. Control-plane nodes always run one at a time.
- **Lifetime.** At most the template `maxLifetime` (itself at most 30 days);
  default 14 days or the template maximum, whichever is shorter.
- **Plan size.** A plan stores each distinct diff once (one per pre-image) and
  must stay below 512 KiB.
- `fixedIn` (1..256 characters) names the release that will contain the fix.

## How the controller runs a stage

- **Executors.** Each node gets exactly one executor Pod (the `hotfix-action`
  command of the node-maintenance image) inside a Job envelope with
  `managedBy: breakglass.t-caas.telekom.com/hotfix`, in the
  `breakglass-node-maintenance` namespace. The attempt is persisted before the
  Pod is created; a missing Pod is reported as `unknown` and never recreated.
  The node's name and UID, the session approval and the template are checked
  again immediately before each Pod is created.
- **Pod shapes.** `node-file` without restarts runs unprivileged with only
  `CHOWN`, `FOWNER` and `DAC_OVERRIDE`, the target directory and
  `/var/lib/breakglass-hotfix` mounted (read-only for a plan), plus
  `/etc/ssl/certs` read-only for a `url` source. Every other payload runs
  privileged with host PID and network and uses host tools through `nsenter`.
  A mutating executor is never deleted while it runs: on a stop, a
  termination or a deletion of the session the controller waits until it
  ends at its own deadline, records its result and only then removes it. Its
  grace period equals its deadline as a second guard. Read-only plan
  executors are stopped at once.
- **Locks.** Apply and rollback hold one `breakglass-hotfix` Lease per cluster.
  Each executor holds the per-node Lease that node maintenance also uses. No
  Lease is ever taken over.
- **Stops.** A failed node, a failed health gate, a suspended or removed
  template, a replaced node, an executor Pod rejected by admission, an
  expired session or a terminated session stop the stage for good: the reason is kept in `status.hotfix.reason`, no further
  executor starts, and started executors are observed to the end (a stopped
  plan reports its unfinished nodes as `interrupted`). Only the
  revocation stages (`rollback`, `reconfirm`, `close`) run with a suspended
  template.
- **Batches.** The plan lays out worker nodes as canary, then
  `maxUnavailable` batches (or one batch for `all-at-once`), and every
  control-plane node in a batch of its own. A plan runs its read-only
  executors 20 nodes at a time.
- **Health gate.** After a batch, every node changed so far must be Ready with
  no pressure or network condition; for a control-plane node its
  `tier=control-plane` Pods must be Ready and the API server `/readyz` must
  answer. The gate must pass within 5 minutes, then the soak time runs before
  the next batch. A failed node or gate stops the rollout: no further batch
  starts and the session fails.
- **Audit.** The stage intent, every node intent and result, and the stage
  result are emitted synchronously with severity Critical. Without a durable
  audit sink nothing runs.
- **Admission.** Templates can declare per-session admission exceptions as
  required `auxiliaryResources` (create before, delete after, fail closed);
  they exist only while the session runs.
- **Record.** Apply creates the `HotfixRecord` before the first node changes
  and records every node result. Applied nodes get the annotation
  `hotfix.breakglass.t-caas.telekom.com/<hash of the record name>`; rollback
  removes it and closes the record when no node carries the hotfix.

Target cluster permissions for the controller's ClusterConfig identity:
get/list Nodes and patch Node annotations; get the
`breakglass-node-maintenance` namespace; create/get/delete Jobs, Pods and
Leases in it; get/list Pods in `kube-system`; the non-resource URL `/readyz`.

## Revoking a hotfix

Everything a hotfix does can be revoked at any time:

- **Stop new hotfixes.** Set `spec.hotfix.suspended: true` on the template (or
  remove the template). New `plan` and `apply` sessions are rejected, and a
  running apply starts no further batch. `rollback`, `reconfirm` and `close`
  stay possible, so an active hotfix can always be revoked.
- **Stop a running rollout.** Terminate the apply session. Nodes whose
  executor already started finish within their deadline; no further batch
  starts. The `HotfixRecord` stays and shows which nodes carry the hotfix.
- **Revert an active hotfix.** Request a `rollback` session for the record.
- **Controller unavailable.** If the controller is stopped or disabled during
  a rollout, no further batch starts, because only the controller starts
  batches. Running executors stop at their deadline. The record stays and
  shows the state at the time of the last observation.

## HotfixRecord

`HotfixRecord` (short name `hfr`) is the durable drift record on the hub,
written only by the controller. Its spec holds the payload with sources and
digests, the plan hash, the node selection, `fixedIn`, `expiresAt` and the
four-eyes sessions. Its status holds the state of each node (`applied`,
`skipped`, `failed`, `rolledBack`, `uncovered`, `reverted`) and the conditions
`Active`, `Reverted`, `Uncovered`, `Expiring`, `Expired` and `Closed`.

Expiry raises a critical alert only; it never rolls back on its own. It ends
with a four-eyes `reconfirm`, `rollback` or `close`.

## Safety notes

- A `node-deb` hotfix is root code execution on every selected node. Pinning,
  the second-person plan review, the canary default, typed payloads, the path
  and service allowlists and the audit trail are the controls.
- Two colluding or compromised approvers, a typo-squatted registry or a
  poisoned URL can still roll out a malicious change. Mirror sources into the
  cluster's registry or repository by digest first.
- Restarting containerd or kubelet briefly affects workloads on the node.
  Restarting a host container such as `cra-vsr` interrupts the node's network.
