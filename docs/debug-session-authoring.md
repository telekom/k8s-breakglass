<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# DebugSession authoring guide

This guide is for platform administrators who publish a safe, reusable
`DebugSessionTemplate`. It describes the upstream CRDs and the five utility
images in this repository. It is deliberately provider-neutral: cluster
admission, image publication, storage classes, and any organization-specific
profiles remain deployment responsibilities.

## Start with a reviewed template

There are two administrator-authored objects:

* `DebugPodTemplate` contains the pod shape for `workload` and `hybrid` modes.
* `DebugSessionTemplate` selects that pod, controls mode, access, duration,
  scheduling, allowed pod operations, and optional auxiliary resources.

Use a digest-pinned image from the [utility image catalogue](./README.md#debug-utility-images).
Do not put an image, command, node name, mount, capability, or RBAC object in
an end-user request or in an `extraDeployVariables` value. Those are template
and provider policy. `extraDeployVariables` is useful for bounded, non-security
parameters such as a report size or a predeclared scheduling option; it is not
an authorization boundary.

The upstream API exposes kubectl-debug operation fields for compatibility. The
upstream controller validates session state and the template's namespace/image
rules, but the API is not a substitute for provider admission. A deployment
that exposes those operations must select the image, command, security
context, target, and output path from an approved profile before sending the
request. This guide therefore omits free-form operation request bodies.

### Minimal workload template

The `template.spec` shape below is the current CRD shape; older `podSpec`
examples are obsolete. Resolve the placeholder digest to the release digest
that your registry and signature policy approve.

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: workload-diagnostics
spec:
  displayName: "Workload diagnostics"
  description: "Read-only, bounded diagnostics from a session pod"
  template:
    spec:
      automountServiceAccountToken: false
      enableServiceLinks: false
      restartPolicy: Never
      containers:
        - name: diagnostics
          image: ghcr.io/telekom/k8s-breakglass/utils/workload-debug@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          imagePullPolicy: IfNotPresent
          resources:
            requests:
              cpu: 10m
              memory: 32Mi
            limits:
              cpu: 250m
              memory: 256Mi
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
            seccompProfile:
              type: RuntimeDefault
```

The utility's image entrypoint supplies its fixed default command. If a
provider needs a different command, it belongs in a separately reviewed
administrator template and admission profile; it must not be request data.

Pair the pod template with a session template. The `targetNamespace` must be
pre-created unless the deployment deliberately grants the template namespace
creation capability. Keep `failMode: closed` for incident tooling.

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: workload-diagnostics
spec:
  displayName: "Workload diagnostics"
  mode: workload
  podTemplateRef:
    name: workload-diagnostics
  workloadType: Deployment
  replicas: 1
  targetNamespace: breakglass-debug
  allowed:
    groups: [sre]
    clusters: [production]
  approvers:
    groups: [sre-leads]
  constraints:
    maxDuration: 2h
    defaultDuration: 30m
  allowedPodOperations:
    exec: true
    attach: false
    logs: true
    portForward: false
```

Use a `DebugSessionClusterBinding` when the same template must be delegated
to selected clusters or namespaces. A binding can narrow access and required
auxiliary categories; it must not weaken the template's mandatory constraints.
See [cluster bindings](./debug-session-cluster-binding.md).

## Standard and advanced intent modes

The image is not the authorization policy. The following matrix describes the
upstream utility contracts and the minimum provider controls. An entry marked
provider-dependent is not a claim that the default Kind proof implements it.

| Intent and image | Standard mode | Advanced mode or extension | Security and cleanup boundary |
| --- | --- | --- | --- |
| `workload-diagnostics` — [`workload-debug`](../utils/workload-debug/README.md) | Non-root pod; bounded DNS, TLS, HTTP(S), read-only Kubernetes API, and report helpers. | No upstream advanced profile. A provider may publish a separately reviewed template for additional read-only endpoints. | No capabilities; token only when the selected read-only API check needs it; default-deny egress where possible. Remove the session pod and any provider-created token/volume at termination or expiry. |
| `network-diagnostics` — [`network-debug`](../utils/network-debug/README.md) | Pod-network diagnostics and bounded `tcpdump` capture with the image's fixed limits. | Host-network/host-PID `pwru` tracing, or controller-mediated selected-pod capture. These require separate approval and Linux prerequisites; `pwru` is never a privileged fallback. | Grant only the required network capabilities. Delete capture pods and private evidence on completion; verify the ephemeral container and target pod are unchanged except for the approved injection. |
| `storage-diagnostics` — [`storage-debug`](../utils/images/storage-debug/README.md) | `mounted-volume` against an already attached, approved PVC; no Kubernetes API. | Controller-owned non-interactive `performance`, `snapshot-restore`, `snapshot-source-clone`, or `block-volume`. CSI/raw-block provider acceptance is required and is not covered by the default Kind proof. | Use a dedicated session namespace, operation-specific SA/RBAC, default-deny egress, and `allowExec: false`. Delete generated Pods, PVCs, ConfigMaps, snapshots, and any temporary cluster-scoped object; preserve unrelated sentinels. |
| `node-maintenance` — [`node-maintenance`](../utils/node-maintenance/README.md) | Read-only `node-recovery` evidence for one exact interface and node. | Independently approved `network-repair` tuple or `kexec-recovery-validate`. The latter validates files and never loads a kernel; boot, rollback, and health policy are provider-owned. | Use one controller-owned workload per node, the fixed evidence volume, and the image's operation/recording/approval bindings. Remove only operation-owned evidence and stale temporary files after retention; never broaden host mounts. |
| `diagnostic-artifact-collection` — [`diagnostic-artifact-collector`](../utils/images/diagnostic-artifact-collector/README.md) | `system-summary.v1`, offline and non-root, with bounded output. | `crashdump-collection.v1`, which needs a read-only coredump host mount and a narrowly approved node placement. Binary dumps are sensitive and are not generically redacted. | The collector is offline; only the controller-issued uploader endpoint may receive an archive. Delete Job, Secret, capability, and stored artifact through the controller's tracked cleanup, and verify no private staging remains. |

The upstream catalogue does not define HBN, HBR, CRA, or SR-IOV profiles. A
downstream platform may add those as extension examples by binding a reviewed
image, node label, network attachment, or admission policy to a template. Such
extensions need their own RBAC, security review, behavior test, digest and
cleanup evidence; they are not implied by the upstream intent names.

## Ephemeral identity and RBAC

Use a per-session ServiceAccount when a utility must call the Kubernetes API or
when the target platform uses impersonation. Create it in the target session
namespace, disable automount on unrelated pods, and grant only the operation's
verbs. A namespaced `Role` is preferable. A `ClusterRole` may be used as a
reusable rule set, but bind it with a namespaced `RoleBinding` and only when
the provider explicitly permits the required cluster-scoped reads.

The following is an authoring pattern, not a built-in profile. The controller
renders session values; the provider must independently validate the rendered
objects and the exact resource allowlist.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: "debug-{{ .session.name }}"
  namespace: "{{ .target.namespace }}"
  labels:
    breakglass.t-caas.telekom.com/session: "{{ .session.name }}"
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: "debug-{{ .session.name }}-read"
rules:
  - apiGroups: [""]
    resources: [pods, pods/log]
    verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: "debug-{{ .session.name }}-read"
  namespace: "{{ .target.namespace }}"
subjects:
  - kind: ServiceAccount
    name: "debug-{{ .session.name }}"
    namespace: "{{ .target.namespace }}"
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: "debug-{{ .session.name }}-read"
```

If the utility needs a token, set `automountServiceAccountToken: true` only on
that named debug pod and keep the token out of command arguments and evidence.
The upstream `DebugPodTemplate` defaults token automount to false. A provider
must also ensure that the controller's spoke-cluster identity can create and
delete the selected resources; the hub's generated RBAC does not magically
grant permissions in a spoke.

Do not put a user-supplied `ClusterRole`, `RoleBinding`, ServiceAccount name,
or RBAC rule set into `extraDeployVariables`. If auxiliary resources are enabled,
allowlist their kinds, namespaces, labels, and verbs before applying them.
`failurePolicy: fail`, `createBefore: true`, and `deleteAfter: true` are the
safe defaults for required identity and network controls.

## Network isolation and Kyverno exceptions

Create a default-deny `NetworkPolicy` before the debug workload. Add only DNS,
the Kubernetes API, the controller's artifact endpoint, and a storage-driver
endpoint required by the selected intent. Select pods using controller-owned
session labels, not a user-provided selector. Keep host-network and host-PID
profiles separate from ordinary workload diagnostics.

The upstream repository does not create or own a Kyverno `PolicyException`.
If a downstream admission policy requires one for a reviewed host-path,
capability, or image-volume profile, the downstream controller must create a
short-lived exception for the exact session namespace and labels, scope it to
the named policy rules, and remove it before the session is considered clean.
Never accept a raw `PolicyException` body from a requester and never use an
exception to make an arbitrary image, command, mount, or node legal.

## Ownership, expiry, and cleanup

The hub `DebugSession` and resources in a spoke cluster cannot use a Kubernetes
ownerReference across clusters. The upstream controller records created
resources in `status.deployedResources`,
`status.auxiliaryResourceStatuses`, and
`status.podTemplateResourceStatuses`, then explicitly deletes them when a
session reaches `Expired`, `Terminated`, or `Failed`. Auxiliary resources with
`deleteAfter: false` are intentionally retained. Cleanup errors remain in
status and are retried; verify the status lists and the target cluster rather
than relying on a successful delete request alone.

At `status.expiresAt`, authorization is no longer valid even if cleanup has
not yet completed. A provider should therefore stop new operations at expiry,
retain enough session/status evidence to finish cleanup, and use a bounded
reconciliation retry. The upstream controller does not install a
DebugSession finalizer. Deleting the hub object directly can therefore remove
the controller's resource inventory before spoke cleanup; providers that need
deletion-triggered cleanup must add and test their own finalizer/retention
controller, or require explicit termination followed by cleanup verification.

Cleanup checklist:

1. Terminate or allow expiry; do not delete the session object first.
2. Confirm `status.state` is terminal and inspect all tracked resource lists.
3. Delete and strongly verify absence of workloads, auxiliary resources,
   generated PVCs/ConfigMaps, ephemeral containers, and evidence objects.
4. Remove any provider-owned ServiceAccount, Role/ClusterRole binding,
   NetworkPolicy, and narrowly scoped Kyverno exception.
5. Confirm utility-specific private staging and remote artifact state are gone
   or retained under an explicit incident retention policy.

## OCI runbook extension

The [OCI runbook bundle contract](./runbook-bundle-contract.md) is the upstream
extension point for additive operator documentation. Mount one immutable,
signature-verified image volume read-only at
`/usr/share/breakglass/runbooks/internal`, without `subPath`; keep the built-in
runbooks at `/usr/share/breakglass/runbooks/upstream` authoritative. The image
must treat the mounted content as text: it must not source, execute, or use it
to change commands, images, mounts, RBAC, or cleanup. Providers must verify
the bundle manifest, compatibility, ownership, and absence of secrets before
the session starts, and remove the volume with the session.

The upstream runbook contract does not define an internal platform's incident
taxonomy or release process. Downstream documentation may add those details in
the mounted bundle while retaining the upstream-versus-downstream boundary.

## Evidence and review

Use the utility README and runbook linked in the catalogue for exact commands,
limits, and behavior tests. A green presence check for an executable, runbook,
or image tag is not acceptance evidence. For each enabled mode, retain a
behavioral proof showing the real image, security context, target isolation,
bounded operation, authorization decision, cleanup, and preservation of an
unrelated sentinel. Provider-dependent CSI, host-kernel, recovery, and
admission behavior needs a feature-capable disposable cluster or host; do not
report it as covered by a static manifest or default Kind smoke test.
