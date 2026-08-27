<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Debug session catalogue interface report

This report records the file and value interfaces introduced by TCAAS-1620 so
the catalogue can be coordinated with image, controller, and release work.

## Resources

The `charts/debug-session-catalogue` chart renders one cluster-scoped
`DebugPodTemplate` and one cluster-scoped `DebugSessionTemplate` per enabled
profile. Both names are deterministic:

```text
<release fullname>-<profile name>
```

The session template's `podTemplateRef.name` is the matching pod template name.
The shipped intent names, in list order, are `workload-diagnostics`,
`network-diagnostics`, `storage-diagnostics`, `dump-access`, `network-repair`,
`node-recovery`, and `cluster-validation`. Profile names are DNS-safe, unique
list item names and may be extended without chart changes; these intent names
remain stable across deployment values.

Bounded report profiles use `workloadType: Job`; this is important because the
controller normalizes Deployments and DaemonSets to `restartPolicy: Always`.
Interactive profiles may use `Deployment` and must keep their process alive.

## Access and targets

`requesters.groups/users`, `approvers.groups/users`, and
`targets.clusters/clusterSelector` are copied into every session template.
They default to empty lists. This is intentional: installation alone grants no
request, approval, or cluster access. The chart does not infer identities from
the release namespace or environment.

`targetNamespace` is copied to `spec.targetNamespace` and
`spec.namespaceConstraints.defaultNamespace`; user-selected namespaces and
namespace creation are disabled. Administrators must create and authorize that
namespace separately.

## Security contract

Restricted profiles use a non-root pod, read-only root filesystem,
RuntimeDefault seccomp, dropped capabilities, no service-account token,
disabled service links, bounded CPU/memory, closed failure mode, mandatory
request reasons, one-hour maximum duration, no renewal, and only exec/log
operations by default. Elevated profiles are absent from the rendered output
unless `enabled: true`, and the chart requires a second explicit `elevated: true`
setting. Only an explicit `preset: elevated-node` may use host namespaces or
sensitive hostPath/projected service-account-token volume overrides.

The `cluster-validation` profile remains restricted by default. API access is
an explicit paired opt-in: set a constrained `serviceAccountName` together
with `automountServiceAccountToken: true`; the chart does not create the
ServiceAccount or grant its read-only RBAC.

The controller re-validates this boundary when a session is activated. A
restricted pod must retain non-root execution, read-only root storage,
`allowPrivilegeEscalation: false`, `drop: [ALL]`, and a confined
`RuntimeDefault` or named `Localhost` seccomp profile; explicit root user/group
overrides, `envFrom`, and external environment values are rejected. Service-
account token sources are rejected except for the explicit, dedicated
`cluster-validation` identity contract. If a restricted template uses
multi-document YAML, the
only additional resource permitted is a fixed-name, namespaceless `core/v1`
`ConfigMap`, which the controller places in the session target namespace.
Cluster-scoped, namespaced-outside-target, workload, RBAC, network, storage,
and identity resources are rejected before anything is applied.

The same revalidation covers the Kubernetes Restricted pod-security surfaces
for regular, init, and ephemeral containers: host ports, unconfined or
malformed AppArmor, unsafe SELinux user/role/type settings, unsafe sysctls,
and HTTP host fields in probes or lifecycle hooks are denied. Legacy AppArmor
annotation keys are denied after all template, binding, session, and rendered
pod annotations have been merged, so an annotation source cannot bypass the
boundary.

Additional resources use create-first semantics and carry the session UID
identity. A fixed-name collision with an existing tenant object fails without
mutation. During cleanup, a replacement with a different session identity is
left untouched; a UID precondition protects deletion of an object still owned
by the session. During upgrades, resources created before the UID marker was
introduced remain removable only when both legacy session name and
`namespace/name` source-session markers match the terminating session; partial
or mismatched legacy markers are retained as a safety boundary.

Node maintenance profiles expose constrained per-session variables for an exact
target node, interface, evidence directory, confirmation token, and (for repair)
an allowlisted action. They are scheduled to the selected node, mount an
ephemeral `/evidence` directory, and disable `exec`; operation logs are the
supported output channel. The chart does not create RBAC. Cluster administrators must review controller
and target-cluster permissions before enabling any elevated profile.

## Image contract

Each profile selects `images.<profile imageKey>` or supplies a direct `image`
reference and runs its `command`/`args`. Images are configurable and should be
pinned by digest in production. The storage and dump mounts match the
`/scratch`, `/reports`, `/input`, and `/output` paths consumed by their images.
The elevated network, dump, repair, and recovery profiles are disabled by
default and must not be treated as shipping node tooling until explicitly
approved.

Profile items are concise: shared authorization, lifecycle, audit, image
resolution, workload wiring, pod hardening, and resource defaults are named
Helm helpers. Generic `preset` classes (restricted, elevated, elevated-node)
provide extension points without hard-coding platform or tenant profile names.

## OCI and release integration

The chart is packaged as `debug-session-catalogue-<version>.tgz` and is
intended for the OCI repository:

```text
oci://ghcr.io/telekom/k8s-breakglass/charts/debug-session-catalogue
```

Release automation should stamp `appVersion` with the release tag and publish
the chart independently from controller images. A chart package contains only
CR templates and values; no image is bundled.
