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
The shipped intent names are `workload-diagnostics`, `network-diagnostics`,
`storage-diagnostics`, `dump-access`, `network-repair`, `node-recovery`, and
`cluster-validation`. Profile names are DNS-safe, unique list item names and
may be extended without chart changes; intent names remain stable across
platform and tenant values.

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

All profiles use a non-root pod, RuntimeDefault seccomp, dropped capabilities,
no service-account token, disabled service links, bounded CPU/memory, closed
failure mode, mandatory request reasons, one-hour maximum duration, no renewal,
and only exec/log operations by default. Elevated profiles are absent from the
rendered output unless `enabled: true`, and the chart requires a second explicit
`elevated: true` setting. Only then can host namespaces, privileged mode, or
additional capabilities be rendered.

The chart does not create RBAC. Cluster administrators must review controller
and target-cluster permissions before enabling any elevated profile.

## Image contract

Each profile selects `images.<profile imageKey>` or supplies a direct `image`
reference and runs its `command`/`args`. Images are configurable and should be
pinned by digest in production. The chart's neutral `busybox:1.36.1` defaults
are intentionally minimal; specialized image work may replace them without
changing CR names or the catalogue interface. In particular, the default
dump, repair, and recovery profiles are disabled and must not be treated as
shipping packet-capture or node-recovery tooling.

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
