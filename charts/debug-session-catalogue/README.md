# Debug Session Catalogue Helm Chart

This standalone chart publishes a neutral catalogue of reusable
`DebugPodTemplate` and `DebugSessionTemplate` resources for
[k8s-breakglass](https://github.com/telekom/k8s-breakglass). It contains no
tenant, platform, identity-provider, or cluster names and does not create
namespaces or RBAC. The target namespace must be pre-created and authorized by
the cluster administrator.

## Install

Install the CRDs and controller first, then configure access and targets:

```yaml
requesters:
  groups: [sre]
  users: []
approvers:
  groups: [incident-commanders]
  users: []
targets:
  clusters: [cluster-a]
targetNamespace: breakglass-debug
```

```bash
helm install debug-catalogue \
  oci://ghcr.io/telekom/k8s-breakglass/charts/debug-session-catalogue \
  --version 0.2.0 \
  -f access-values.yaml
```

The default empty requester, approver, and target lists intentionally make the
catalogue unusable until an administrator supplies local policy. This prevents
a chart installation from accidentally granting access to every user or
cluster. `failMode: closed`, mandatory request reasons, one-hour maximum
duration, no renewal, no attach/port-forward, no service-account token, and
non-root isolated pods are also defaults.

## Profiles

The chart includes these profiles:

| Profile | Default | Purpose |
| --- | --- | --- |
| `workload-diagnostics` | enabled | Isolated workload diagnostics |
| `network-diagnostics` | disabled | Elevated node-network diagnostics |
| `storage-diagnostics` | enabled | Ephemeral storage inspection |
| `dump-access` | disabled | Inspect and copy approved existing dump files |
| `network-repair` | disabled | Host-network network repair |
| `node-recovery` | disabled | Host-network/host-PID node recovery |
| `cluster-validation` | disabled | Isolated read-only validation checks (explicit RBAC opt-in) |

Bounded reports use `workloadType: Job`, so a completed diagnostic is retained
for inspection and is not restarted by the controller's Deployment/DaemonSet
normalization. `dump-access` is also a bounded Job: it runs one configured
`dump-reader copy` operation, disables `exec`, and uses a 1 GiB output volume.
The source path and source volume are deployment-supplied; the generic chart
does not silently select a node path or artifact name. It never starts an
interactive or host-network shell.

The node-oriented profiles are elevated. Enable them only with an explicit
two-part opt-in, including host networking only for profiles that need it,
for example:

```yaml
profiles:
  - name: dump-access
    intent: dump-access
    enabled: true
    elevated: false
    hostNetwork: false
```

The chart fails closed when an elevated profile is enabled without
`elevated: true`. Replace the default public utility images with organization-
approved images, ideally by digest:

```yaml
images:
  dumpAccess:
    repository: registry.example.invalid/debug-tools
    tag: "2026.01"
    digest: sha256:...
```

Images are an interface, not a dependency of this chart: each image must
provide the command in its profile's `command`/`args` values and should be
reviewed for the capabilities requested by that profile. Restricted profiles
run as UID/GID 65532 with a read-only root filesystem and no added
capabilities. The network utility is therefore elevated and disabled by
default because its packet and node inspection tools require root/capability
access. Pin each image to its release digest in production.

The `storage-diagnostics` profile mounts the image's `/scratch`, `/reports`,
and writable `/tmp` paths. The `dump-access` profile mounts the approved source
directory at `/input` read-only and a separate 1 GiB `emptyDir` at `/output`,
matching the dump-reader image contract. The source path is an explicit
administrator-controlled value beneath `/input` and must be paired with a
reviewed source volume:

```yaml
profiles:
  - name: dump-access
    enabled: true
    elevated: false
    hostNetwork: false
    sourcePath: /input/incident-123.dump
    pod:
      volumes:
        - name: input
          hostPath:
            path: /var/lib/approved-dumps/incident-123
            type: Directory
        - name: output
          emptyDir:
            sizeLimit: 1Gi
```

The administrator must constrain that host path and its retention separately;
the image still rejects symlinks and traversal. The dump profile does not
require `elevated-node`, host networking, host PID, or added capabilities; the
hostPath is exposed only through the read-only `/input` mount. All catalogue
containers retain a read-only root filesystem. Writable paths must be explicit bounded volumes
(for example `/output`, `/evidence`, or `/work`); the chart has no writable-root
opt-out. Restricted profiles accept only `emptyDir`, `configMap`, and
`downwardAPI` volumes; Secret, projected-token, PVC, and CSI sources require
explicit elevated node opt-in. The dump-access input is the sole exception:
its hostPath must be mounted read-only and is still an administrator-reviewed
source boundary.

`cluster-validation` does not receive a service-account token by default. To
run API checks, explicitly set both `serviceAccountName` and
`automountServiceAccountToken: true` on that profile, and bind the named
ServiceAccount to narrowly scoped read-only discovery, node, namespace, and
pod permissions. The chart does not create that ServiceAccount or its RBAC.

Platform-specific controls (SR-IOV, admission protections, NetworkPolicies,
Kyverno PolicyExceptions, node labels, and tenant/session policy) remain
downstream concerns. Consumers may add those controls through their normal
deployment overlay or Function configuration; this generic chart deliberately
does not name a platform, tenant, or policy engine.

### Adding profiles and upgrading from the map format

`profiles` is an ordered list so installations can add profiles without a
chart change. Every item needs a unique DNS-safe `name`, stable `intent`,
display metadata, `enabled`/`elevated`, a command and args, and either an
`imageKey` from `images` or a direct `image` reference. Optional `preset`,
capabilities, service-account opt-in, and narrow pod overrides (mounts, volumes,
and node selectors) are generic; restricted security invariants cannot be
weakened by overrides.
The list order is preserved in rendered output.

Versions before 0.2.0 accepted a map keyed by profile name. Convert each map
entry to an item and move its key into `name`; for example:

```yaml
# old
profiles:
  workload: {enabled: true, imageKey: workload}
# new
profiles:
  - name: workload-diagnostics
    intent: workload-diagnostics
    enabled: true
    elevated: false
    imageKey: workload
    displayName: Workload diagnostics
    description: Inspect a workload.
    command: ["sh"]
    args: []
```

For `network-repair` and `node-recovery`, the shipped profiles require the
per-session `targetNode`, `interface`, and exact confirmation variables. Repair
also requires an allowlisted `action`; the generated pod is scheduled to the
selected node and writes evidence beneath `/evidence`. The node-maintenance
profiles disable `exec`; use their fixed operation entrypoints and retrieve
logs/evidence after completion. Keep these variables bound to the approved
binding and scheduling policy.

The chart rejects map-shaped profiles, duplicate or invalid names, unresolved
image references, and enabled profiles that require elevation without an
explicit `elevated: true` opt-in.

## Interface report

See [`docs/debug-session-catalogue-interface.md`](../../docs/debug-session-catalogue-interface.md)
for the resource naming contract, profile/image contract, and integration
notes for adjacent image and controller work.
