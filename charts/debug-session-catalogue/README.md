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
  --version 0.1.0 \
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
| `network-diagnostics` | enabled | Isolated DNS/network diagnostics |
| `storage-diagnostics` | enabled | Ephemeral storage inspection |
| `cluster-validation` | enabled | Isolated read-only validation checks |
| `dump-access` | disabled | Host-network packet capture |
| `network-repair` | disabled | Host-network network repair |
| `node-recovery` | disabled | Host-network/host-PID node recovery |

The node-oriented profiles are elevated. Enable them only with an explicit
two-part opt-in, for example:

```yaml
profiles:
  - name: dump-access
    intent: dump-access
    enabled: true
    elevated: true
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

Images are an interface, not a dependency of this chart: each image should
provide the command in its profile's `command`/`args` values and should be
reviewed for the capabilities requested by that profile. The defaults are
deliberately neutral and do not claim to include specialized tools such as
`tcpdump` or `kubectl`.

### Adding profiles and upgrading from the map format

`profiles` is an ordered list so installations can add profiles without a
chart change. Every item needs a unique DNS-safe `name`, stable `intent`,
display metadata, `enabled`/`elevated`, a command and args, and either an
`imageKey` from `images` or a direct `image` reference. Optional `preset`,
capabilities, and narrow pod overrides (mounts, volumes, and node selectors)
are generic; restricted security invariants cannot be weakened by overrides.
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

The chart rejects map-shaped profiles, duplicate or invalid names, unresolved
image references, and enabled profiles that require elevation without an
explicit `elevated: true` opt-in.

## Interface report

See [`docs/debug-session-catalogue-interface.md`](../../docs/debug-session-catalogue-interface.md)
for the resource naming contract, profile/image contract, and integration
notes for adjacent image and controller work.
