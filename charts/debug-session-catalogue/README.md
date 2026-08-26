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
| `workload` | enabled | Isolated workload diagnostics |
| `network` | enabled | Isolated DNS/network diagnostics |
| `storage` | enabled | Ephemeral storage inspection |
| `cluster-validation` | enabled | Isolated read-only validation checks |
| `dump-access` | disabled | Host-network packet capture |
| `network-repair` | disabled | Host-network network repair |
| `node-recovery` | disabled | Host-network/host-PID node recovery |

The last three profiles are elevated. Enable them only with an explicit
two-part opt-in, for example:

```yaml
profiles:
  dump-access:
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

## Interface report

See [`docs/debug-session-catalogue-interface.md`](../../docs/debug-session-catalogue-interface.md)
for the resource naming contract, profile/image contract, and integration
notes for adjacent image and controller work.
