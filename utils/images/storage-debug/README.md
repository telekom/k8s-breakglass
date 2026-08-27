<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Storage diagnostics utility image

`storage-debug` is the standalone image for the `storage-diagnostics` intent.
It combines two deliberately different execution boundaries:

| Operation | Purpose | Execution boundary | User-selectable input |
| --- | --- | --- | --- |
| `mounted-volume` | Bounded `fio` and `ioping` against an already attached filesystem | Direct, unprivileged Pod; no Kubernetes API access | Existing mount, 1–1024 MiB, 1–60 seconds, 1–20 probes |
| `performance` | Provision a disposable PVC and run kubestr's `default-fio` profile | Non-interactive Job with a controller-owned ServiceAccount | StorageClass and an allowlisted 4/8/16/32 GiB PVC size |
| `snapshot-restore` | Exercise CSI snapshot creation and restore where a provider supplies a snapshot-capable class | Non-interactive Job with controller-owned namespaced RBAC plus read-only class discovery | StorageClass and VolumeSnapshotClass; not covered by the default Kind proof |
| `snapshot-source-clone` | Exercise kubestr's duplicate-snapshot-from-source check where explicitly approved | Stronger escalation profile; additionally creates and deletes a temporary VolumeSnapshotClass | StorageClass and VolumeSnapshotClass; not covered by the default Kind proof |
| `block-volume` | Exercise raw block PVC attachment where a provider supplies a raw-block-capable class | Non-interactive Job with a controller-owned ServiceAccount | StorageClass; not covered by the default Kind proof |

The cluster operations use kubestr v0.4.49 built from verified commit
`01940ed37be9a0c7a70d80cd26c648eaa11e5174`. They intentionally expose only
the workflows above. The wrapper does not accept a command, container image,
namespace, node selector, custom fio file, test name, run-as UID, capability,
ServiceAccount, or RBAC object. `POD_NAMESPACE` comes from the Downward API and
`STORAGE_DEBUG_WORKLOAD_IMAGE` must be a provider-owned `image@sha256:digest`
reference. This keeps the upstream image generic while allowing every
deployment to use its own signed immutable publication.

## Mounted-volume usage

The default image command shows intent help. Run a bounded check against an
already attached filesystem with:

```sh
storage-diagnostics mounted-volume \
  --path /scratch --size-mb 16 --runtime-seconds 5 --ioping-count 5 \
  --output /reports/storage-report.txt
```

The mounted-volume operation runs as UID/GID 65532, needs no Linux capability,
and needs no network. It creates a private random scratch file, removes it on
all normal exit paths, refuses symlink traversal and existing report paths,
and emits a deterministic `storage-debug/v1` report. Use `--dry-run` for a
read-only volume. A real performance test writes to the selected filesystem;
obtain the data owner's approval before targeting production data.

## Cluster-operation usage

Cluster workflows are designed for a controller-rendered Job with
`allowExec: false`. For example:

```sh
storage-diagnostics performance --storage-class fast-csi --pvc-size 4Gi
```

Use `storage-diagnostics plan ...` to validate input and display the exact
bounded kubestr invocation without contacting Kubernetes. The provider must
inject these values, not expose them as free-form session input:

```text
POD_NAMESPACE=<dedicated session namespace>
STORAGE_DEBUG_WORKLOAD_IMAGE=registry.example/storage-debug@sha256:<64 hex>
```

The same immutable image is used for kubestr's child Pods. Do not use
kubestr's unpinned upstream default (`ghcr.io/kastenhq/kubestr:latest`). The
Job has a 600-second outer bound; kubestr v0.4.49 applies its own five-minute
operation context and performs its built-in cleanup.

The default Kind integration proves only `performance`/`default-fio` with a
disposable no-provisioner volume. Kind does not provide a CSI snapshot driver
or a raw-block StorageClass, so a green default proof does not prove
`snapshot-restore`, `snapshot-source-clone`, or `block-volume`. A provider must
run those operations on a disposable cluster with the relevant CSI classes and
must record successful API results, child Pod security, cleanup, and unrelated
sentinel preservation. The downstream validator's storage matrix may cover
StorageClass lifecycle and per-node smoke, but it does not replace kubestr's
fio IOPS/latency, CSI snapshot/restore, or raw-block/PVC evidence.

## Runbook layout

Generic documentation built into the image is rooted at
`/usr/share/breakglass/runbooks/upstream/storage-diagnostics`. A deployment may
mount an additional OCI image-volume bundle at exactly
`/usr/share/breakglass/runbooks/internal`. That optional mount must be
root-owned and read-only, must mount the whole volume without `subPath`, and is
documentation only. Neither this entrypoint nor a helper sources or executes
content from the internal bundle. Use `storage-diagnostics docs` to show both
locations and `storage-diagnostics runbook` to print only the built-in generic
runbook.

## Authorization and security boundary

The image does not install RBAC. A provider should create a dedicated
ServiceAccount per session and grant only the verbs needed by the selected
operation. `performance` needs read-only access to its Namespace, selected
StorageClass, Nodes, and bound PV for event diagnosis, plus
create/get/list/watch/delete for Pods, PVCs, and
ConfigMaps in the dedicated namespace and `create` on `pods/exec`.
`snapshot-restore` additionally needs namespaced VolumeSnapshot operations and
read-only VolumeSnapshotClass discovery. `snapshot-source-clone` is the only
operation that needs create/delete on VolumeSnapshotClasses and must stay
behind the stronger escalation. `block-volume` needs the Pod/PVC subset.

These cluster operations must never be exposed through an interactive shell:
Kubernetes RBAC cannot constrain Pod creation by image, command, or security
context. Enforce the fixed Pod shape with admission policy, disable token
automount on the namespace's default ServiceAccount (kubestr creates child
Pods without selecting a ServiceAccount), and isolate the namespace with a
default-deny NetworkPolicy plus only the egress needed by the selected
storage driver and API flow. The runner itself needs Kubernetes API egress.

Kubestr v0.4.49 has important upstream limitations:

- Fio creates generated ConfigMaps, PVCs, and Pods and deletes the returned
  names, but it does not use UID delete preconditions.
- Block-mount names are derived from the StorageClass and can collide. Run it
  only in a fresh, controller-owned namespace with no other writers.
- Child Pods do not set a complete Restricted Pod Security context. Enforce
  the reviewed child shape with admission; do not weaken cluster policy by
  granting privileged mode or extra capabilities.
- Cleanup errors in several upstream paths are printed rather than returned.
  The controller must therefore verify resource absence and delete the whole
  session namespace on completion or expiry.

These are reasons for the non-interactive, single-session namespace contract;
they are not permission to grant broader access.

## Compatibility and migration

Kubestr was previously bundled into `network-debug`. That placement mixed
storage provisioning with packet diagnosis and could encourage a
network-privileged Pod to also receive storage RBAC. It is now available only
from `storage-debug`. Existing TDCI-11722 flows map as follows:

| Previous kubestr flow | New operation | Notes |
| --- | --- | --- |
| `kubestr fio` / performance diagnosis | `performance` | Fixed `default-fio`; no custom fio file, image, test, or node selector |
| `kubestr csicheck` snapshot and restore | `snapshot-restore` | Source-clone sub-check is skipped to avoid cluster-scoped mutation |
| Full `csicheck` including duplicate snapshot source | `snapshot-source-clone` | Separate stronger escalation because it mutates VolumeSnapshotClasses |
| `kubestr blockmount` | `block-volume` | Fixed 1 GiB PVC, 120-second Pod-ready wait, cleanup always enabled |
| Diagnostics on an already attached PVC | `mounted-volume` | No Kubernetes API or escalation required |
| Kubestr baseline cluster validator | Not included | Use the platform's cluster validator; this image is storage-only |
| `browse` and `file-restore` | Not exposed | They launch hard-coded mutable third-party images and interactive port forwards in v0.4.49 |

## Build and verification

The Alpine runtime and Go builder are pinned by immutable multi-architecture
digests. Fio, ioping, and kubestr versions are recorded in `versions.env` and
the final manifest is published with SPDX SBOM, provenance, and keyless Cosign
signatures.

Run the hermetic contract tests with `make -C utils/images/storage-debug test`.
The Linux CI integration additionally builds the real image, executes actual
fio/ioping against a disposable mounted volume, then runs kubestr fio in a
fresh Kind cluster with least-privilege RBAC, observes the actual child Pod,
and proves resource cleanup and unrelated sentinel preservation. Snapshot and
raw-block operations require a separate provider CSI acceptance run; they are
not silently treated as covered by the default Kind job.
