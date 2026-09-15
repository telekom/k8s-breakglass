<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Storage-diagnostics runbook

The digest-pinned Alpine base and exact `fio`/`ioping` versions are fixed
inputs. This Dockerfile does not run `apk upgrade` or add a separate
repository, so weekly rolling rebuilds do not silently refresh the inherited
package layer. Update the reviewed base digest or package pins when security
fixes are needed, then scan the exact built digest before publication.

## Choose the least-powerful operation

| Symptom | Start with | Escalate when |
| --- | --- | --- |
| Latency or I/O errors on an attached PVC | `mounted-volume --dry-run`, then a bounded real run approved by the data owner | You need to compare provisioning through a StorageClass |
| Suspected StorageClass performance regression | `performance` | The fixed default-fio profile cannot reproduce the issue |
| Snapshot or restore failure | `snapshot-restore` | A disposable CSI-capable acceptance cluster is available |
| Raw block claim will not attach | `block-volume` | A disposable raw-block-capable acceptance cluster is available |
| Need arbitrary Kubernetes inspection or custom fio | Existing audited escalation | Never add free-form command/image/RBAC input to this Job |

## Direct attached-volume workflow

1. Mount only the approved PVC at `/scratch` and a separate artifact volume at
   `/reports`; do not mount a host filesystem.
2. Run as UID/GID 65532 with `allowPrivilegeEscalation: false`, a read-only
   root filesystem, `RuntimeDefault` seccomp, and all capabilities dropped.
3. Run `storage-diagnostics mounted-volume --dry-run ...` and confirm the
   bounds. A real run writes a temporary file to the target filesystem.
4. Retrieve the private mode-0600 report through an authorized same-UID
   collector. Confirm no `.storage-debug-fio.*` or `.storage-report.*` remains.
5. Remove the DebugSession and verify the Pod, ServiceAccount, NetworkPolicy,
   and any PolicyException are absent.

## Controller-owned kubestr workflow

1. Create a fresh single-session namespace. Refuse reuse or name collisions.
2. Disable token automount on its `default` ServiceAccount. Create a separate
   runner ServiceAccount and operation-specific Role/ClusterRole bindings.
3. Apply default-deny network policy, then allow the runner only to the
   Kubernetes API and the storage-driver endpoints required by the operation.
4. Deploy a non-interactive Job (`allowExec: false`) from the signed immutable
   storage-debug digest. Inject that same digest as
   `STORAGE_DEBUG_WORKLOAD_IMAGE` and the namespace through the Downward API.
5. Use `plan` first if reviewing a new profile. Run one of `performance`,
   `snapshot-restore`, `snapshot-source-clone`, or `block-volume` with typed
   class selections. Never pass through arbitrary kubestr flags.
6. Record the selected operation, class names, image digest, session UID,
   result, and cleanup result in the audit event. Do not log raw volume data.
7. After completion, verify every `kubestr-*` Pod, PVC, ConfigMap, and
   VolumeSnapshot is absent. For `snapshot-source-clone`, also verify the
   temporary cloned VolumeSnapshotClass is absent. Then delete the entire
   session namespace using its UID precondition.

The default Kind proof covers only `performance`/`default-fio`. It cannot prove
CSI snapshot or raw-block behavior because its no-provisioner fixture has no
CSI driver. Do not report those operations as passed from the default job;
run the provider-specific acceptance workflow and retain its API results.

If kubestr exits non-zero or cleanup cannot be proven, treat the session as
failed and retain only bounded diagnostics. Do not delete similarly named
objects outside the dedicated namespace, and do not retry block-volume in a
shared namespace because v0.4.49 derives fixed names from the StorageClass.

See `README.md` for the exact operation/RBAC matrix, migration from the former
network-debug placement, the distinction between validator storage-matrix
smoke and kubestr fio/CSI/raw-block evidence, and the upstream kubestr
limitations that admission and controller cleanup must compensate for.

Built-in generic runbooks live under
`/usr/share/breakglass/runbooks/upstream/storage-diagnostics`. An optional
provider bundle may be mounted read-only, root-owned, and without `subPath` at
`/usr/share/breakglass/runbooks/internal`. Treat that bundle only as text to
read: never source or execute a script from it, and never let it replace the
built-in upstream directory.
