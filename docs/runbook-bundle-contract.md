<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# OCI runbook bundles

This document defines the portable contract for adding operator-owned runbooks
to a Breakglass debug utility pod. It is deliberately independent of a
registry, a platform distribution, or a particular utility image. A platform
may use it to publish a more detailed, internal runbook bundle without
changing the upstream utility image.

## Two documentation trees

Every utility image should ship generic documentation below
`/usr/share/breakglass/runbooks/upstream/<utility-or-intent>`. An approved platform may add an
OCI artifact as a Kubernetes [image volume][k8s-image-volume], mounted
read-only at `/usr/share/breakglass/runbooks/internal`.

The two trees are additive. The internal tree may provide more detailed
operational context, but it must not replace or override the upstream
description of commands, security boundaries, required capabilities, limits,
or cleanup. Utilities and entrypoints MUST NOT source, execute, or dynamically
load files from either tree. A missing internal tree therefore leaves the
generic workflow usable.

The mount is intentionally at the bundle root. Consumers MUST NOT use
`subPath`, user-provided mount paths, or a writable mount. The controller does
not copy the bundle into a writable volume and does not interpret its files as
configuration.

## `bundle.yaml`

The artifact root MUST contain `bundle.yaml` and `INDEX.md`. `bundle.yaml` is
metadata, not executable configuration. The following schema is normative;
unknown fields SHOULD be rejected by the publishing pipeline so typos cannot
silently change the contract:

The machine-readable form is [`runbook-bundle.schema.yaml`](./runbook-bundle.schema.yaml).
It is a JSON Schema document represented as YAML so it can be consumed by
standard JSON Schema tooling after YAML parsing.

```yaml
schema: breakglass.runbook/v1
intent: network-diagnostics
version: 2026.08.0
image:
  name: example/network-debug
  digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  architectures:
    - amd64
    - arm64
compatibility:
  kubernetes: ">=1.36.0"
  utility: network-debug
  utilityVersions: ["1.x"]
index:
  - id: network-overview
    title: Network overview
    path: runbooks/network-overview.md
    summary: Collect bounded, read-only network evidence.
    security: No host namespaces, credentials, or network mutation.
source:
  repository: https://example.invalid/operations/runbooks
  revision: 0123456789abcdef0123456789abcdef01234567
  generatedAt: "2026-08-01T12:00:00Z"
```

Required fields are `schema`, `intent`, `version`, `image.name`,
`image.digest`, `compatibility`, `index`, and `source`. `image.digest` MUST be
an OCI manifest digest (`sha256:` followed by exactly 64 hexadecimal digits),
not a tag or a layer digest. `version` is the bundle version and `source` is
the provenance of the content; neither grants access or changes the image
being run.

`intent` names the diagnostic outcome, for example `workload-diagnostics`,
`network-diagnostics`, `storage-diagnostics`, or
`diagnostic-artifact-collection`. It is an inventory key, not an RBAC role.
The same intent can have several bundle versions, but one selected
DebugSession must use one complete bundle and one utility image digest.

Each `index[].path` MUST be relative to the artifact root, use `/` as its
separator, and resolve to a regular UTF-8 Markdown file. Paths MUST NOT be
absolute, contain `..`, or point through symlinks. `INDEX.md` MUST link to all
entries and identify the intent, bundle version, utility image digest, source
revision, prerequisites, limits, evidence, security boundary, failure modes,
and cleanup procedure. The source repository and revision are informational
provenance and must not be fetched at runtime.

Bundles contain documentation and data only. They MUST NOT contain scripts,
ELF or other binaries, credentials, tokens, private keys, certificates with
private material, setuid/setgid files, device nodes, sockets, or symlinks.
Publishing CI should inspect the assembled artifact, validate the schema and
paths, generate an SBOM and provenance attestation, and sign the immutable OCI
manifest. Admission policy should verify the signature and attestations before
allowing the reference in a debug workload.

## DebugPodTemplate usage

The upstream API already carries the Kubernetes `corev1.Volume` and
`VolumeMount` structures through `DebugPodTemplate`. An administrator-owned
template can use the image volume as follows (the digest below is illustrative
and must be replaced by the reviewed bundle digest):

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: network-diagnostics
spec:
  template:
    spec:
      containers:
        - name: debug
          image: example/network-debug@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          volumeMounts:
            - name: internal-runbooks
              mountPath: /usr/share/breakglass/runbooks/internal
              readOnly: true
      volumes:
        - name: internal-runbooks
          image:
            reference: example/runbooks/network-diagnostics@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
            pullPolicy: IfNotPresent
```

The template owner, not the session requester, chooses the reference, volume
name, and mount path. A platform may generate this part of the template from
its own profile catalogue, but user variables MUST NOT control any of these
values. The image reference must be allowlisted, digest-pinned, signed, and
available to the target nodes using the normal image-pull-secret mechanism.

`IfNotPresent` is appropriate for an immutable digest and allows nodes to use
their cached copy. `Always` is also valid when the platform accepts registry
availability as a startup dependency. `Never` and mutable tags are not valid
for a production runbook bundle. The volume is read-only by Kubernetes;
callers must still use a read-only `volumeMount` and a read-only security
context. `AlwaysPullImages` applies to image volumes too.

Image-volume support depends on the cluster version and components:

| Kubernetes version | Required platform decision |
| --- | --- |
| Before 1.31 | Unsupported; omit the optional bundle. |
| 1.31–1.34 | Enable the `ImageVolume` feature gate on the API server and every eligible kubelet, and prove CRI support before selecting the bundle. |
| 1.35 | The beta feature is enabled by default; still prove the actual kubelet/runtime path. |
| 1.36 and later | The API is GA and always enabled; CRI support and registry access remain prerequisites. |

`subPath` is intentionally excluded even where the cluster version supports
it. Do not depend on image-volume digest reporting in Pod status; that is a
separate feature and the immutable reference in the administrator-owned
template remains the source of truth.

Image volumes are resolved by the target kubelet and runtime, not by the
Breakglass controller. The target cluster must support the ImageVolume API,
its kubelet and CRI must support image volumes, and registry credentials and
egress must be configured. The controller or platform integration MUST fail
closed when the capability is explicitly required: it must not silently omit
the internal bundle or replace it with an init-container copy. Clusters where
the capability is unavailable may run the built-in upstream documentation
only, if the selected profile declares the internal bundle optional.

The Kubernetes image-volume cache can remain on a node after a Pod is deleted.
Session cleanup deletes the Pod and its owned resources; it does not promise
node cache eviction. Consequently bundles must never contain secrets or
incident evidence. Image-volume mounts cannot currently be made `noexec`, so
publishers must reject executable modes and utility images must never execute
bundle content. Pull failures surface as Pod startup failures and are
handled as an unmet prerequisite, not as a successful run with reduced docs.

## Review and test requirements

The publishing and platform pipelines should prove behavior, not just inspect
YAML strings:

1. Build the bundle as an OCI artifact, inspect its manifest digest, verify its
   signature, SBOM, provenance, schema, paths, file modes, and absence of
   executable or secret material. Do not assume that an admission rule which
   verifies container images also examines `volumes[*].image.reference`;
   release or admission CI must prove that coverage before relying on it.
2. Render the administrator-owned DebugPodTemplate and create it in a cluster
   with image-volume support. Start a disposable debug Pod using a local
   registry fixture and verify that `bundle.yaml`, `INDEX.md`, and an indexed
   document are readable by the utility's runtime UID.
3. Verify the mount is read-only by attempting a write and checking the
   operation is rejected. Verify the utility still runs its built-in command
   when no internal volume is selected.
4. Delete the DebugSession and verify the Pod and session-owned resources are
   gone. Record separately that node-local image cache eviction is outside the
   session cleanup contract.
5. Exercise negative cases: tag references, unapproved registries, missing
   digests, invalid paths, duplicate index IDs, unsupported cluster
   capability, failed pulls, and signature/provenance failures must all fail
   closed for a required bundle.

The Breakglass controller does not verify OCI signatures itself and does not
claim support for image volumes on clusters whose Kubernetes components lack
the feature. Those checks belong to the platform admission and release
pipeline, while this document defines the interface they must implement.

[k8s-image-volume]: https://kubernetes.io/docs/concepts/storage/volumes/#image
