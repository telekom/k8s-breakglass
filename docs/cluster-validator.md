<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Standalone cluster-validator image

The `cluster-validator` image is a small, read-only Kubernetes client for
producing a machine-readable readiness report. It is provider-neutral and can
be redistributed under the Apache-2.0 license. It does not contain or call an
internal T-CaaS validator, and it does not assume a particular namespace,
operator, CRD, CNI, cloud, or platform service.

## Report contract

Every run emits one JSON document with this stable shape:

```json
{
  "apiVersion": "cluster-validator.telekom.com/v1alpha1",
  "kind": "ClusterValidationReport",
  "mode": "one-time",
  "status": "ready",
  "checks": [
    {"name": "api-discovery", "status": "ready", "message": "Kubernetes API discovery succeeded"},
    {"name": "api-server", "status": "ready", "message": "Kubernetes v1.36.4"},
    {"name": "namespaces-healthy", "status": "ready", "message": "3 namespace(s) active"},
    {"name": "nodes-ready", "status": "ready", "message": "3 node(s) Ready"},
    {"name": "pods-ready", "status": "ready", "message": "12 active pod(s) Ready"}
  ]
}
```

`mode` is either `one-time` or `post-upgrade`; the same contract is used for
both modes so automation does not need mode-specific parsers. Check results
are sorted by `name`. Timestamps are omitted by default, making output
deterministic for a fixed cluster state. `--include-timestamp` adds the
optional RFC3339 `generatedAt` field for audit artifacts.

The process exits `0` when `status` is `ready`, `1` when a check reports
`not-ready`, and `2` for configuration, output, or usage errors. Consumers
must inspect both the exit code and `status` and must reject an unknown
`apiVersion`.

Built-in checks use only public Kubernetes APIs:

* API server version and API discovery are reachable;
* at least one node exists and every node reports `Ready=True`;
* no namespace is terminating; and
* every non-Succeeded pod is Running and reports `PodReady=True`. When the
  validator runs inside Kubernetes, it excludes only its exact current pod
  (matching both `metadata.name` and `metadata.namespace`) from this check.
  The two Downward API identity values are optional for standalone runs; if
  either is missing or does not match, no pod is excluded.

Pod checking can be disabled with `--skip-pods` where a read-only identity is
not allowed to list pods. This is an explicit trade-off and is recorded in
the invocation, not silently inferred by the image.

## Run the image

The image first tries in-cluster configuration, then a kubeconfig. Reports are
written to `/reports/{mode}.json` and also printed to stdout. Mount `/reports`
as a writable volume, or pass `--report -` to disable the file.
For safety, a report path supplied with `--report` or `VALIDATOR_REPORT_PATH`
must resolve below `/reports`; relative paths are resolved within that volume,
and traversal or symlink escapes are rejected. Report files are written with
owner-only permissions.

```bash
docker run --rm \
  -v "$PWD/reports:/reports" \
  -v "$KUBECONFIG:/kubeconfig:ro" \
  -e VALIDATOR_KUBECONFIG=/kubeconfig \
  "${VALIDATOR_IMAGE_REF:?set a verified image tag or digest}" \
  --mode one-time

docker run --rm \
  -v "$PWD/reports:/reports" \
  -v "$KUBECONFIG:/kubeconfig:ro" \
  -e VALIDATOR_KUBECONFIG=/kubeconfig \
  "${VALIDATOR_IMAGE_REF:?set a verified image tag or digest}" \
  --mode post-upgrade
```

Set `VALIDATOR_IMAGE_REF` to the exact release reference selected after
signature and SBOM verification; a digest reference is preferred.

Equivalent environment variables are `VALIDATOR_MODE`,
`VALIDATOR_REPORT_PATH`, `VALIDATOR_KUBECONFIG`, `VALIDATOR_CONTEXT`,
`VALIDATOR_TIMEOUT`, `VALIDATOR_INCLUDE_TIMESTAMP`, and
`VALIDATOR_SKIP_PODS`. CLI flags take precedence over environment variables.

The identity needs read access to `nodes`, `namespaces`, and `pods`, plus
discovery access. A minimal starting point is:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-validator
rules:
  - apiGroups: [""]
    resources: ["nodes", "namespaces", "pods"]
    verbs: ["get", "list"]
  - nonResourceURLs: ["/version", "/api", "/api/*", "/apis", "/apis/*"]
    verbs: ["get"]
```

Review this RBAC against the target cluster's discovery behavior. The image
does not request, create, patch, or delete any Kubernetes object.

For an in-cluster invocation, inject the validator pod identity using the
Kubernetes Downward API:

```yaml
env:
  - name: VALIDATOR_POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
  - name: VALIDATOR_POD_NAMESPACE
    valueFrom:
      fieldRef:
        fieldPath: metadata.namespace
```

## Use from a DebugSession

The same image can back a restricted `cluster-validation` DebugSession
profile. Configure a `DebugPodTemplate` with the validator as an
`initContainer`, a small hold-open container for the session workload, and
`automountServiceAccountToken: true`. Bind that pod to a dedicated
`cluster-validator` ServiceAccount with the read-only role above; do not reuse
the controller or node ServiceAccount. Use an exact signed image reference
(preferably a digest) and pass `--mode one-time --report -` so the result is
available in the pod log. The `DebugSessionTemplate` should set
`allowedPodOperations.logs: true` and keep `exec`, `attach`, and
`portForward` disabled unless the incident policy explicitly requires them.

For post-upgrade checks, run the standalone command after the upgrade rather
than restarting a long-lived workload. If a catalogue supplies the generic
`cluster-validation` intent, it must preserve these same ServiceAccount,
read-only RBAC, exact-image, and mode requirements.

## Real-cluster integration contract

Run `make test-validator-integration` on a Linux host with Docker, kind,
kubectl, jq, and Go. The harness builds
`utils/cluster-validator/Dockerfile`, creates a disposable pinned-node-image
kind cluster, runs the image as the restricted
ServiceAccount, and executes every built-in check in both `one-time` and
`post-upgrade` modes. It also runs the extension contract probe through the
same read-only facades. It also creates an unhealthy disposable pod to prove
the built image returns exit code `1` with a `not-ready` report. The contract
asserts sorted deterministic reports, the documented exit codes `1` for an
unhealthy cluster and `2` for an invalid mode, denied config-map mutation,
denied Secret access, no marker/token leakage into reports or logs, and
removal of all test RBAC and namespace resources before the cluster is
deleted.

The machine-readable intent and expected check/tool contract is kept in
[`hack/cluster-validator-integration.contract.json`](../hack/cluster-validator-integration.contract.json);
the executable harness is
[`hack/cluster-validator-integration.sh`](../hack/cluster-validator-integration.sh).
The harness proves the contract from reports, exit codes, and cluster
behavior emitted by the built image; it does not load the JSON file as a
pass/fail oracle.
The CI job is intentionally self-contained so it can be moved into a
consolidated utility-integration workflow without changing the contract.

## Extension point

Downstream users can build a thin wrapper binary and append checks implementing
the `clustervalidator.Check` interface, then pass them to
`clustervalidator.NewValidator`. Checks receive the narrow
`clustervalidator.ReadOnlyClient` facade, which exposes list operations only;
the public image never gives an extension a mutating client. Discovery is
similarly restricted to server-version and group discovery; the raw client-go
REST client is not exposed. An extension must return one of the contract
statuses (`ready` or `not-ready`) and must keep the name returned by `Name()`
stable. The public image ships no private plugin and will never infer
provider-specific checks. Keep extensions in a separately licensed image or
wrapper when redistributing.

## Multi-architecture, signing, and SBOM

`utils/cluster-validator/Dockerfile` is pinned to digest-addressed Go and distroless base
images and is designed for `linux/amd64` and `linux/arm64`:

```bash
make test-validator
make docker-build-validator-multiarch \
  VALIDATOR_IMG=ghcr.io/example/cluster-validator:v0.1.0
```

The local multi-architecture target writes `cluster-validator-multiarch.tar`
as an OCI archive and does not push it. This repository currently includes no
image-publication workflow and does not publish or sign a release image. A
downstream deployment pipeline must build from the reviewed
source, publish a digest-addressed manifest, attach BuildKit provenance and an
SPDX SBOM, and sign the resulting digest before deployment. Verify the exact
downstream digest with that pipeline's documented identity and issuer:

```bash
cosign verify ghcr.io/example/cluster-validator@sha256:<64-hex-digest> \
  --certificate-identity-regexp='<downstream-pipeline-identity>' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

The image labels include the source revision, report contract version, and
`spdx-json`/`sigstore-keyless` readiness markers for registries and scanners.
