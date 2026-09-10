# Diagnostic artifact E2E acceptance

The single-cluster API E2E lane must exercise the complete `system-summary.v1` and `crashdump-collection.v1`
paths: an API-created active DebugSession and ConnectionLease, collection against
an approved Pod, a controller-created collector Job, HTTPS upload, authenticated
download, and cleanup. The lane uses an immutable digest for the test collector
image and a test CA trust layer; it does not weaken production TLS or claim that
the release image has been published.

The test also checks outsider and replay denial, authorization after session
termination, and provider/object cleanup. Unit and envtest suites remain the
source of coverage for injected publication and CAS race failures.

The single-cluster CI job explicitly runs `e2e/fixtures/artifacts/setup.sh`,
then `go test -tags=e2e ./e2e/api -run '^TestDebugSessionArtifactCollectorE2E$'`.
Missing fixture configuration fails this named lane. Other E2E suites keep their
existing HTTP listener; a test-only TLS sidecar forwards to that listener.

The setup creates a fresh private test CA and signing Secret, builds the actual
collector/uploader from source, appends the CA to a test-only trust layer, and
imports its archive into every disposable Kind node. It tags each node's actual
containerd manifest digest and requires those digests to agree. Both generated
Job containers use that immutable reference. This proves the test image; it does
not publish or certify the release image.

A single-replica Recreate controller mounts a private RWO PVC. A test-only init
command calls `local.ProvisionSentinels`; production startup still fails closed
on unprovisioned storage. The test observes the real object files through its
administrator fixture, verifies removal after artifact finalization, and keeps a
second artifact readable while the first is deleted. The disposable Kind cluster
and its PVC are removed by the existing CI cluster teardown. Generated private
keys are never printed or attached to diagnostics.

## Activation and hard-expiry diagnostics

The separate hard-expiry lane exercises authorization expiry and API-mediated
ephemeral injection. Its failure bundle selects the deployed controller pods by
`app=breakglass` and captures bounded, redacted logs. DebugSession wait failures
report the last observed UID, resource version, state, message, expiry, and read
error before fixture cleanup removes the object.

`TestFreshKubectlDebugSessionActivatesWithRealAPI` runs the production reconciler
with quota admission, a persisted template, and a real connection Lease against
an envtest API server. Set `KUBEBUILDER_ASSETS` to run it. This is complementary
to the Kind lane; it does not reproduce manager-cache timing or spoke transport.
Completed ephemeral-operation replay records its existing reference once while
preserving the separate Active-only allowed-Pod update.

## Explicit backend and lifecycle matrix

The same named test runs separately with `E2E_ARTIFACT_BACKEND=local` and `s3`.
`select-s3.sh` replaces the local configuration with an explicit S3 configuration;
there is no automatic failover. Each backend runs both recipes through terminate,
expiry, and session deletion. Each case restarts the real controller before
reading the retained control artifact, then verifies provider and tracked Job/
Secret cleanup. Local object files must remain mode 0600 and UID/GID 65532; S3
inventory includes all versions and delete markers so hidden versions cannot
masquerade as successful cleanup.

The crashdump source is harmless synthetic text seeded only inside the disposable
Kind nodes at `/var/lib/systemd/coredump/core.artifact-kind-fixture`. Tests inspect
the admitted Pod's exact node, immutable image, read-only hostPath and mount,
host namespace/runtime fields, and the downloaded archive's synthetic payload.
Both recipes validate their manifest contract, stdout/stderr, and payload hashes.
No production source directory or credential is used.

The requester identity and groups used for API collection are impersonated for
actual forbidden create/patch/delete attempts against Jobs, Pods, Secrets and
NetworkPolicies carrying artifact labels in the execution namespace. Kyverno
PolicyException authorization is checked through SubjectAccessReview; this
upstream fixture does not install Kyverno and does not claim provider execution
or the downstream three-Function integration required by the SI acceptance gate.

## Disposable S3 dependency

MinIO's official distribution is source-only. CI builds the official security
release `RELEASE.2025-10-15T17-29-55Z`, commit
`9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a`, instead of using older registry images.
Source: <https://github.com/minio/minio/tree/9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a>.
The fixture image includes its AGPL license and is imported by actual manifest
digest into Kind; it is not a shipping utility catalogue image. A private internal
HTTPS service uses the fixture CA. Random fixture credentials are confined to
its Secret, MinIO, the controller startup, and administrator inventory helper;
they never enter collector/uploader environment or public artifact metadata.
The versioned bucket and backend sentinel are provisioned by the test helper.

Compilation and lint are local checks only. Actual container, storage, admitted
Pod and lifecycle behavior requires the named Kind CI matrix to pass.
