# Diagnostic artifact E2E acceptance

The single- and multi-cluster API E2E lanes must exercise the complete `system-summary.v1` and `crashdump-collection.v1`
paths: an API-created active DebugSession and ConnectionLease, collection against
an approved Pod, a controller-created collector Job, HTTPS upload, authenticated
download, and cleanup. The lane uses an immutable digest for the test collector
image and a test CA trust layer; it does not weaken production TLS or claim that
the release image has been published.

The test also checks outsider and replay denial, authorization after session
termination, and provider/object cleanup. Unit and envtest suites remain the
source of coverage for injected publication and CAS race failures.
Revocation before the first authorized download bytes returns an error status
without attachment or length headers; later revocation stops the existing stream.
The real API-server reservation test also starts the artifact controller under
RBAC that denies hub Job access. Collector Jobs are created and polled through
spoke clients without hub owner references; a hub Job watch must not block
artifact cache synchronization or require broader controller permissions.

The single-cluster CI job explicitly runs `e2e/fixtures/artifacts/setup.sh`,
then `go test -tags=e2e ./e2e/api -run '^TestDebugSessionArtifactCollectorE2E$'`.
Missing fixture configuration fails this named lane. Other E2E suites keep their
existing HTTP listener; a test-only TLS sidecar forwards to that listener.
Once the environment and port-forwards are established, both artifact backends
run even if an earlier test suite fails. Each matrix depends on its own successful
fixture setup; failures still fail the job and cancellation stops further work.
The shared E2E termination client retries only explicit optimistic `409 CONFLICT`
responses, at most three times, without retrying authorization failures.
Both fixture setup and S3 backend selection wait for `/api/config` through the
runner's API port-forward after replacing the controller Pod. Deployment
readiness alone does not mean the keepalive port-forward has reconnected.
An unavailable endpoint fails setup before any session-creation POST is sent.
Session reads, artifact API routes and archive identity checks use the namespace
returned by session creation, which belongs to the ClusterConfig. The controller
fixture and artifact reservations remain in the controller namespace; the two
namespaces must not be assumed to match.
Workload Pod identity checks tolerate Kubernetes' canonical
`enableServiceLinks: true` admission default only when the workload left it
unset; an explicit `false` remains authoritative.

The setup creates a fresh private test CA and signing Secret and builds the
actual collector/uploader from source. Both generated Job containers use the
untouched image with its pinned system roots, imported into every disposable
Kind node by verified immutable manifest digest. Templates select a ConfigMap
for system-summary and a Secret for crashdump upload trust. Their CA key is
projected only into the uploader; the lifecycle test verifies the reference's
repository round-trip and successfully uploads through the private-CA TLS edge.
The system-summary termination case also runs the same fixed Job/image without
the bundle and requires an unknown-authority certificate-verification failure.
It never disables verification. This proves the test image, not a published
release image.

Only the test-only storage/TLS fixture layer appends the CA to its own system
roots, for MinIO and independent backend inventory. Collector Jobs do not use
that layer.

A single-replica Recreate controller mounts a private RWO PVC. Setup first
requires the controller to fail closed on the fresh PVC without provisioning.
A Job whose `stagingDir` is outside the volume must fail before it writes
anything.
It then runs the shipped `config/components/artifact-local-provision` Job
(`breakglass artifacts provision`) and requires the controller to start. The
same Job with a foreign instance ID must fail on the provisioned volume. Moving
the Deployment to a second, empty PVC must fail closed again. The test observes the real object files through its
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
an envtest API server. Its ClusterConfig fixture is marked Ready because
activation requires it. `make test-platform` runs it in the CI job "CRD Schema &
API Server Validation"; elsewhere set `KUBEBUILDER_ASSETS` to run it. This is complementary
to the Kind lane; it does not reproduce manager-cache timing or spoke transport.
Completed ephemeral-operation replay records its existing reference once while
preserving the separate Active-only allowed-Pod update.

## Incremental recording flush

In the multi-cluster artifact lanes the fixture config sets
`artifacts.terminalRecordingSegmentBytes: 65536` and exports
`E2E_RECORDING_SEGMENT_BYTES`, so every recording test there uses the opt-in
segmented path; the single-cluster lanes keep the default in-memory path, and
`TestDebugSessionTerminalRecordingIncrementalE2E` skips there (the multi-cluster
steps require it to pass). It runs against both backends:

- Backend failure: 200 KB are committed as segments first, then the existing
  fault hook (`/artifacts/provider-outage` for S3, `chmod 000 /artifacts/objects`
  for local) breaks the backend before more output. The stream must end within
  a minute without the later marker, `terminal_recording_failed` with
  `stage: flush` must be audited, and nothing may be listed.
- Controller kill: the controller Pod is force-deleted mid-stream once segments
  exist. The stream must end; nothing is listed until the artifact controller
  publishes the committed prefix after the session (stream binding) expired
  plus its one-minute grace. The prefix must be incomplete, digest- and
  hash-chain-verified, contain committed output but not the uncommitted tail,
  and its recovery must be audited (`recovered: true`, actor `system`). Only the
  recording object may remain in the backend (segments and manifests are
  removed), and the template's 3 minute `recordingRetention` must then remove it.

Sessions last 3 to 30 minutes; all waits are bounded polls. These lanes run
with a 45 minute `go test` timeout.

## Terminal recording limits

`TestDebugSessionTerminalRecordingLimitsE2E` runs in all four artifact lanes.
The single-cluster lanes keep the defaults (`uploadMaxBytes`, 2 streams); the
multi-cluster lanes set `terminalRecordingMaxBytes: 1048576` and
`terminalRecordingMaxConcurrent: 3`. The fixture exports the effective values
(`E2E_RECORDING_MAX_BYTES`, `E2E_RECORDING_MAX_STREAMS`); the test holds that
many streams open, requires `429` for one more, and requires a recording below
the byte limit to complete and one above it to stop the stream as incomplete
(audited as `recording_limit`). A recorded terminal moves only a few hundred
KiB per minute in Kind (#1761), so the stream above the limit runs only in the
opt-in lanes (1 MiB); that the default byte limit is `uploadMaxBytes` is covered
by unit tests (`TestTerminalRecordingLimits`, `TestRegisteredTerminalRouteStreamsAndPublishesRecording`).

## Explicit backend and lifecycle matrix

The same named test runs separately with `E2E_ARTIFACT_BACKEND=local` and `s3`.
`select-s3.sh` replaces the local configuration with an explicit S3 configuration;
there is no automatic failover. Each backend runs both recipes through terminate,
expiry, and session deletion. Each case restarts the real controller before
reading the retained control artifact, then verifies provider and tracked Job/
Secret cleanup. Local object files must remain mode 0600 and UID/GID 65532; S3
inventory includes all versions and delete markers so hidden versions cannot
masquerade as successful cleanup.
Each collection must first observe a Succeeded collector Pod with the exact
artifact ID, session UID and Job controller UID. Artifact deletion must remove
those Pods as well as the Job; termination, natural expiry and session deletion
must leave zero collector Pods for the session UID. These inventories do not
filter by owner reference or Pod phase, so a completed Pod orphaned by Job
deletion cannot masquerade as successful cleanup.
Permission checks run while both local objects are available, not while cleanup
can remove files between inventory and `stat`. Expiry cases request five-minute
sessions and wait for their real deadline; they never move an Active session's
expiry backward through a forbidden status patch.
The requester obtains a fresh OIDC token after cleanup so the final 404 checks
prove artifact denial for an authenticated identity, not an expired login token.

Before deleting a verified provider version, cleanup persists ownership evidence
in the existing `CleanupPublicationObserved` status condition. A restarted worker
can then finish after a lost completion-status write and two empty inventories.
Without that evidence, an unobserved publication remains ambiguous and retains
its finalizer; inventory errors and foreign versions still prevent finalization.

The crashdump source is harmless synthetic text seeded only inside the disposable
Kind nodes at `/var/lib/systemd/coredump/core.artifact-kind-fixture`. Tests inspect
the admitted Pod's exact node, immutable image, read-only hostPath and mount,
host namespace/runtime fields, and the downloaded archive's synthetic payload.
Both recipes validate their manifest contract, stdout/stderr, and payload hashes.
Generated Jobs pass recipe inputs through `DIAGNOSTIC_NODE`,
`DIAGNOSTIC_MAX_AGE_MINUTES`, and `DIAGNOSTIC_DETAIL_LEVEL`, matching the shipping
collector rather than relying on its standalone defaults.
No production source directory or credential is used.

The requester identity and groups used for API collection are impersonated for
actual forbidden create/patch/delete attempts against Jobs, Pods, Secrets and
NetworkPolicies carrying artifact labels in the execution namespace. Kyverno
PolicyException authorization is checked through SubjectAccessReview; this
upstream fixture does not install Kyverno and does not claim provider execution
or the downstream three-Function integration required by the SI acceptance gate.
The Kind API server calls the SAR webhook on the controller's API port 8080,
not its metrics port 8081. A metrics-port 404 becomes an authorization error
(HTTP 500), which must not be mistaken for the required forbidden response.

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
The fixture S3 service publishes not-yet-ready Pod addresses because its MinIO
and TLS proxy are sidecars of the controller. Otherwise the controller's S3
startup verification waits for service endpoints that require that same startup
to finish. This does not change readiness gating for the controller API service.

Compilation and lint are local checks only. Actual container, storage, admitted
Pod and lifecycle behavior requires the named Kind CI matrix to pass.

## Real hub/spoke execution

The Multi-Cluster E2E job runs the same local/S3 lifecycle matrices with
`-tags=e2e,multicluster` and `E2E_CLUSTER_NAME=spoke-cluster-a`. Reservations,
signing keys, provider credentials and provider storage stay on the hub;
workload Pods, collector Jobs, scoped upload-token Secrets and upload CA
references are inspected through the real spoke client. The test requires a
different API-server address, no hub owner references on spoke Jobs, and no
same-named collector Job on the hub. Requester create/patch/delete negatives
also execute against the spoke, not the hub.

The disposable fixture imports the immutable collector image and synthetic
crashdump source into both hub and spoke nodes. A spoke Service/EndpointSlice
routes the unchanged private-CA TLS name to the hub's NodePort; certificate
verification remains enabled. Only the public upload CA is projected into the
spoke's administrator-created ConfigMap or Secret. No TLS private key, signer
key or provider credential is copied there. Native acceptance still requires
the exact-head Multi-Cluster job to pass; compilation is not acceptance.

## Failure injection

A fixture-only HTTPS edge can pause collector uploads while the test sends a
freshly issued artifact token directly to the real Breakglass upload handler.
A valid re-bound archive is accepted first; missing/extra outputs, a wrong output
declaration, a cross-recipe manifest and a wrong session identity must then be
rejected on separate reservations. The independent native
`TestArtifactArchiveMutationContract` verifies the probe's payload-tar checksum,
so rejection cannot be attributed solely to broken fixture serialization.

The deletion paths also exercise real failure retention before repair:

- Local/PVC: temporarily unreadable object root, then a corrupted stored file.
- S3: a fixture HTTP 503 outage, then an actual foreign object version with
  mismatched ownership metadata in the disposable versioned bucket.
- Both: a persisted cleanup reference to a nonexistent ClusterConfig, while the
  original tracked Job and Secret still exist.

Each failure must preserve the artifact finalizer and tracked resource inventory.
Provider failures must set the cleanup-ambiguous status. Repair restores the
original fixture evidence, triggers reconciliation, and must remove only the
owned artifact while keeping its control artifact readable. The missing-config
case repairs the original reference without creating a substitute ClusterConfig
or changing its UID. These controls exist only in the disposable E2E fixture.

Collector Job and immutable upload Secret names include the reservation's CR UID,
not its reusable artifact slot. A real kubelet can retain an immutable Secret's
old value while an earlier Pod references that name, even after the Secret is
deleted and recreated. Persisted legacy resource intents remain reconcilable.
Each case waits for its session's artifact cleanup before the next provider
inventory baseline is captured, including when an earlier assertion fails.

S3 publication supplies the verified staged size as `Content-Length`; the
digest-checking reader does not expose its length to the AWS SDK. Signed writes
without that length are rejected by the real versioned MinIO fixture with 411,
not treated as a successful or automatically retried upload.

## Acceptance map

Each acceptance bullet maps to named tests. `E2E` means
`TestDebugSessionArtifactCollectorE2E/<recipe>/<terminate|expire|delete>`, run once
per backend (`E2E_ARTIFACT_BACKEND=local|s3`) in the single-cluster and the
multi-cluster Kind lanes. `e2e/api.` tests are built with the `e2e` tag and run in
the same lanes. Everything else runs under `go test ./pkg/artifacts/...`. Tests
assert both the rejection and that no state, provider byte or resource changed.
Where a bullet is enforced in layers, the enforcement column names the layer
each unit test pins; the other layers keep rejecting when one is removed.
The new unit tests call `backend.Service` directly; handler-level (HTTP) denial
is covered by the E2E lanes.

| Acceptance | Test | Enforcement it fails without |
| --- | --- | --- |
| Crashdump Pod mounts exactly `/var/lib/systemd/coredump` read-only at `/host-coredumps`, collector only, no host namespaces | `job.TestBuildMountsExactHostCoredumpPathReadOnlyIntoCollectorOnly`, `job.TestBuildCrashdumpJobPinsNodeAndReadOnlyHostPath`; admitted Pod, exact node, immutable image, no extra runtime fields in E2E, both backends | `job.Build` host path, `ReadOnly`, mount path |
| Rendered runtime surface limited to the recipe | `job.TestCollectorExecutionRejectsMutations`, `job.TestCollectorExecutionAcceptsRealAPIDefaults`, E2E admitted-Pod assertions | admission of runtime fields |
| Injected recipe/input/argument rejected | E2E only (`unknown` recipe, `command`/`args`/`image`/`path`/`mounts` fields) | strict request decoding, recipe allowlist |
| Wrong/missing/extra/cross-recipe outputs and manifest identity rejected server-side | E2E `assertArtifactArchiveRejections`, `e2e/api.TestArtifactArchiveMutationContract`, `archive.TestValidateRejectsManifestAmbiguityAndBindingForgery`, `archive.TestValidateRejectsChecksumCountsAndHeaderTampering`, `archive.TestValidateSystemSummaryExactContract` | `archive.Validate` |
| Cross-session denial (session A cannot read, upload or download session B's artifacts) | `backend.TestUploadTokenOfSessionACannotWriteSessionB`, `TestUploadTokenWithForeignSessionUIDIsForbidden`, `TestUploadTokenCannotBeReplayedOnAnotherArtifactRoute`, `TestSessionACannotListOrDownloadSessionBArtifacts`, `TestListAuthorizedChecksCompleteArtifactBinding`; E2E second session gets 404 for the first session's artifact, outsider gets 404/403 | `Upload` looks the record up by the signed claims (never the request path), plus route and session-UID binding; `ListAuthorized` caller check and per-record binding (layered); `Download` name and UID binding (layered: the UID test pins `authorize`) |
| Upload token replay rejection | `backend.TestUploadRejectsStaleJTIAndConsumedTokens` (consumed token returns replay, in-flight reuse conflicts, foreign JTI forbidden), `TestServiceRealLocalStoreRoundtripUIDIsolationAndExistingRecovery`, `host.TestCollectorLeaseRecreationDeniesOldUploadTokenAndDownload`, `host.TestDurableCollectorReservationTokenAndLocalRoundtrip`; E2E consumed token gets 409 | one-time JTI-hash/state check in `Upload` |
| Expired token / expired reservation | `backend.TestUploadTokenExpiredIsRejectedWithoutSideEffects`, `TestUploadAfterReservationExpiryIsRejected`, `token.TestVerifyUsesInclusiveTimeBoundaries` | token expiry, reservation expiry |
| Object cleanup after terminate, expire and delete | E2E (all three cleanups; provider inventory incl. S3 versions and delete markers, zero Jobs/Secrets/Pods), `host.TestAvailableCollectorEvidenceFollowsSessionLifecycle`, `backend.TestCleanupRequiresTwoEmptyInventoriesAfterExactDelete` | controller and `Service.Cleanup` |
| RBAC negatives: requester cannot create/patch/delete Jobs, Pods, Secrets, NetworkPolicies, nor authorize PolicyExceptions; forged collector labels rejected | E2E `assertArtifactRequesterCannotForge` (impersonated requester, forged copies carrying real artifact labels, on the spoke in the multi-cluster lane) | Kubernetes RBAC for the requester identity |
| Finalizer retained when the target is ambiguous (absent vs unreachable) | `controller.TestReconcileRetainsFinalizerWhenTargetStateIsAmbiguous` (ClusterConfig absent, unreachable, UID replaced, invalid, spoke read failure, session absent), control `TestReconcileReleasesFinalizerWhenTargetIsProvenClean`, `TestCleanupRetainsUIDLessIntentAndBlocksFinalization`; E2E missing-ClusterConfig, provider outage, foreign version | `cleanupSpokeResources` error returns, which `Reconcile` propagates (its non-empty-inventory guard is a race-only second layer not isolated by a unit test) |
| Credentials and provider location never leak | E2E metadata/Job env assertions, `backend.TestPublicRecordOmitsProviderMetadata`, `job.TestBuildRejectsUnpinnedImageAndProviderURL` | public record shape, Job env |
| Local backend: private modes, restart, no S3 failover | E2E `E2E_ARTIFACT_BACKEND=local` (mode 0600, UID/GID 65532, controller restart), `host.TestProvisionLocalRequiresExplicitLocalBackend`, `host.TestOpenStoreRejectsMixedBackendsAndCrossNamespaceCredentials` | explicit backend selection |

Not covered upstream: the three-Function production-like integration and the
Kyverno policy execution; they belong to the downstream auth-operator Function CI.
