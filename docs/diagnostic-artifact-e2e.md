# Diagnostic artifact E2E acceptance

The single-cluster API E2E lane must exercise the complete `system-summary.v1`
path: an API-created active DebugSession and ConnectionLease, collection against
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
