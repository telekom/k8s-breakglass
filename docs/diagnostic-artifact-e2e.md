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
