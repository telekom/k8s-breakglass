<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Helper invariants

Namespace selectors use exact membership: `*` is literal, missing labels differ
from empty values, and deny rules take precedence. `GlobMatch` keeps its special
universal wildcard and exact-literal behavior. Approval-reason enrichment keeps
backend/stored reasons ahead of legacy lookups without mutating responses.

Unused frontend wrappers were removed; backend token validation and supported
session actions are unchanged. Run `go test ./pkg/utils` and
`cd frontend && npm test` for the affected helpers.

## Backend and frontend helpers

Exact membership uses `slices.Contains`, not wildcard matching. Map copies use
`maps.Clone`; helpers that previously normalized empty maps to `nil` retain that
behavior, and modifying a copied map must not modify its input. Both exported
RFC 1123 name normalizers retain their fallback, trimming, and 63/253-character
limits while sharing the normalization pipeline.

### Platform characterization before shared-library adoption

Run `make test-platform` for race-enabled tests of rate limiting, certificates,
resource readiness, leader election, name outputs, config reload and audit
redaction. The target installs the pinned envtest assets and runs certificate,
condition and leadership tests against a real API server; ordinary unit runs
without `KUBEBUILDER_ASSETS` skip these envtests. CI runs the target in the
CRD validation job.

The certificate test supplies the same empty Secret as production manifests
and explicitly projects Secret data onto disk because envtest has no kubelet.
It checks leadership gating, service SANs and CA identity, CA injection,
readiness after projection, leaf refresh with a preserved CA, and CA rotation.
The election test uses two real Lease clients with shorter election durations
and partitions one client's transport. It checks cancellation of per-epoch
work, channel replacement, competing leadership and reacquisition without
restarting the election loop.

Readiness tests persist ClusterConfig and BreakglassEscalation status
transitions, including status-subresource round trips, stable transition times
for reason-only changes and stale generation handling. Generic kstatus treats
unknown kinds without conditions as Current and ignores the local `Failed`
condition; `Stalled=True` yields Failed. Domain-specific escalation readiness
is stricter. Do not substitute one readiness predicate for another.
The auxiliary-resource integration test preserves the recorded-UID guard:
missing resources are pending, same-name replacements fail, and legacy
resources without a recorded UID are never accepted as ready.

The naming goldens preserve user-visible normalization and truncation, not
merely validation. A session-creation envtest exercises the actual naming
consumer, checks persisted generated names and resolved-identity labels, and
selects the created session through the canonical user label. CLI tests pin
certificate filename/path defaults and environment/flag precedence; existing
webhook options tests cover how those paths reach the serving configuration.
Config reload coverage preserves interval-based checks,
mtime equality, last-known-good fallback on malformed/deleted files, recovery
and atomic replacement, including the escalation manager's injected shared
loader. Neither Kubernetes name validation nor a strict YAML
decoder is a behavior-preserving replacement for those policies by itself.
Rate-limit tests preserve per-IP/per-identity isolation, denial responses,
retry reservation cancellation and idle eviction. General Gin middleware does
not set Retry-After; session creation does, using rounded-up seconds.

### Platform library adoption

The public [`t-caas-go-library` guide](https://github.com/telekom/t-caas-go-library/blob/main/docs/upstream-libraries.md)
documents the upstream-first policy. This repository pins library `v0.1.0`.

Certificate registration now uses `pkg/certrotation`. The local adapter keeps
the dedicated manager, external leadership gate, empty-Secret bootstrap,
service SANs, CA identity, no-restart policy and the existing readiness channel.
It does not enable the library's leader-only mounted-pair readiness mode:
`Ensure` still checks PEM presence, as characterized before migration.
`TestLibraryCertificateBootstrapEnvtest` exercises the real library path,
including leaf and CA rotation, without the original test's injectable
cert-controller hook. Controller names are scoped by namespace/Secret to avoid
process-wide registration collisions.

Audit URL diagnostics use `pkg/redact.URL`, preserving the `<invalid-url>`
marker. Opaque URLs are now hidden rather than leaking their contents; adoption
tests cover this deliberate diagnostic improvement and preserved encoded-fragment
redaction.
The constant transport-error wrapper stays local: `redact.Wrap` only removes
known URL components and cannot hide arbitrary nested transport details while
preserving the original `errors.Is`/`errors.As` chain.

Generic readiness already delegates to `kstatus/status.Compute`, and CRD
condition setters already use apimachinery. Their domain adapters are unchanged.
An attempted `wait.PollUntilContextTimeout` replacement was dropped: applying its
deadline to the initial API request changes the Phase 1 timeout result from
NotFound to Unknown, and leaving that request outside the deadline would not
provide a strict end-to-end deadline. Callers needing one must supply a deadline
on their context.
Name trimming uses `strings.TrimFunc`, while normalization keeps apimachinery's
existing length constants and exact goldens.

The following helpers deliberately remain local after inspecting the tagged
APIs; replacing them would break unchanged Phase 1 contracts:

* The keyed limiter's periodic, strictly-older-than idle cleanup and unbounded
  key retention differ from library `pkg/ratelimit`'s mandatory bounded LRU
  storage, lazy expiry and restricted rate/burst validation. Eviction resets
  budgets. Adding a cardinality bound or changing stop/idle semantics requires
  an explicit configuration and policy decision; the existing buckets already
  use upstream `golang.org/x/time/rate`.
* Leader election already uses client-go. The local callbacks and retry loop
  preserve reacquisition and cancellation of per-epoch background work;
  controller-runtime's one-shot manager lifecycle is not a replacement.
* Apimachinery validates names but does not normalize identity-derived values.
  Replacing the remaining normalization with validation would change names,
  fallbacks and persisted labels.

### Post-adoption SSA cleanup

The merged status-SSA and optimistic-patch adoption left several unused
compatibility APIs in `pkg/utils`: `RetryConfig`, `DefaultRetryConfig`,
`StatusUpdateWithRetry`, `UpdateWithRetry`, `ApplyTypedObject`, `ApplyStatus`,
and `ToStatusApplyConfiguration`. They had no production callers and are now
removed with their helper-only unit and envtest cases. The unused
`ssa.PatchApplyResultCreated` status alias is also removed: status writes require
an existing object, while the main-resource `utils` alias remains in use. The unrelated
`api/v1alpha1.RetryConfig` mail-provider field and `e2e/helpers.UpdateWithRetry`
remain unchanged.

Main-resource consumers still use `ApplyObject` and `ApplyUnstructured`.
Status consumers use the CRD-specific builders in
`api/v1alpha1/applyconfiguration/ssa`, backed by shared `pkg/ssa`; concurrent
status mutations use shared `pkg/patch`. Both SSA adapter packages use the same
field-manager constant. The remaining main-resource converter always excludes
status, preserving scope, GVK and integer precision.

Retained real-API tests exercise every status builder, competing/custom field
managers, explicit empty lists, auxiliary-resource reclaim, session lifecycle
fences and concurrent activity writers. Removing tests of the dead retry engine
does not remove the live conflict/recompute tests in the controllers and
webhook. Two `PatchApplyResult.String` tests were also removed because both
types are aliases of the shared library's already-tested enum.

The remaining main-resource comparison glue is deliberate: the typed gate
compares full converted metadata, while the unstructured gate ignores status
and compares only labels/annotations within metadata, preserving its own
managed-field pruning checks. Shared `pkg/ssa.Applier` instead uses extracted
ownership and never skips UID/resourceVersion preconditions. Harmonizing these
policies with auth-operator requires a separate behavior decision, not another
generic compatibility wrapper.
* Upstream provides no reload wrapper with this repository's last-known-good,
  mtime and check-interval policy. Keep the existing YAML-tagged decoder;
  switching to strict or JSON-tagged decoding would change accepted config.

Import frontend date and duration utilities by their named exports rather than
constructing a stateless composable object. Pending-request withdrawals remain
in the view's confirmation/action flow, including busy state, error handling,
and pruning the completed request. Vite handles the literal dynamic imports used
by lazy routes and both UI flavours without an extra Rollup plugin.

## Unregistered APIs and obsolete filtering

The standalone `ClusterBindingAPIController` and its response DTOs were removed.
Production deliberately never registered those routes: debug-session bindings
are resolved through `GET /api/debugSessions/templates/:name/clusters`.
Only the deleted controller's tests and benchmark constructed it. Its local
`IsBindingActive` duplicate also had no consumers outside that controller.
The live binding predicates, CRD reconciler, authorization and discovery paths
are unchanged. `TestDebugSessionAPITemplateClusters`,
`TestDebugSessionAPIClusterSelectorMatching` and
`TestDebugSessionClusterBindingAuthorization` retain E2E coverage;
`TestHandleGetTemplateClusters` exercises the live handler.

The unused `EscalationFiltering` adapter was also removed with its two tests.
Only those tests invoked its group-extractor-based filtering. Production uses
the escalation controller and session controller's identity-aware authorization,
not this legacy adapter. `TestEscalationAPIList`, `TestEscalationAPICombinedFilters`
and `TestGroupBasedApproverCanApprove` still exercise the public API flows.
No registered endpoint or supported CRD field was removed.

The unused `MockKafkaBroker` fixture was removed as well: no test constructed it.
It did not implement the Kafka protocol and supplied no live audit coverage.
Kafka sink/manager tests and real Kafka delivery E2E tests remain unchanged.

## E2E helpers

Resource builders assign optional scalars and pointers directly. Defaults,
explicit `false`/zero pointers, and empty-slice normalization are unchanged.
`UpdateWithRetry` retries only update conflicts, re-fetches before reapplying
the modifier, and stops after six total attempts. Backoff starts at 50 ms,
doubles with a one-second cap, and remains cancellable through the context.

CI and the single-cluster setup share `e2e/lib/port-forward.sh`:

```bash
source e2e/lib/port-forward.sh
start_keepalive_port_forward breakglass-system breakglass-breakglass 8080 8080
```

An optional fifth argument selects a kubeconfig; otherwise the helper uses
`HUB_KUBECONFIG`, then `KUBECONFIG`. It preserves the two-second restart delay,
prints the wrapper PID, and records it when `PF_FILE` is set. Stopping the
wrapper also stops and reaps the active forwarder or restart-delay process.
Kubectl diagnostics are quiet by default; a sixth argument of `/dev/stderr`
duplicates the caller's stderr descriptor, preserving its capture and shared
file offset on Linux, as used by the hard-expiry workflow.
Endpoint-specific readiness checks remain with the callers.

Run `go test -race ./e2e/helpers`, `bash e2e/lib/port-forward_test.sh`, and
`shellcheck -x e2e/lib/port-forward.sh e2e/lib/port-forward_test.sh` for these
helper contracts. The shell test covers lifecycle behavior with a command
fixture; the normal CI E2E lanes remain the real Kubernetes forwarding proof.
