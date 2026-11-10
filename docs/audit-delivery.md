<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Audit delivery and immutable identity

## Release notes

Queued audit sinks now retain failed batches in their worker and retry the same
event IDs with bounded exponential backoff. `queue.dropOnFull: false` now applies
bounded backpressure rather than dropping with a warning. Each AuditConfig's
queue/delivery settings apply to its own sinks, independently of other configs.
The manager's shared ingress queue remains fixed at 100,000 entries and five
workers; only `dropOnFull` and the sampling settings are copied from the first enabled
AuditConfig by name.
Per-config `queue.size` and `queue.workers` tune sink queues, not shared ingress.

The event envelope has additive optional `target.uid`, `target.clusterUID`,
`requestContext.sessionUID`, `requestContext.debugSessionUID` and
`requestContext.escalationUID` fields. Authenticated API actors carry their full
verified group claim list; group paths are not truncated. System actors do not
inherit the requester or approver's identity. Background DebugSession events can
use the admission-protected authenticated requester group snapshot.
Existing actor identifiers are preserved: session request events use the
requester's email, while API approval events prefer the authenticated username
and fall back to email. Both identifiers receive the same verified group claims.

Resource identity is captured through the existing **uncached** client before
enqueue, with a one-second lookup deadline. Session emission sites also carry
their already-known UID. A previously captured UID is never replaced by a
same-named resource's new UID. Missing/ambiguous resources do not produce an
invented identity. Name-only emitters remain uncorrelated: a lookup cannot prove
which object they originally observed. Object-bearing emitters must supply the
source UID. Consumers should flag missing correlation when a resource was
deleted before emission or an older emitter omits its UID.
Cluster names and `clusterConfigRef` names alone do not populate `clusterUID`;
only an emitter that observed the exact ClusterConfig may supply that UID.
An unrelated target's UID does not authorize enrichment of a name-only session
reference: a UID-bearing target must identify the same session name.
A granted group is not an escalation name: the old
misleading group-based reference is not used for identity resolution.
`escalationUID` and its canonical name come only from the session's controlling
BreakglassEscalation owner reference, including after the escalation is deleted
or recreated. A same-named current escalation is never substituted.

## Outages longer than the retry window

Since #1538 a batch whose retry window (`retryAttempts` or
`retryTimeoutSeconds`) is exhausted is **retained** instead of dropped: the
sink worker keeps the batch with the same event IDs and retries it every
`retryMaxBackoffMillis` until it is delivered, a permanent failure occurs, or
the pipeline shuts down.

Permanent failures are not retried and do not trip the circuit breaker:
serialization errors, payloads that a healthy sink refuses (webhook HTTP 413
or 422; Kafka records or record lists that are too large, or invalid records;
not CRC errors) and a sink panic that persists past the retry window. Because
such a failure may come from the batch size or from one event, a failed batch
is halved and each half delivered again, down to single events; only a single
event is dropped, with reason `serialization`, `rejected` or `panic`. Other
events of the batch are delivered and cannot be blocked by it. Webhook HTTP
400 stays retryable, because gateways also return it for configuration
errors. Panics are logged with their stack. The kafka-go balancer panic on a
metadata response without partitions is returned as an ordinary, retryable
error.

The retention is logged once per
batch at warning level, and `breakglass_audit_events_retained{sink}` shows the
events currently held past their retry window.

Memory stays bounded by `queue.size` plus one batch per worker. A synchronous
Kafka write that times out leaves its records inside the kafka-go writer until
the writer's own produce attempt ends. The sink admits one synchronous write
at a time and keeps that slot until those records complete; other writers wait
for it within their own deadline (a healthy write holds it only while it
runs), so retries during an outage do not pile up copies in the writer. While the
workers hold their batches, new events wait in the sink queue; once it is full
they are dropped and counted with reason `queue_full` (or, with
`dropOnFull: false`, `enqueue_timeout`), and a warning is logged at most every
ten seconds. So the only losses are the explicit, counted ones: a full queue,
shutdown (reason `shutdown`) and the permanent failures above. A reload that
replaces the pipeline (for example a changed AuditConfig or a rotated Secret
during an outage) does not lose the events the old pipeline holds: after up to
`retryTimeoutSeconds` the old sink hands its queued, retrying and retained
events to the sink with the same AuditConfig, sink type and sink name in the new
pipeline, which counts its own overflow. Events still in the old manager's
ingress queue (for example with `dropOnFull: false` while a sink queue is
full) move to the new manager, which routes them through its own sinks,
within one write timeout for the whole handover; events that do not fit by
then are counted as `shutdown`. A
replaced pipeline that is itself already closed forwards them along the chain
of reloads. Only events of a sink that the reload removed are dropped as
`shutdown`. Retention is in memory: a controller restart or crash
still loses the retained and queued events.

Because the worker keeps retrying, the network circuit breaker keeps probing:
after its 30-second open timeout the next retry is a half-open probe, and two
successful probes close it again. A sink therefore recovers on its own after
the broker returns, without a restart or an AuditConfig change. A panic in a
sink write (kafka-go panics on a metadata response without partitions) counts
as a failed probe and no longer leaves the breaker stuck half-open with no
free probe slot, where it reported "circuit breaker is open" for every write
until the controller restarted (TCAAS-1614).

### Opt-out (transitional)

`queue.dropAfterRetryWindow: true` restores the earlier behaviour: the batch is
dropped and counted with reason `retry_exhausted` once the retry window is
exhausted, and five exhausted batches in a row open the queue's own circuit,
which drops non-sensitive events with reason `circuit_open`. This is a
transitional escape hatch for deployments that prefer fresh events over old
ones during a long outage; it will be removed in a future release. The
circuit-breaker fix applies in both modes.

```yaml
spec:
  queue:
    dropAfterRetryWindow: true
```

## Configuration

```yaml
spec:
  enabled: true
  queue:
    size: 10000
    workers: 1
    dropOnFull: false
    retryAttempts: 8
    retryInitialBackoffMillis: 1000
    retryMaxBackoffMillis: 10000
    retryTimeoutSeconds: 60
    dropAfterRetryWindow: false
  sinks:
    - name: events
      type: kafka
      kafka:
        brokers: ["kafka.example:9093"]
        topic: audit-events
        requiredAcks: -1
        async: false
        tls:
          enabled: true
          caSecretRef: {name: kafka-client, namespace: breakglass-system}
          clientCertSecretRef: {name: kafka-client, namespace: breakglass-system}
```

The retry fields above are the defaults. Attempts include the initial write.
Each write is bounded by five seconds and the fast retry phase is additionally
bounded by `retryTimeoutSeconds` (1–300). Backoff doubles to its configured cap.
After that the batch is retained and retried every `retryMaxBackoffMillis`
(see above). The worker holds the batch while retrying, bounding memory to the
configured queue plus worker batches. Network circuit-open errors are retried
like other failures. Per-sink and per-config filters run before enqueueing, so excluded
events neither consume queue capacity nor count as failed or dropped delivery.
A pipeline replaced by an AuditConfig change first finishes the events it
holds, bounded by its retry window (see `docs/audit-config.md`, "Reload
failures"). Shutdown interrupts backoff and shares a five-second queue-drain
budget; failed shutdown writes are counted. The manager ingress drain has its
own five-second budget; unprocessed ingress events are counted with reason
`shutdown`. Sink queues then drain concurrently with a five-second budget each.
Blocking sink ingress runs in parallel, so an unavailable sink cannot prevent
healthy sinks from receiving the same event.
After a sink's drain deadline, remaining queued events are counted together
without invoking the sink again. As with other context-based I/O, an in-flight
sink implementation must honor cancellation; a sink that ignores its context
cannot be forcibly interrupted safely.

With `dropOnFull: false`, enqueue blocks until capacity, caller cancellation, or
five seconds. Cancellation/timeout returns an error at the sink and counts the
lost event. Async `Manager.Emit` cannot return a delivery error, so its overflow
is logged and counted. Blocking mode is an **in-memory** fallback, not a durable
outbox: process crashes, full queues and (with `dropAfterRetryWindow: true`)
exhausted retry windows can still lose events. It does not provide unlimited lossless delivery.
Normal revocation and cleanup must not depend on the broker's availability.

Use synchronous Kafka (`async: false`) with acknowledgements for retryable
delivery. `async: true` and `requiredAcks: 0` intentionally do not provide a
delivery receipt. Whole-batch retry can redeliver records when Kafka accepted
them but an acknowledgement was lost. Consumers must deduplicate by event ID.
The event ID is stable across retries. Multiple workers do not establish total
lifecycle ordering; use event timestamps and immutable session identity.
Serialization failure rejects the entire batch before any network write instead
of silently skipping records. Such permanent failures are not retried and do
not alter either circuit breaker's failure or success state; dropped events
are counted with reason `serialization`. Fire-and-forget completion failures are explicitly
logged and counted with the `async_write` reason; they cannot be retried by the
external queue because submission already returned.
The external queue drain budget does not bound kafka-go's final `Writer.Close`
flush for asynchronous submissions; that flush waits for the writer's own
configured network timeouts and retries.
For asynchronous Kafka, processed-event metrics and queue health count broker
completion, not submission. Failed completions count as failed/dropped events.
The manager does not emit processed delivery metrics for handoffs into isolated
or queued sinks; those sinks report delivery separately. In-memory Manager
`ProcessedEvents` stats retain their ingress-handoff meaning.

## Observability

- `breakglass_audit_sink_errors_total{error_type="write"|"batch_write"}` counts
  failed event write attempts; `error_type="retry"` counts retry scheduling.
- `reason="rejected"`, `serialization` and `panic` count single events that
  failed permanently after their batch was split.
- `breakglass_audit_events_dropped_total{reason="retry_exhausted"}` counts each
  event abandoned after the delivery bound with `dropAfterRetryWindow: true`,
  not merely failed batches.
- `breakglass_audit_events_retained{sink}` is the number of events held past
  their retry window until the sink recovers. Their periodic retries count only
  as `breakglass_audit_sink_errors_total{error_type="retry"}`, not as further
  failed events or as the Kafka sink's classified error types.
- `breakglass_audit_circuit_breaker_state{sink}` (0 closed, 1 open, 2
  half-open) and `breakglass_audit_circuit_breaker_state_transitions_total`
  follow the network circuit breaker; each transition is logged.
- `reason="enqueue_timeout"`, `queue_full` and `circuit_open` identify other
  bounded loss paths. Exhaustion is logged at error level and drops at warning
  (per-event queue drops at most every ten seconds).
- Queued sink health exposes failed attempts, dropped/processed events,
  last error, queue occupancy and circuit status.

## Verification

```bash
make lint test
bash hack/audit-delivery-kind.sh
```

The isolated kind test starts a real digest-pinned KRaft broker, scales it down,
emits an audit event through the production service, confirms failed attempts,
restarts the broker and consumes the retained event with the same ID, full
groups and real Kubernetes target UID. It creates only a uniquely named kind
cluster and deletes that cluster on completion; it never uses an existing lab.
Two more tests keep the broker down for longer than both the retry window and
the breaker's open timeout: by default every event emitted during the outage
is consumed after the broker returns, nothing is counted as dropped and the
breaker closes again; with `dropAfterRetryWindow: true` the event is counted as
`retry_exhausted` and the sink still delivers new events after recovery.
The `Audit delivery` workflow runs these tests for PRs.

The existing controller/Keycloak/Kafka kind `TestAuditLogging` performs real
session request and approval via the API and now checks the persisted session
UID plus each authenticated actor's complete groups. Unit tests cover retry
exhaustion, backoff, deadline/backpressure, shutdown, independent queue
configuration, immutable name-reuse fences and actor identity separation.
