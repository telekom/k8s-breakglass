<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Audit delivery and immutable identity

## Release notes

Queued audit sinks now retain failed batches in their worker and retry the same
event IDs with bounded exponential backoff. `queue.dropOnFull: false` now applies
bounded backpressure rather than dropping with a warning. Each AuditConfig's
queue/delivery settings apply to its own sinks, independently of other configs.
The manager's shared ingress queue retains its existing first-config settings.

The event envelope has additive optional `target.uid`, `target.clusterUID`,
`requestContext.sessionUID`, `requestContext.debugSessionUID` and
`requestContext.escalationUID` fields. Authenticated API actors carry their full
verified group claim list; group paths are not truncated. System actors do not
inherit the requester or approver's identity. Background DebugSession events can
use the admission-protected authenticated requester group snapshot.

Resource identity is captured through the existing **uncached** client before
enqueue, with a one-second lookup deadline. Session emission sites also carry
their already-known UID. A previously captured UID is never replaced by a
same-named resource's new UID. Missing/ambiguous resources do not produce an
invented identity. Consumers should flag missing correlation when a resource was
deleted before emission. A granted group is not an escalation name: the old
misleading group-based reference is not used for identity resolution.
`escalationUID` and its canonical name come only from the session's controlling
BreakglassEscalation owner reference, including after the escalation is deleted
or recreated. A same-named current escalation is never substituted.

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
Each write is bounded by five seconds and the complete delivery is additionally
bounded by `retryTimeoutSeconds` (1–300). Backoff doubles to its configured cap.
The worker holds the batch while retrying, bounding memory to the configured
queue plus worker batches. Network circuit-open errors are retried within the
same bound. Shutdown interrupts backoff and shares a five-second queue-drain
budget; failed shutdown writes are counted. The manager ingress drain has its
own five-second budget; unprocessed ingress events are counted with reason
`shutdown`. Sink queues then drain concurrently with a five-second budget each.
Blocking sink ingress runs in parallel, so an unavailable sink cannot prevent
healthy sinks from receiving the same event.

With `dropOnFull: false`, enqueue blocks until capacity, caller cancellation, or
five seconds. Cancellation/timeout returns an error at the sink and counts the
lost event. Async `Manager.Emit` cannot return a delivery error, so its overflow
is logged and counted. Blocking mode is an **in-memory** fallback, not a durable
outbox: process crashes, exhausted retry windows, full queues and prolonged
outages can still lose events. It does not provide unlimited lossless delivery.
Normal revocation and cleanup must not depend on the broker's availability.

Use synchronous Kafka (`async: false`) with acknowledgements for retryable
delivery. `async: true` and `requiredAcks: 0` intentionally do not provide a
delivery receipt. Whole-batch retry can redeliver records when Kafka accepted
them but an acknowledgement was lost. Consumers must deduplicate by event ID.
The event ID is stable across retries. Multiple workers do not establish total
lifecycle ordering; use event timestamps and immutable session identity.
Serialization failure rejects the entire batch before any network write instead
of silently skipping records. Fire-and-forget completion failures are explicitly
logged and counted with the `async_write` reason; they cannot be retried by the
external queue because submission already returned.

## Observability

- `breakglass_audit_sink_errors_total{error_type="write"|"batch_write"}` counts
  failed event write attempts; `error_type="retry"` counts retry scheduling.
- `breakglass_audit_events_dropped_total{reason="retry_exhausted"}` counts each
  event abandoned after the delivery bound, not merely failed batches.
- `reason="enqueue_timeout"`, `queue_full` and `circuit_open` identify other
  bounded loss paths. Exhaustion is logged at error level and drops at warning.
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
The `Audit delivery` workflow runs this test for PRs.

The existing controller/Keycloak/Kafka kind `TestAuditLogging` performs real
session request and approval via the API and now checks the persisted session
UID plus each authenticated actor's complete groups. Unit tests cover retry
exhaustion, backoff, deadline/backpressure, shutdown, independent queue
configuration, immutable name-reuse fences and actor identity separation.
