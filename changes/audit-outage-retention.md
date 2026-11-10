---
section: Behaviour changes
---

- Audit sinks no longer drop a batch when a broker outage outlasts the retry
  window (#1538). The worker retains the batch and retries it every
  `queue.retryMaxBackoffMillis` until the sink recovers; only events that no
  longer fit in the queue are dropped and counted (`queue_full`,
  `enqueue_timeout`). The new gauge `breakglass_audit_events_retained` shows
  the held events. Apply the CRDs before the controller: `AuditConfig` has the
  new field `queue.dropAfterRetryWindow`. Setting it to `true` restores the
  earlier drop behaviour; it is a transitional escape hatch and will be
  removed in a future release.
- A panic in a sink write during a half-open circuit-breaker probe no longer
  leaves the breaker stuck reporting "circuit breaker is open" after the broker
  recovers; Kafka writer panics are returned as errors (TCAAS-1614).
