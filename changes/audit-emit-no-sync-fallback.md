---
section: Behaviour changes
---

- Asynchronous audit emission no longer writes a sensitive event (for example
  `access.denied`) synchronously when the manager's ingress queue is full. The
  event is dropped and counted in
  `breakglass_audit_events_dropped_total{reason="queue_full"}`. Before, the
  authorization webhook could wait up to the five-second write timeout for a
  stalled sink, such as a Kafka broker that is down, so a SubjectAccessReview
  with a shorter webhook timeout failed closed. `queue.dropOnFull: false`
  keeps its bounded wait for queue capacity. Paths that need a delivery
  receipt still emit synchronously and fail closed. This reverses the earlier
  synchronous fallback for sensitive events on a full queue. See
  `docs/audit-config.md` (#1540; issue 1538).
