---
section: Fixes
---

- A queued audit sink now updates `breakglass_audit_events_dropped_total` before
  the dropped count in its health status. A reader that sees the new count also
  sees the metric. Delivery is unchanged (#1548).
