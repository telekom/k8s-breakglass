---
section: Behaviour changes
---

- The controller audits BreakglassEscalation changes as `escalation.created`,
  `escalation.updated` and `escalation.deleted`, and the authorization webhook
  emits `debug_session.attached` when a DebugSession authorizes exec, attach
  or port-forward into one of its pods. Both have structured schemas in
  `api/audit/v1` and are never sampled; exclude them per sink with
  `eventTypes` or `filtering.excludeEventTypes` (TCAAS-1625).
