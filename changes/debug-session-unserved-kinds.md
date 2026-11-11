---
section: Behaviour changes
---

- DebugSession activation now fails before the first target write when a
  required auxiliary resource needs an API the target cluster does not serve
  (for example a Kyverno `PolicyException` on a cluster without Kyverno). A
  client-side `NoMatch` on create counts as a definitive rejection, so no
  cleanup residual is left behind. Before, cleanup retried such sessions every
  5 seconds without end. Cleanup still never infers deletion from discovery:
  recorded objects and unresolved create intents of an uninstalled kind stay
  residuals until an operator lists them in the new
  `breakglass.t-caas.telekom.com/cleanup-acknowledged-absent` annotation, which
  emits `debug_session.cleanup_acknowledged` (#1663).
- Setting that annotation requires the new RBAC verb `acknowledge-cleanup` on
  `debugsessions`, checked by the DebugSession webhook with a
  SubjectAccessReview. The controller ClusterRole now includes
  `subjectaccessreviews: create`. The new ClusterRole
  `debugsession-cleanup-acknowledger` is bound to nobody; bind it to the
  operators who may acknowledge. The new `status.cleanupAcknowledgement` field
  requires the updated DebugSession CRD, so apply CRDs before the controller
  (#1663).
- Failed cleanup backs off exponentially up to 5 minutes and emits
  `debug_session.cleanup_failed` once per distinct residual set instead of on
  every attempt. To restore the previous behaviour, use the transitional
  opt-outs `--disable-debug-session-unserved-kind-handling` (preflight) and
  `--disable-debug-session-cleanup-backoff` (#1663).
- Sessions already in `CleanupFailed` when you upgrade emit one more
  `debug_session.cleanup_failed`, because their condition message predates the
  residual-set digest. Their next retry then waits the full 5-minute backoff,
  since they have been failing since before the upgrade (#1663).
