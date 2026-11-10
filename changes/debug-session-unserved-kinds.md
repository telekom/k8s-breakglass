---
section: Behaviour changes
---

- DebugSession cleanup now retires unresolved create intents (no recorded UID)
  of auxiliary, pod-template and deployed resources whose kind the target
  cluster does not serve, confirmed via discovery (for example a Kyverno
  `PolicyException` on a cluster without Kyverno). Before, cleanup retried them
  every 5 seconds without end. Resources with a recorded UID are kept as
  residuals, because a deregistered APIService keeps its stored objects. Activation now fails before
  the first target write when a required auxiliary resource needs an unserved
  API. Failed cleanup backs off exponentially up to 5 minutes and emits
  `debug_session.cleanup_failed` once per distinct residual set instead of on
  every attempt. To restore the previous behaviour, use the transitional
  opt-outs `--disable-debug-session-unserved-kind-handling` and
  `--disable-debug-session-cleanup-backoff` (#1663).
- Sessions already in `CleanupFailed` when you upgrade emit one more
  `debug_session.cleanup_failed`, because their condition message predates the
  residual-set digest. Their next retry then waits the full 5-minute backoff,
  since they have been failing since before the upgrade (#1663).
