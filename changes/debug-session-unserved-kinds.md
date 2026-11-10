---
section: Behaviour changes
---

- DebugSession cleanup now treats auxiliary, pod-template and deployed resources
  whose kind the target cluster does not serve (for example a Kyverno
  `PolicyException` on a cluster without Kyverno) as already deleted. Before,
  cleanup retried them every 5 seconds without end. Activation now fails before
  the first target write when a required auxiliary resource needs an unserved
  API. Failed cleanup backs off exponentially up to 5 minutes and emits
  `debug_session.cleanup_failed` once per distinct residual set instead of on
  every attempt. To restore the previous behaviour, use the transitional
  opt-outs `--disable-debug-session-unserved-kind-handling` and
  `--disable-debug-session-cleanup-backoff` (#1663).
