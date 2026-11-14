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
  residuals until an operator retires them with the new
  `DebugSessionCleanupAcknowledgement` resource, which emits
  `debug_session.cleanup_acknowledged` (#1663).
- Creating a `DebugSessionCleanupAcknowledgement` requires RBAC `create` on
  the new resource; the new ClusterRole
  `breakglass-debugsession-cleanup-acknowledger` (`debugsession-cleanup-acknowledger`
  plus the `config/base` kustomize name prefix) is bound to nobody.
  Applied acknowledgements carry a retention finalizer: when uninstalling,
  end sessions through the API and wait for their cleanup, then delete the
  sessions, then the acknowledgements, then the controller (see
  `docs/installation.md#uninstalling-breakglass`). On Kubernetes 1.30+, add the optional kustomize component
  `config/components/cleanup-acknowledgement-policy`: its
  ValidatingAdmissionPolicy enforces `acknowledgedBy` in the API server, even
  before the webhook is deployed. Acknowledgements are processed only while their validating webhook
  is active for CREATE and UPDATE with `failurePolicy: Fail`; it also keeps
  the acknowledgement spec immutable on hubs without CEL validation. An acknowledgement by the session's
  requester, approver or a participant is rejected (#1663).
- Upgrade order: apply the CRDs (the new
  `debugsessioncleanupacknowledgements` CRD and the DebugSession status field
  `cleanupAcknowledgements`) before the controller. An older DebugSession CRD
  prunes the field; the controller then logs an error and keeps no
  provenance record on the session until the CRD is updated (#1663).
- Failed cleanup backs off exponentially up to 5 minutes and emits
  `debug_session.cleanup_failed` once per distinct residual set instead of on
  every attempt. To restore the previous behaviour, use the transitional
  opt-outs `--disable-debug-session-unserved-kind-handling` (preflight) and
  `--disable-debug-session-cleanup-backoff` (#1663).
- Sessions already in `CleanupFailed` when you upgrade emit one more
  `debug_session.cleanup_failed`, because their condition message predates the
  residual-set digest. Their next retry then waits the full 5-minute backoff,
  since they have been failing since before the upgrade (#1663).
- Sessions created, joined or approved before this version have no recorded
  party identities, so four-eyes cannot compare them fully: every cleanup
  acknowledgement for them is rejected (fail closed), including sessions
  already in `CleanupFailed`. To retire residuals of such a session, run the
  controller with `--allow-legacy-identity-cleanup-acknowledgement`, which
  compares only the identities that were recorded, create the
  acknowledgement, then remove the flag again (#1663).
- Downgrading: older controllers never remove the
  `breakglass.t-caas.telekom.com/cleanup-acknowledgement-retention` finalizer
  from Applied acknowledgements, so deleting an acknowledgement or its
  namespace hangs. Remove the finalizer by hand as described in
  `docs/installation.md#uninstalling-breakglass` (#1663).
