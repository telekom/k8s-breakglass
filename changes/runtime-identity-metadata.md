---
section: Upgrade notes
---

- Apply the CRDs before the controller: `DebugSession` has the new field
  `spec.ticketSystemID`, `DebugSessionTemplate` has
  `spec.audit.runtimeIdentityMetadata` and the kubectl-debug operation status
  records `ephemeralContainer.requestedName` (TCAAS-1551).
- Debug pods (workload, pod copy, node debug, artifact collector) get the
  runtime identity labels `breakglass.telekom.com/debug-session-uid` and
  `debug-template` and the annotations `requested-by`, `approved-by` and
  `ticket`. Ephemeral containers are named `bg-<uid8>-<n>` by the controller
  and the target pod gets `breakglass.telekom.com/ephemeral.<name>`; clients
  that attach to an injected container must use the `container` name from the
  API response. Existing pods are not relabeled. The transitional escape
  hatches `debugSessions.disableRuntimeIdentityMetadata` (global) and
  `spec.audit.runtimeIdentityMetadata: false` (template) turn this off. See
  [docs/debug-session.md](../docs/debug-session.md#runtime-identity-metadata).
