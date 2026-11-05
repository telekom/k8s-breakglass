---
section: Fixes
---

- A `DebugSessionClusterBinding` whose cluster or template selector matches
  nothing now reports `Ready=True` with `NoClustersMatched` or
  `NoTemplatesMatched` and clears its stale resolved references. Stage-
  partitioned catalogues therefore install through Helm/Flux on hubs that do
  not host every target stage. Missing explicit references, invalid selectors,
  and resolution errors still report `Ready=False`. Intentionally disabled
  `IdentityProvider`, `MailProvider`, and `AuditConfig` resources also report
  `Ready=True` with their disabled reason while remaining inactive (#1581).
