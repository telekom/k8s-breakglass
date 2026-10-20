---
section: Behaviour changes
---

- `POST /api/debugSessions` without `bindingRef` now uses the first binding
  that grants the cluster and allows the requester (visible bindings before
  hidden ones, each in namespace and then name order). Before, it used the
  first binding by name and rejected requesters that only a later binding
  allows, for example an onboarding requester when a first-line binding of the
  same template and cluster sorted first. A requester that no binding for the
  cluster allows is still rejected with 403 (#1535).
