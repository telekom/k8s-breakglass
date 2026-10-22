---
section: Security
---

- Add review-gated Renovate tracking for unsupported tool, system-package and
  embedded image pins while leaving ordinary manifest updates with Dependabot.
  The hosted Renovate App must be installed before this configuration is
  merged; it is not active as part of this change.
- Keep vulnerability scan findings advisory and disable automatic issue
  closure while preserving stale labels.
