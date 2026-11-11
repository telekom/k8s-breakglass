---
section: Behaviour changes
---

- `bgctl debug kubectl inject` now sends a security context. It sets
  `allowPrivilegeEscalation: false` unless the template allows privileged
  containers; when the session template requires non-root (or the session
  cannot be read) it also sets `runAsNonRoot: true`, `runAsUser` and
  `runAsGroup` `65534`, drops all
  capabilities and uses the `RuntimeDefault` seccomp profile, so injecting into
  `requireNonRoot` templates works without flags. New flags `--run-as-non-root`,
  `--run-as-user`, `--run-as-group`, `--allow-privilege-escalation`,
  `--add-capabilities`, `--drop-capabilities` and `--security-context-file`
  change it; `--default-security-context=false` restores the old behaviour.
  Policy rejections now show the template policy and the context sent (#1666).
