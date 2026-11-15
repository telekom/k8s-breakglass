---
section: Behaviour changes
---

- Debug session notification exclusions (`notification.excludedRecipients.groups`)
  now resolve group members with the current IdentityProvider configuration,
  so a rotated Keycloak group-sync client secret is used after the next
  IdentityProvider reload instead of only after a manager restart. When group
  sync is removed from the IdentityProvider, these notifications are skipped
  (fail closed) as they are when group sync was never configured.
  `docs/identity-provider.md#rotating-client-secrets` describes the rotation
  procedure for all client secrets.
