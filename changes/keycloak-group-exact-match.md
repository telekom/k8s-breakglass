---
section: Behaviour changes
---

- Keycloak group sync now resolves approver groups by exact, case-sensitive name first. A case-insensitive match is still used when it is the only one; names that differ only in case (for example mixed-case ZAM role groups) now fail closed like a missing group, clearing cached approver members instead of resolving the members of an arbitrary group.
