---
section: Behaviour changes
---

- Keycloak approver group sync now resolves a configured approver group only by its exact, case-sensitive name. Group names such as ZAM roles that differ only in case are distinct identities. A configured name that matches more than one group, including a same-named nested subgroup, fails closed with the `ApproverGroupAmbiguous` event: cached members are removed and the group is stored as an empty `status.approverGroupMembers` list, so nobody can approve through it, not even by token group claim. A group that exists only as a nested subgroup is not resolved and is reported as not found.
- Transitional opt-out: `kubernetes.approverGroupCaseInsensitiveFallback: true` accepts a unique case-insensitive match when no exact match exists. It never restores first-match resolution; several candidates still fail closed. It will be removed in a future release.
