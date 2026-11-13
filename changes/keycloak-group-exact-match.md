---
section: Behaviour changes
---

- Keycloak approver group sync now resolves a configured approver group only by its exact, case-sensitive name. Group names such as ZAM roles that differ only in case are distinct identities. A configured name that matches more than one group fails closed with the `ApproverGroupAmbiguous` event: cached members are removed and the group gets no `status.approverGroupMembers` entry, so approval by exact token group still works but no notifications are sent for that group.
- Transitional opt-out: `kubernetes.approverGroupCaseInsensitiveFallback: true` accepts a unique case-insensitive match when no exact match exists. It never restores first-match resolution; several candidates still fail closed. It will be removed in a future release.
