---
section: Behaviour changes
---

- Keycloak approver group sync now resolves a configured approver group only by its exact, case-sensitive name. Group names such as ZAM roles that differ only in case are distinct identities. A configured name that matches more than one group, including a same-named nested subgroup, fails closed with the `ApproverGroupAmbiguous` event: cached members are removed and the group is stored as an empty `status.approverGroupMembers` list, so nobody can approve through it, not even by token group claim. A group that exists only as a nested subgroup is not resolved and is reported as not found.
- New opt-in flag `--require-synced-approver-groups` (`BREAKGLASS_REQUIRE_SYNCED_APPROVER_GROUPS`, default off): approval through an approver group is denied (HTTP 403) until its members have been synced, instead of falling back to token or cluster groups. It closes the window before the first sync at the cost of possible lockout until that sync succeeds.
- When identity provider discovery fails, the escalation status updater keeps the last synced, provider-scoped approver status and reports `ApprovalGroupMembersResolved=False` (`GroupSyncFailed`) instead of switching to the legacy resolver.
- Transitional opt-out: `kubernetes.approverGroupCaseInsensitiveFallback: true` accepts a unique case-insensitive match when no exact match exists. It never restores first-match resolution; several candidates still fail closed. It will be removed in a future release.
