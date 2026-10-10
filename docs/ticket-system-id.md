<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Ticket system ID

Session creation optionally accepts a freeform `ticketSystemID` string:

```json
{
  "cluster": "example",
  "group": "temporary-reader",
  "reason": "Investigate a service disruption",
  "ticketSystemID": "operations/example-123"
}
```

The value is preserved verbatim in `BreakglassSession.spec.ticketSystemID`.
There is no required format, regex, length policy or external ticket lookup.
Omitting it preserves existing behavior. This is an **unverified, audit-only
reference**, not an authorization credential, approval, or proof of an incident.
Existing authentication, authorization, reason and approval policies still apply.

The request dialog has an optional **Ticket system ID** field. Approvers see
the unverified value in the approval dialog. Vue text interpolation escapes
user-supplied values; they are never interpreted as HTML or executable content.
The immutable session spec keeps the original value after approval and expiry.

```bash
bgctl session request --cluster example --group temporary-reader \
  --reason "Investigate a service disruption" \
  --ticket-system-id "operations/example-123"
bgctl session get SESSION -o yaml
```

Session lifecycle audit events contain `details.ticketSystemID`. Session creation
also writes a structured log field `ticketSystemID`; treat it as untrusted text.
Do not put credentials or personal information in this field. Audit delivery
and retention depend on the deployment's configured audit sinks.

No per-escalation format knob or enforcement is introduced. Future enforcement
requires a separately reviewed policy and migration; this audit field must not
be counted as enforced incident approval compliance.
