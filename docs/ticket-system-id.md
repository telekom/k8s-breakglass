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
It is limited to 256 characters (Unicode code points); longer values are
rejected with `422 Unprocessable Entity` by the API, by the CRD schema
(`maxLength: 256`), by `bgctl` before sending, and by the request dialog.
There is no required format, regex or external ticket lookup.

Upgrading from v0.3.0-rc.10 (the first release with this field): Kubernetes
1.30+ keeps unchanged longer values valid through CRD validation ratcheting. On
older hub clusters, updates to the main resource of a session whose reference
exceeds 256 characters (for example metadata or finalizer changes) are rejected
because the immutable spec cannot be shortened; `/status` updates are not
affected. Let such sessions expire or delete them before applying the new CRD.
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
