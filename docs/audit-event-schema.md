<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Audit event schema (v1)

This is the consumer contract for Breakglass audit events, for example for a
SOC that reads the Kafka audit topic. The machine-readable contract is the JSON
Schema (draft 2020-12)
[`api/audit/v1/audit-event.schema.json`](../api/audit/v1/audit-event.schema.json).
Go consumers can validate with `auditv1.Validate` from
`github.com/telekom/k8s-breakglass/api/audit/v1`.

The schema describes one event as JSON. Sinks carry it as follows:

| Sink | Representation |
|---|---|
| Kafka | Each record value is one event. |
| Webhook, single write | The request body is one event. A webhook with `payloadFormat: slack` posts chat messages instead and is not covered. |
| Webhook, batch write (`batchUrl`) | The body is `{"events": [<event>, ...], "count": <n>}`; validate each element of `events`. |
| Log | The `audit_event` log line flattens selected fields (`event_id`, `event_type`, `actor_user`, ...) and encodes `details` as a JSON string. It is not covered by the schema; consume Kafka or the webhook for a schema-conformant feed. |
| Kubernetes | Kubernetes Events with a summary; not covered by the schema. |

Sink configuration is described in
[AuditConfig](audit-config.md); retries and loss accounting are described in
[Audit delivery](audit-delivery.md).

## Kafka transport

| Property | Value |
|---|---|
| Topic | `spec.sinks[].kafka.topic` of the AuditConfig. Every Kafka sink writes to exactly one topic. Several sinks, or several AuditConfigs, can deliver the same event to several topics, each with its own filters (`eventTypes`, `minSeverity`, `filtering`). The writer may create a missing topic when the broker allows auto-creation; production topics should be created and ACL-scoped in advance. |
| Record key | The event `id` (UTF-8). |
| Record value | One UTF-8 JSON event that conforms to the schema. There is no envelope around it, no batching inside a record, and no `content-type` header. |
| Headers | `event-type` (the `type`), `severity`, `timestamp` (RFC 3339, second precision; the body carries nanoseconds), `schema-version` (`v1`), and, when set, `actor` (`actor.user`, which is personal data) and `correlation-id` (`requestContext.correlationId`). Single and batched writes carry the same headers. |
| Compression | `kafka.compression`: `snappy` (default), `gzip`, `lz4`, `zstd` or `none`. Standard Kafka clients decompress this transparently. |
| Acknowledgement | `kafka.requiredAcks`: `-1` (all in-sync replicas, the default), `1` (leader) or `0` (none). |
| Batching | `kafka.batchSize` (default 100) and `kafka.batchTimeoutSeconds` (default 1 s). Synchronous writes are flushed at once. |
| Maximum record size | The broker's `message.max.bytes` applies. A record that the broker rejects as too large is a permanent failure. Its batch is halved until the single event is dropped and counted with reason `rejected`; the other events are still delivered. |

### Partitioning and ordering

Records are distributed with the kafka-go `LeastBytes` balancer. The record key
does **not** select the partition. There is therefore **no ordering
guarantee** across events, including the events of one session. Order events
by `timestamp`, and correlate them by the identifiers in `requestContext` and
`target.uid`, not by offset. Within one partition records keep their write
order. Retries and a reload handover can still write an older event after a
newer one.

### Delivery semantics

Delivery is **at least once** for synchronous Kafka sinks with broker
acknowledgements (`kafka.async: false` and `kafka.requiredAcks` `-1` or `1`,
the defaults). A failed batch is retried with the **same event IDs**, retained
past its retry window, and handed over on a configuration reload; see
[Audit delivery](audit-delivery.md). A retry after a broker timeout can write a
record twice. `kafka.requiredAcks: 0` and `kafka.async: true` are best effort:
a write can succeed without the broker having accepted the record.

Detected losses are counted in `breakglass_audit_events_dropped_total`: a full
queue, shutdown, and permanent rejection. A controller crash or kill loses the
events that are still queued or retained in memory **without** counting them.
Detect that gap on the consumer side, for example by reconciling the session
lifecycle (a `session.requested` without a terminal event) and alerting on
controller restarts.

**Deduplicate on `id`.** It is unique per event and stable across retries.
Most IDs are random UUIDs. Synchronously delivered receipts use deterministic
IDs, so a re-emission after a controller restart is also detectable:

| Events | `id` |
|---|---|
| `debug_session.hotfix.*` | `<operationID>-intent`, `<operationID>-result`, or the node operation name with `-intent` or `-result` |
| `debug_session.admission_recipe.*` | `<operationID>-intent`, `<operationID>-drift-<digest>`, `<operationID>-reverted` |
| `debug_session.node_maintenance.*` | `<operationID>-intent`, `<operationID>-result` |
| Duplicate-session cleanup (`session.termination_intent` and its legacy `session.expired` or `session.withdrawn`) | `duplicate-cleanup/<session UID>` |

## Envelope

| Field | Type | Required | PII | Description |
|---|---|---|---|---|
| `id` | string | yes | | Unique event ID; the deduplication key. |
| `schemaVersion` | string `v1` | no | | Envelope schema version. Releases before this schema did not set it; treat its absence as `v1`. |
| `type` | string | yes | | Event type; selects the `details` schema. |
| `severity` | `info`, `warning`, `critical` | yes | | Default severity per type, see `SeverityForEventType`. |
| `timestamp` | RFC 3339 date-time | yes | | When the event occurred. |
| `actor.user` | string | yes | **yes** | Email, username or service account, or `system` for controller actions. |
| `actor.identityProvider` | string | no | | Identity provider of the user. |
| `actor.groups` | string[] | no | **yes** | Verified group claims. |
| `actor.sourceIP` | string | no | **yes** | Request origin. |
| `actor.userAgent` | string | no | | Request user agent. |
| `target.kind`, `target.name` | string | yes | | Affected resource. |
| `target.uid` | string | no | | Immutable UID of the affected object, when known. |
| `target.namespace`, `target.cluster`, `target.apiGroup` | string | no | | Location of the resource. |
| `target.clusterUID` | string | no | | UID of the ClusterConfig, only when the emitter observed it. |
| `target.namespaceLabels` | map | no | | Labels of the target namespace. |
| `requestContext.correlationId` | string | no | | Groups the events of one API request or terminal stream. |
| `requestContext.sessionName`, `sessionUID` | string | no | | BreakglassSession (or DebugSession) identity. |
| `requestContext.escalationName`, `escalationUID` | string | no | | Controlling BreakglassEscalation. |
| `requestContext.debugSessionName`, `debugSessionUID` | string | no | | DebugSession identity. |
| `details` | object | no | see below | Event-type-specific payload. |

Free-text fields (`details.message`, `details.reason`) can contain whatever a
requester or approver typed, so treat them as potentially personal data.
Terminal bytes, tokens, Secret contents and credential locations are never part
of an event.

## Details per event type

The schema maps every declared event type to exactly one `details` definition
(`$defs`). A contract test fails when a new event type has no mapping.

### Breakglass sessions (`sessionLifecycle`)

`session.requested`, `session.approved`, `session.denied`, `session.rejected`,
`session.activated`, `session.expired`, `session.revoked`, `session.withdrawn`,
`session.dropped`, `session.extended`, `session.validated`,
`session.invalidated`, `session.termination_intent`

| Field | Type | PII | Description |
|---|---|---|---|
| `message` | string | | Summary of the transition. |
| `cluster` | string | | Target cluster. |
| `grantedGroup` | string | | Granted group. |
| `state` | string | | Session state after the transition. |
| `ticketSystemID` | string | | Ticket or incident reference (unverified). |
| `user`, `requestedBy` | string | **yes** | Requesting user. |
| `escalationName` | string | | Escalation. |
| `reason`, `expirationReason` | string | | Reason (code or free text). |
| `terminalState`, `terminalDecision`, `transitionCommitted` | string, string, boolean | | Duplicate-session cleanup outcome. |
| `scheduledStartTime`, `actualStartTime` | date-time or null | | Scheduled sessions. |

```json
{"id":"8d3c1c1e-6f1a-4a43-9f53-0c4f0c2a9b11","schemaVersion":"v1","type":"session.requested","severity":"info","timestamp":"2026-11-13T09:15:02.123456789Z","actor":{"user":"alice@example.com","identityProvider":"corp-oidc","groups":["/ops/platform"]},"target":{"uid":"6b8f6a1e-2f4b-4b8e-9d0e-1f2a3b4c5d6e","kind":"BreakglassSession","name":"prod-eu-1-admin-x7k2","namespace":"breakglass","cluster":"prod-eu-1"},"details":{"message":"Session requested","cluster":"prod-eu-1","grantedGroup":"cluster-admin","state":"Pending","ticketSystemID":"INC-4711","user":"alice@example.com"},"requestContext":{"correlationId":"c0ffee00-1111-2222-3333-444455556666","sessionName":"prod-eu-1-admin-x7k2","sessionUID":"6b8f6a1e-2f4b-4b8e-9d0e-1f2a3b4c5d6e","escalationName":"prod-admin","escalationUID":"0a1b2c3d-0000-4000-8000-000000000001"}}
```

`session.approval_unverified_groups` (`sessionApprovalUnverifiedGroups`): an
approval was authorized on JWT-claim groups because the cluster group lookup
failed. Fields: `message`, `cluster`, `grantedGroup`, `matchedGroup`,
`groupBasis` (`unverified_request_context`), `loadBearing`, `authorization`
(`allowed`), `ticketSystemID`.

### Debug sessions (`debugSessionLifecycle`)

`debug_session.created`, `started`, `approved`, `rejected`, `renewed`,
`validated`, `validation_failed`, `terminated`, `failed`, `expired`,
`approval_timeout`, `cleanup_failed`, `cleanup_recovered`, `binding_unresolved`

| Field | Type | PII | Description |
|---|---|---|---|
| `message` | string | | Summary of the transition. |
| `cluster` | string | | Target cluster. |
| `templateRef`, `templateName`, `template` | string | | DebugSessionTemplate. |
| `requestedBy`, `requested_by` | string | **yes** | Requesting user. |
| `state`, `previous_state` | string | | Session state after and before the transition. |
| `reason` | string | | Reason. |
| `residuals` | string[] | | Resources left behind by a failed cleanup. |
| `bindingName`, `bindingNamespace` | string | | Unresolvable DebugSessionClusterBinding. |

```json
{"id":"1f0e2d3c-4b5a-4968-8776-655443322110","schemaVersion":"v1","type":"debug_session.started","severity":"info","timestamp":"2026-11-13T09:20:00Z","actor":{"user":"alice@example.com"},"target":{"uid":"9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d","kind":"DebugSession","name":"dbg-node-a","namespace":"breakglass","cluster":"prod-eu-1"},"details":{"cluster":"prod-eu-1","templateName":"node-shell"},"requestContext":{"sessionName":"dbg-node-a","sessionUID":"9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d","debugSessionName":"dbg-node-a","debugSessionUID":"9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"}}
```

### Debug session workloads (`debugSessionWorkload`)

`debug_session.pod_failed`, `pod_restarted`, `resource_deployed`,
`resource_cleanup`. The envelope target is the Pod or deployed resource.
Fields: `debug_session`, `session_ns`, `cluster`, `failure_reason`, `message`,
`restart_count` (integer), `last_termination_reason`.

### Node maintenance, admission recipes and hotfixes

These receipts are delivered synchronously: the operation fails closed when the
event cannot be delivered. `approvedBy` is personal data.

| Definition | Event types | Fields |
|---|---|---|
| `debugSessionNodeMaintenance` | `debug_session.node_maintenance.execution_intent`, `.result` | `sessionUID`*, `operationID`*, `approvalID`, `approvedBy`, `approvedAt`, `nodeUID`, `tuple`, `image`, `dryRun`, `podUID`, `jobUID`, `leaseUID`, `result`, `bootID`, `restartPods`, `restartedPodUIDs`, `hostUnchanged` |
| `debugSessionAdmissionRecipe` | `debug_session.admission_recipe.applied`, `.drift`, `.reverted` | `sessionUID`*, `operationID`*, `action`*, `approvedBy`, `approvedAt`, `targets[]` (`target`, `state`, `original`, `applied`, `message`) |
| `debugSessionHotfix` | `debug_session.hotfix.intent`, `.node_intent`, `.node_result`, `.result` | `sessionUID`*, `stage`*, `approvedBy`, `operationID`, `recordName`, `planHash`, `payloadSHA256`, `executorImage`, `payload` (intent only), `nodes` (count, or counts per result), `nodeUID`, `beforeSHA256`, `afterSHA256`, `podUID`, `result`, `message`, `phase`, `reason`, `state` |

\* always present.

### Terminal recordings (`terminalRecording`, `terminalRecordingAccess`)

Recordings are **not** sent over Kafka. The audit events are the index of the
retained evidence: they identify the recording, its integrity digest, size,
completeness and retention. The bytes stay in the configured
[diagnostic artifact backend](diagnostic-artifacts.md) (local volume or S3) and
are read through the Breakglass API, which audits every read:
`GET /debugSessions/:name/terminal` lists and
`GET /debugSessions/:name/terminal/:id` replays one recording for an authorized
session reader; `bgctl debug recordings export` converts it to asciicast. See
[Terminal recording](terminal-recording.md). These events ignore the template's
`audit.enabled` switch and are never sampled. All events of one stream share
`requestContext.correlationId`.

| Field | Type | Events | Description |
|---|---|---|---|
| `recordingId` | string | all | Artifact ID; the replay `:id`. |
| `podNamespace`, `podName`, `podUID`, `container` | string | started, finalized, failed | Target container. |
| `operation` | `exec`, `attach` | started, finalized, failed | Terminal operation. |
| `formatVersion` | integer | started, finalized, failed | Recording framing version (2). |
| `leaseUID`, `generation` | string, string | started, finalized, failed | Connection lease. |
| `retentionExpiresAt` | date-time | started, finalized, failed | Retention deadline of the recording. |
| `frames`, `bytes`, `complete` | integer, integer, boolean | finalized, failed (finalize) | Recording size and completeness. |
| `sha256` | 64 hex digits | finalized, accessed (replay) | SHA-256 of the stored recording; compare it with a replayed copy. |
| `streamError`, `abortReason` | string, enum | finalized, failed | Aborted stream: `credential_changed`, `cluster_config_changed`, `target_changed`, `session_authority_changed`, `lease_changed`, `expired`, `client_disconnected`, `stream_failed`. |
| `stage` | `reserve`, `finalize` | failed | Failed stage. |
| `access` | `list`, `replay` | accessed | Access kind; the actor is the reader. |
| `recordingIds` | string[] | accessed (list) | Listed recordings. |

```json
{"id":"5d6e7f80-91a2-4b3c-8d4e-5f60718293a4","schemaVersion":"v1","type":"debug_session.terminal_recording_finalized","severity":"info","timestamp":"2026-11-13T09:41:17.5Z","actor":{"user":"alice@example.com","identityProvider":"corp-oidc","groups":["/ops/platform"],"sourceIP":"10.0.0.7"},"target":{"uid":"9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d","kind":"DebugSession","name":"dbg-node-a","namespace":"breakglass","cluster":"prod-eu-1"},"details":{"recordingId":"rec-01JC7Z8K2M","podNamespace":"breakglass-debug","podName":"dbg-node-a-shell","podUID":"3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f","container":"shell","operation":"exec","formatVersion":2,"leaseUID":"7e8f9a0b-1c2d-4e3f-8a4b-5c6d7e8f9a0b","generation":"3","retentionExpiresAt":"2027-02-11T09:41:17Z","frames":412,"bytes":18234,"complete":true,"sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},"requestContext":{"correlationId":"2b7e1516-28ae-4d2a-a6d2-abf7158809cf","sessionName":"dbg-node-a","sessionUID":"9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d","debugSessionName":"dbg-node-a","debugSessionUID":"9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"}}
```

```json
{"id":"6e7f8091-a2b3-4c4d-9e5f-60718293a4b5","schemaVersion":"v1","type":"debug_session.terminal_recording_accessed","severity":"info","timestamp":"2026-11-14T08:00:00Z","actor":{"user":"auditor@example.com","groups":["/security/soc"]},"target":{"uid":"9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d","kind":"DebugSession","name":"dbg-node-a","namespace":"breakglass","cluster":"prod-eu-1"},"details":{"access":"replay","recordingId":"rec-01JC7Z8K2M","sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","bytes":18234},"requestContext":{"correlationId":"4c1d2e3f-5a6b-4c7d-8e9f-0a1b2c3d4e5f","debugSessionName":"dbg-node-a","debugSessionUID":"9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"}}
```

### Authorization webhook

| Definition | Event types | Fields |
|---|---|---|
| `accessDecision` | `access.granted`, `access.denied`, `access.allowed`, `access.checked` | `allowed`, `verb`, `source`, `apiGroup`, `subresource`, `reason` |
| `accessPolicyDenial` | `access.denied.policy` | `policyName`, `policyScope`, `verb`, `apiGroup`, `subresource` |
| `policyViolation` | `policy.violation` | `policyName`, `reason` |
| `podSecurity` | `pod_security.evaluated`, `.allowed`, `.denied`, `.warning`, `.override` | `policyName`, `action`, `riskScore`, `riskFactors`, `reason`, `verb`, `apiGroup`, `subresource`, `overrideApplied` |
| `impersonation` | `resource.impersonate` | `allowed`, `impersonationVerb`, `impersonationVerbKind`, `impersonationMode`, `impersonationConstraint`, `identityResource`, `identityName` (**PII**), `identityNamespace`, `source`, `requestorUID` (**PII**), `extraKey`, `underlyingVerb`, `reason`, `legacyFallbackWarned` |

### Other declared types (`generic`)

The remaining declared types (for example `resource.*`, `secret.*`,
`config.changed`, `system.*`, `audit.*`, `nonresource.*`, and
`debug_session.command`) have no structured payload in this release. Their
`details`, when present, is an object. A later v1 revision may define it
additively.

## Versioning and compatibility

- The schema directory and `schemaVersion` carry the major version (`v1`).
- Within v1, changes are **additive only**: new optional envelope or details
  fields, new event types, and new enum values for fields documented as reason
  codes. Fields are not removed, renamed, retyped or made required.
- Consumers must ignore unknown properties and unknown event types. The
  published schema is open (it allows unknown properties). CI validates emitted
  events against a strict variant, so every field that the code emits is
  declared in the schema.
- A breaking change ships as `api/audit/v2` with `schemaVersion: v2`. During a
  migration a controller can write each version to its own topic.

CI enforces the contract:

- `pkg/audit/schema_contract_test.go` maps every `EventType` constant to a
  details definition, compares the envelope with the Go types, validates the
  Manager's emitters, rejects malformed events, and validates the examples on
  this page.
- The `pkg/breakglass` and `pkg/breakglass/debug` test doubles validate every
  event that the session, debug session, hotfix, admission-recipe,
  node-maintenance and terminal-recording code emits in its tests
  (`pkg/audit/audittest`).
- The Kafka delivery e2e (`hack/audit-delivery-kind.sh`) validates a record
  that a real broker returned, including its key and headers.

## Consuming from SOC/CDI

- **Transport security.** The sink supports TLS 1.2+ with a CA bundle
  (`kafka.tls.caSecretRef`), mutual TLS (`kafka.tls.clientCertSecretRef`), and
  SASL `PLAIN`, `SCRAM-SHA-256` or `SCRAM-SHA-512`
  (`kafka.sasl.credentialsSecretRef`). Secrets must live in the controller
  namespace. Do not use `insecureSkipVerify` in production. Consumers use their
  own principal with read-only topic ACLs.
- **Consumer group.** Use one dedicated consumer group per consuming system so
  that it receives every record independently of other readers. Scale within
  the group up to the partition count.
- **Deduplication.** Deduplicate on `id` (the record key), for example within a
  window that covers the producer retry and retention horizon
  (`queue.retryTimeoutSeconds` plus any outage that you want to bridge).
- **Ordering.** Order by `timestamp` and correlate by `requestContext.sessionUID`,
  `requestContext.debugSessionUID`, `target.uid` and
  `requestContext.correlationId`; do not rely on partition order.
- **Filtering.** Route by the `event-type` header without parsing the body.
  Validate the body with the schema at ingestion and alert on failures instead
  of dropping events.
- **Completeness.** A healthy producer connection does not prove receipt.
  Monitor `breakglass_audit_events_dropped_total`,
  `breakglass_audit_events_retained`, and sink health on the producer side, and
  reconcile by event ID on the consumer side.
