<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Diagnostic artifact backend and durable lifecycle plan

This document describes the next implementation slice after the artifact
primitives in [PR #1279](https://github.com/telekom/k8s-breakglass/pull/1279).
It is a plan and acceptance contract, not a claim that the backend or the
Breakglass API is implemented.

## Goal and boundaries

The backend shall let an approved diagnostic collector upload one immutable
artifact, allow an authorized reader to download it, and remove it when its
retention contract ends. The same lifecycle must work with an S3-compatible
object store and with the reviewed single-replica local/PVC store. A caller
must never be able to select an arbitrary image, command, bucket key, or
storage credential.

This plan covers:

- an S3 adapter implementing the `storage.Store` interface in
  `pkg/artifacts/storage/storage.go`;
- authenticated, resumable-safe upload and download operations;
- durable artifact metadata and monotonic lifecycle state;
- a bounded operation outbox for retries and restart recovery;
- API and controller integration, including quotas and authorization;
- fault-injection, concurrency, and lifecycle acceptance tests.

It does not cover collector image publication, arbitrary script execution,
the user interface or CLI, a new CRD without an approved API shape, a
multi-replica local backend, cross-region replication, backup policy, or
production rollout. The artifact feature remains disabled until the complete
path is reviewed and its integration gates pass.

## S3 adapter contract

The adapter must use a configured endpoint, bucket, and credential reference;
these values are administrator-owned. It must not accept endpoint, bucket,
credential, or object-key overrides from an HTTP request or Kubernetes
resource. Object keys are generated from validated server-side identifiers.

The implementation shall:

1. establish and document its consistency posture, including a startup
   sentinel identity check so that two configurations cannot silently share a
   bucket prefix;
2. publish an object with one conditional create operation and reject an
   existing key whose identity or digest differs;
3. list, read, and delete by exact version/identity, never by a caller-chosen
   prefix or a mutable display name;
4. reconcile an acknowledged upload whose response was lost, accepting it
   only when size, digest, and metadata match the pending operation;
5. require two independent empty-inventory observations before declaring a
   cleanup target absent when the provider can return incomplete inventory;
6. bound object size, metadata, pagination, retries, and request deadlines;
7. classify authentication, permission, throttling, transient transport, and
   integrity errors separately for retry and audit purposes.

The adapter must expose no delete or overwrite primitive that bypasses the
metadata and authorization layer. Credentials are loaded through the
administrator-configured secret mechanism and are never logged or returned
in API errors.

## Durable state and outbox

Each artifact record must contain an immutable artifact identifier, session
and target identity, generation, exact size and digest, storage identity,
creation/expiry timestamps, and a monotonic lifecycle state. State transitions
must be validated server-side; retries and controller restarts cannot move a
record backwards or turn an unknown result into success.

The initial state machine should distinguish at least `Pending`, `Uploading`,
`Available`, `Deleting`, `Deleted`, `Expired`, `Revoked`, and `Unknown` (the
final names belong to the approved API shape). `Unknown` is the safe result of
an ambiguous provider response. Terminal evidence and audit metadata remain
available for their retention period even after the object is removed.

An outbox entry shall record the operation kind, artifact identity, expected
generation, attempt number, lease owner/expiry, and a bounded error summary.
Claiming is lease-based and idempotent. A worker may make at most three
provider attempts for one entry before recording a terminal/manual-review
outcome. Cleanup has fixed capacity for evidence and does not allow an
unbounded retry queue. Reconciliation after restart must use the stored
identity and digest and must not replay an expired, revoked, or ambiguous
mutation blindly.

All state and outbox writes must be conditional on the expected resource
version. Concurrent upload, expiry, revoke, and cleanup operations must
produce one monotonic result and an auditable conflict, not a lost update.

## Authorization, API, and controller dependencies

The API must authenticate the caller before reading artifact metadata or
bytes. Authorization is evaluated against the live session, target, and
artifact state for every upload-part/finalize, download, retry, revoke, and
delete operation. Expiry and revocation are deny-by-default even when an
informer cache is stale. Error responses must not disclose whether an
unauthorized artifact exists.

The controller/API seam must be agreed before adding fields or generated
resources. It must define:

- the request-to-session and target binding;
- approved collector intent and immutable digest requirements;
- maximum artifact count and bytes per session/tenant, with atomic quota
  reservations and reconciliation of abandoned reservations;
- retention, expiry, revocation, and deletion ownership;
- status and audit fields that are safe to expose;
- RBAC, secret references, metrics, and operational alerts.

The controller must enqueue durable work rather than relying on an in-memory
goroutine. It must release reservations on every failure path and make
shutdown/restart recovery observable.

## Fault and behavior tests

Before enabling the feature, tests must cover behavior rather than source
shape:

- conditional duplicate upload, digest/size mismatch, and lost upload
  response reconciliation;
- pagination, delayed visibility, transient errors, throttling, auth failure,
  timeout, and delete failure in the S3 adapter;
- exact-version read/delete and the two-empty-inventory cleanup proof;
- concurrent distinct-key quota admission, duplicate reservation, and
  reservation release after cancellation;
- monotonic transitions under concurrent upload, expiry, revoke, retry, and
  controller restart;
- lease expiry, three-attempt exhaustion, bounded cleanup evidence, and
  ambiguous-result handling;
- authorization for owner, approver, administrator, unrelated caller, and
  expired/revoked sessions, including cache-stale denial;
- local-backend and S3 contract parity using the same lifecycle tests;
- API/controller integration with exact digest, audit events, metrics, and
  no secret or object-key leakage in logs/errors.

Race tests, focused unit tests, API tests, and an isolated S3-compatible fault
environment are required. A green local unit suite is not cluster-runtime
proof; the CI integration lane must record the provider, image/digest, and
the exact test head.

## Rollout, rollback, and acceptance gates

The rollout is staged: merge the adapter/state primitives, run contract and
fault tests, deploy with the feature disabled, then enable only for an
explicit development/rolling cohort. Every published collector and utility
image must be independently approved and pinned by digest before
an enabled environment consumes it.

Acceptance requires all of the following:

1. design/API/controller shape is reviewed;
2. generated API files and manifests are produced by repository targets;
3. S3 and local implementations pass the common contract and race tests;
4. quotas, authorization, expiry, revocation, restart recovery, and cleanup
   pass the fault matrix with no secret leakage;
5. exact-head CI is green, including lint, unit, API/controller, and the
   permitted integration environment;
6. documentation, changelog, RBAC, metrics, and rollback runbook match the
   shipped behavior; and
7. a review records the immutable artifact/image digests and confirms that no
   production rollout or publication occurred during this plan phase.

Rollback disables new artifact requests, drains or quarantines pending
outbox work, and preserves terminal audit evidence. It must not delete objects
solely because the controller was rolled back. Any destructive cleanup is
resumed only after the same identity and authorization checks pass.
