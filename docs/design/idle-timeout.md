# Design: BreakglassSession Idle Timeout & Last Used Fields

> **Issues:** [#8](https://github.com/telekom/k8s-breakglass/issues/8), [#312](https://github.com/telekom/k8s-breakglass/issues/312), [#314](https://github.com/telekom/k8s-breakglass/issues/314)
> **Status:** Implemented
> **Label:** `nicetohave`

## 1. Problem Statement

Breakglass system operators need:

1. **Visibility** into when a specific session (granted group) was last exercised.
2. **Automatic revocation** of approved sessions that remain unused for a configurable period (idle timeout), forcing a fresh approval cycle.

Before this PR, `BreakglassSessionStatus` had no activity tracking or idle timeout fields. The webhook handler performs a single RBAC check across all granted groups; per-session attribution is achieved by re-checking each session individually after the combined check (see the NOTE at [pkg/webhook/controller.go lines 756–758](../../pkg/webhook/controller.go#L756-L758)). This PR adds `idleTimeout` to spec and `lastActivity`/`activityCount` to status.

> **Note:** Duration strings in this project use `api/v1alpha1.ParseDuration` (which supports day units like `"1d12h"`) rather than `time.ParseDuration`. All references below use the shared helper.

## 2. Prior Art in the Codebase

- `DebugPodTemplateStatus.LastUsedAt` — records when the template was last used to create a debug session.
- `DebugSessionTemplateStatus.LastUsedAt` — records when the template was last used.
- The pattern uses `*metav1.Time` with SSA-compatible apply configurations (`WithLastUsedAt`).

## 3. Proposed CRD Changes

### 3.1 `BreakglassSessionSpec`

```go
// idleTimeout specifies the maximum duration a session can remain
// unused (no webhook hits) before it is automatically expired.
// Duration format, e.g. "4h", "30m", "1d".
// Parsed via api/v1alpha1.ParseDuration (supports day units).
// If not set, the session remains active for its full MaxValidFor window.
// +optional
IdleTimeout string `json:"idleTimeout,omitempty"`
```

### 3.2 `BreakglassSessionStatus`

```go
// lastActivity records the most recent time this session's granted group
// was exercised (successfully authorized) through the webhook.
// Updated by the ActivityTracker via buffered flush after each successful RBAC check.
// +optional
LastActivity *metav1.Time `json:"lastActivity,omitempty"`

// activityCount records the total number of webhook authorizations
// attributed to this session.
// +optional
ActivityCount int64 `json:"activityCount,omitempty"`
```

### 3.3 CRD Generation

After modifying the types:

```bash
make generate && make manifests
```

This will update `zz_generated.deepcopy.go`, the CRD YAML, and the SSA apply configurations.

## 4. Webhook Changes (Last Used Tracking)

### 4.1 The Attribution Problem

The current webhook grants access based on a merged RBAC check across all groups from all active sessions. After the combined check succeeds, the implementation iterates over each active session's groups individually to attribute which sessions contributed.

**Implemented approach — per-session attribution with buffered writes:**

After the combined RBAC check succeeds, iterate over the active sessions' groups individually:

```go
// After confirming can == true:
for _, session := range activeSessions {
    groups := []string{session.Spec.GrantedGroup}
    if canSingle, _ := wc.canDoFn(ctx, rc, groups, sar, clusterName); canSingle {
        // This session contributed — update LastUsedAt
        wc.updateLastUsed(ctx, session)
        break // attribute to first matching session
    }
}
```

**Trade-offs:**

| Approach | Accuracy | Extra SAR checks | Status writes |
|----------|----------|------------------|---------------|
| Skip attribution (update all active) | Low (over-counts) | O(1) combined check only | O(n) per request (one write per active session, debounced) |
| Per-session RBAC re-check (proposed) | High (first match) | O(n) extra SAR checks | O(1) per request (update only the attributed session) |
| Async batch update | Medium | O(1) combined check only | O(n) per batch, off the webhook critical path |

**Recommendation:** The implementation uses per-session attribution (re-check each session individually) with buffered writes via the `ActivityTracker`. Activity is recorded in-memory and flushed to the API server every 30 seconds using optimistic-concurrency status merge-patch (`client.MergeFrom` + `retry.RetryOnConflict`), avoiding hot-path latency while still providing per-session granularity.

### 4.2 Write Concern

The webhook records activity through the `ActivityTracker` which batches writes. Mitigations:

- **Buffered writes:** The `ActivityTracker` accumulates activity records in-memory and flushes every 30 seconds, collapsing multiple requests into a single status update per session.
- **Background flush:** Flush runs in a background goroutine to avoid adding latency to the webhook response path. Failed flushes are re-queued with merge logic (latest timestamp, summed counts) up to 5 retries.
- **Status merge-patch:** Use optimistic-concurrency status merge-patch (`client.MergeFrom` + `retry.RetryOnConflict`) to avoid lost updates across replicas.

```go
// ActivityTracker.RecordActivity records an activity event for the named session.
// The event is buffered in-memory and flushed to the API server periodically.
func (at *ActivityTracker) RecordActivity(namespace, name string, ts time.Time) {
    at.mu.Lock()
    defer at.mu.Unlock()
    key := types.NamespacedName{Namespace: namespace, Name: name}
    entry, exists := at.entries[key]
    if !exists {
        if len(at.entries) >= maxEntries {
            return // cap map size to prevent unbounded growth
        }
        at.entries[key] = &activityEntry{
            namespace: namespace, name: name,
            lastSeen: ts, count: 1,
        }
        return
    }
    if ts.After(entry.lastSeen) {
        entry.lastSeen = ts
    }
    entry.count++
}
```

## 5. Controller Changes (Idle Expiry)

### 5.1 Reconciliation Logic

In the idle expiry controller (`ExpireIdleSessions`), for each approved session:

```go
if spec.IdleTimeout != "" {
    idleTimeout, err := v1alpha1.ParseDuration(spec.IdleTimeout)
    if err != nil {
        // Log and skip — malformed idle timeout should not crash reconciliation
        log.Warnw("Invalid idleTimeout", "session", session.Name, "value", spec.IdleTimeout)
    } else {
        lastUsed := session.Status.LastActivity
        if lastUsed == nil || lastUsed.IsZero() {
            continue // no activity recorded yet — skip to avoid false positives
        }
        if time.Since(lastUsed.Time) > idleTimeout {
            // Transition to IdleExpired state
            return r.transitionToIdleExpired(ctx, session)
        }
    }
}
```

### 5.2 New Session State

Add a new state constant:

```go
const SessionStateIdleExpired BreakglassSessionState = "IdleExpired"
```

Reuse the existing idle condition type:

- Condition type: `SessionConditionTypeIdle` (already defined in `api/v1alpha1/breakglass_session_types.go`).

When idle-expired:
- Set condition `SessionConditionTypeIdle` to `True` with reason `"IdleTimeout"`.
- Transition session state to `IdleExpired`.
- Update `isValidBreakglassSessionStateTransition` to allow `SessionStateApproved` → `SessionStateIdleExpired`.
- Clean up RBAC bindings (same as normal expiry).

### 5.3 Frontend Display

Add `IdleExpired` to the status tag mapping and session state options in the frontend. Display `lastActivity` and `activityCount` in the session detail view if available.

## 6. Validation

### 6.1 Admission Webhook

- Validate `idleTimeout` is parseable via `v1alpha1.ParseDuration` if set.
- Validate `idleTimeout` ≤ `maxValidFor` (idle timeout should not exceed session lifetime).

### 6.2 Unit Tests

- `TestExpireIdleSessions` — session transitions to `IdleExpired` when idle beyond timeout; sessions within timeout are skipped.
- `TestExpireIdleSessions_SendsEmail` — idle expiry triggers email notification.
- `TestExpireIdleSessions_EdgeCases` — sessions without `idleTimeout` or without `lastActivity` are skipped (no false positives).
- `TestExpireIdleSessions_ZeroLastActivity` — zero-value `lastActivity` is treated as unset.
- `TestExpireIdleSessions_RetrySucceedsOnSecondAttempt` — status update retries on conflict.
- `TestExpireIdleSessions_AllRetriesExhausted` — error logged after max retries.
- `TestExpireIdleSessions_ConcurrentTransitionDuringRetry` — stops retrying if another process already transitioned the session.

## 7. Migration & Backward Compatibility

- Both new fields are optional (`omitempty`). Existing sessions are unaffected.
- `lastActivity` starts as `nil` for existing sessions. The idle check skips sessions without `lastActivity` to avoid false positives.
- No breaking CRD version change needed (`v1alpha1` remains).

## 8. Resolved Questions

1. **Should `IdleExpired` sessions be re-approvable?** No — `IdleExpired` is a terminal state. The user must create a new request.
2. **Should idle timeout be configurable per-escalation or per-session?** Both. `idleTimeout` is set on `BreakglassEscalation` and automatically copied to `BreakglassSessionSpec` when a session is approved. This allows operators to configure idle timeouts per escalation policy while still allowing per-session inspection.

## 9. Implementation Notes

The implementation differs from the original proposal in the following ways:

- **Field naming:** `lastUsedAt` was renamed to `lastActivity` (with `activityCount`) to better reflect the buffered activity tracking model.
- **Attribution approach:** Activity is tracked per matching session only: the webhook attributes activity to the specific session returned by `authorizeViaSessions` (first matching session). Activity is recorded via a buffered `ActivityTracker` with 30s flush interval.
- **Optimistic concurrency:** Status updates use retry-on-conflict merge-patches to safely handle concurrent flushes from multiple replicas.
- **Re-queue on failure:** Failed flushes are re-queued with merge logic (latest timestamp, summed counts) up to 5 retries instead of simple fire-and-forget.
- **Idle baseline:** The idle expiry controller uses `lastActivity` only; sessions where `lastActivity` is nil (no activity recorded yet) are skipped to avoid false positives (the design proposed a fallback chain through `actualStartTime` > `approvedAt`).
- **Monotonic status validation:** `ValidateUpdate` in the validating webhook enforces that `status.activityCount` never decreases and `status.lastActivity` never regresses. This is defense-in-depth for full-object updates (e.g., `kubectl edit`); internal controllers use the status subresource (`client.Status().Patch`), which bypasses admission webhooks. The primary monotonic guarantee for controller writes is the in-code merge logic in `ActivityTracker.updateSessionActivity`.
