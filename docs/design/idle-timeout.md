# Design: BreakglassSession Idle Timeout & Last Used Fields

> **Issue:** [#8](https://github.com/telekom/k8s-breakglass/issues/8)
> **Status:** Draft / Plan Only
> **Label:** `nicetohave`

## 1. Problem Statement

Breakglass system operators need:

1. **Visibility** into when a specific session (granted group) was last exercised.
2. **Automatic revocation** of approved sessions that remain unused for a configurable period (idle timeout), forcing a fresh approval cycle.

Currently `BreakglassSessionStatus` has no `LastUsedAt` or `IdleTimeout` fields. The webhook handler performs a single RBAC check across all granted groups and cannot attribute which specific group permitted the operation (see the TODO at [pkg/webhook/controller.go line 756](../pkg/webhook/controller.go#L756)).

## 2. Prior Art in the Codebase

- `DebugPodTemplateStatus.LastUsedAt` — records when the template was last used to create a debug session.
- `DebugSessionTemplateStatus.LastUsedAt` — records when the template was last used.
- The pattern uses `*metav1.Time` with SSA-compatible apply configurations (`WithLastUsedAt`).

## 3. Proposed CRD Changes

### 3.1 `BreakglassSessionSpec`

```go
// idleTimeout specifies the maximum duration a session can remain
// unused (no webhook hits) before it is automatically expired.
// Uses Go duration format (e.g. "4h", "30m").
// If not set, the session remains active for its full MaxValidFor window.
// +optional
IdleTimeout string `json:"idleTimeout,omitempty"`
```

### 3.2 `BreakglassSessionStatus`

```go
// lastUsedAt records the most recent time this session's granted group
// was exercised (successfully authorized) through the webhook.
// Updated by the webhook handler after each successful RBAC check.
// +optional
LastUsedAt *metav1.Time `json:"lastUsedAt,omitempty"`
```

### 3.3 CRD Generation

After modifying the types:

```bash
make generate && make manifests
```

This will update `zz_generated.deepcopy.go`, the CRD YAML, and the SSA apply configurations.

## 4. Webhook Changes (Last Used Tracking)

### 4.1 The Attribution Problem

The current webhook grants access based on a merged RBAC check across all groups from all active sessions. This means we know the user **is** authorized but not **which session** granted the access.

**Proposed approach — best-effort attribution:**

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

| Approach | Accuracy | Cost |
|----------|----------|------|
| Skip attribution (update all active) | Low (over-counts) | O(1) write per session count |
| Per-session RBAC re-check (proposed) | High (first match) | O(n) extra RBAC checks |
| Async batch update | Medium | O(n) writes, deferred |

**Recommendation:** Start with "update all active sessions for this user" (cheap, O(1) status patches per session). This is good enough for the idle timeout use case — a session is "used" if the user is active at all. Refine to per-group attribution later if operators need per-session granularity.

### 4.2 Write Concern

The webhook currently only reads `BreakglassSession` CRDs. Updating `LastUsedAt` introduces a write on every authorized request. Mitigations:

- **Debounce:** Only update if the current `LastUsedAt` is older than a threshold (e.g. 5 minutes). This reduces writes from potentially every API call to at most 1 per 5 min per session.
- **Async fire-and-forget:** Update in a goroutine to avoid adding latency to the webhook response path.
- **SSA patch:** Use Server-Side Apply to avoid conflicts with the session controller.

```go
func (wc *WebhookController) updateLastUsed(ctx context.Context, session *v1alpha1.BreakglassSession) {
    now := metav1.Now()
    if session.Status.LastUsedAt != nil &&
       now.Sub(session.Status.LastUsedAt.Time) < 5*time.Minute {
        return // debounce
    }
    go func() {
        // SSA status patch with field manager "breakglass-webhook"
        applyConfig := ssa.BreakglassSessionStatusApply(session).
            WithLastUsedAt(now)
        if err := wc.client.Status().Patch(ctx, session, applyConfig); err != nil {
            wc.log.Warnw("Failed to update LastUsedAt", "session", session.Name, "error", err)
        }
    }()
}
```

## 5. Controller Changes (Idle Expiry)

### 5.1 Reconciliation Logic

In the session controller's reconcile loop, after confirming a session is in `Approved` / `Active` state:

```go
if spec.IdleTimeout != "" {
    idleTimeout, err := time.ParseDuration(spec.IdleTimeout)
    if err != nil {
        // Log and skip — malformed idle timeout should not crash reconciliation
        log.Warnw("Invalid idleTimeout", "session", session.Name, "value", spec.IdleTimeout)
    } else {
        lastUsed := session.Status.LastUsedAt
        if lastUsed == nil {
            lastUsed = &session.Status.ApprovedAt // fallback: treat approval as first "use"
        }
        if time.Since(lastUsed.Time) > idleTimeout {
            // Transition to IdleExpired state
            return r.transitionToIdleExpired(ctx, session)
        }
        // Requeue for next idle check
        requeueAfter := idleTimeout - time.Since(lastUsed.Time)
        return ctrl.Result{RequeueAfter: requeueAfter}, nil
    }
}
```

### 5.2 New Session State

Add a new state constant:

```go
const SessionStateIdleExpired BreakglassSessionState = "IdleExpired"
```

Add a corresponding condition type:

```go
const ConditionIdle = "Idle"
```

When idle-expired:
- Set condition `Idle` to `True` with reason `"IdleTimeoutExceeded"`.
- Transition session state to `IdleExpired`.
- Clean up RBAC bindings (same as normal expiry).

### 5.3 Frontend Display

Add `IdleExpired` to the status tag mapping and session state options in the frontend. Display `LastUsedAt` in the session detail view if available.

## 6. Validation

### 6.1 Admission Webhook

- Validate `idleTimeout` is a parseable Go duration if set.
- Validate `idleTimeout` ≤ `maxValidFor` (idle timeout should not exceed session lifetime).

### 6.2 Unit Tests

- `TestIdleTimeoutParsing` — valid/invalid duration strings.
- `TestLastUsedAtDebounce` — updates are skipped within the debounce window.
- `TestIdleExpiryReconcile` — session transitions to `IdleExpired` when unused past timeout.
- `TestIdleFallbackToApprovedAt` — when `LastUsedAt` is nil, `ApprovedAt` is used.
- `TestNoIdleTimeout` — sessions without `idleTimeout` spec are unaffected.

## 7. Migration & Backward Compatibility

- Both new fields are optional (`omitempty`). Existing sessions are unaffected.
- `LastUsedAt` starts as `nil` for existing sessions. The idle check falls back to `ApprovedAt`.
- No breaking CRD version change needed (`v1alpha1` remains).

## 8. Open Questions

1. **Should `IdleExpired` sessions be re-approvable,** or must the user create a new request?
2. **Should idle timeout be configurable per-escalation** (in `EscalationPolicy`), per-session (in `BreakglassSessionSpec`), or both?
3. **Debounce interval** — 5 minutes is a starting point. Should this be configurable?
4. **Audit implications** — should idle expiry emit a Kubernetes event or audit log entry?

## 9. Implementation Order

1. CRD changes (`api/v1alpha1/breakglass_session_types.go`) + codegen
2. Webhook `LastUsedAt` tracking (with debounce)
3. Controller idle expiry reconciliation
4. Admission validation for `idleTimeout`
5. Frontend status display
6. Unit + integration tests
7. Documentation update
