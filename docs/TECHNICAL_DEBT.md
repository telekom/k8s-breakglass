# Technical Debt Tracking

This document tracks known technical debt, TODOs, and future improvements identified in the codebase.

## High Priority

### 1. TMux Terminal Sharing Support (E2E Tests Disabled)

**Status:** ⏸️ Blocked - Requires container image updates  
**Impact:** Medium - Feature works but E2E tests are disabled  
**Files:**
- `e2e/kubectl_debug_test.go:162`
- `e2e/kubectl_debug_test.go:217`
- `e2e/debug_session_e2e_test.go:1321`
- `e2e/api/functional_verification_test.go:557`
- `e2e/api/debug_session_advanced_test.go:248`

**Description:**
TMux terminal sharing tests are disabled because test container images don't include tmux binary.

**Action Items:**
1. Create or update debug container image with tmux installed
2. Re-enable the 5 disabled test cases
3. Document tmux requirement in debug session docs

**Tracking Issue:** [Create GitHub issue]

---

### 2. Field Selector Performance for Debug Sessions

**Status:** 🔮 Future Enhancement  
**Impact:** Low - Current implementation works, optimization for scale  
**File:** `pkg/breakglass/debug_session_kubectl.go:57`

**Description:**
```go
// TODO: Add field selector for performance in future - NOT IMPLEMENTED (requires indexer setup)
```

Currently lists all DebugSessions without filtering. For clusters with many debug sessions, this could be optimized with field selectors.

**Action Items:**
1. Set up controller-runtime field indexers for DebugSession lookups
2. Add field selector support for common query patterns (user, cluster, status)
3. Benchmark performance improvement

**Tracking Issue:** [Create GitHub issue]

---

## Medium Priority

### 3. Migrate to NewClientset for Event Recorder Tests

**Status:** 🔄 Refactoring  
**Impact:** Low - Technical debt from deprecated API  
**Files:**
- `pkg/breakglass/event_recorder_test.go:16`
- `pkg/breakglass/event_recorder_test.go:53`

**Description:**
```go
cs := fake.NewSimpleClientset() //nolint:staticcheck // TODO: migrate to NewClientset when available
```

Using deprecated `NewSimpleClientset()` - should migrate when non-deprecated alternative becomes available in client-go.

**Action Items:**
1. Monitor client-go releases for NewClientset availability
2. Update tests when migration path is clear
3. Remove staticcheck suppressions

**Tracking Issue:** [Create GitHub issue]

---

## Low Priority / Documentation

### 4. Context.TODO() in Test Code

**Status:** ✅ Acceptable - Test code only  
**Impact:** None - Test-specific usage  
**Files:**
- `api/v1alpha1/validation_helpers_test.go` (multiple occurrences)

**Description:**
Test code uses `context.TODO()` for validation function calls. This is acceptable in test code but production code should always use proper contexts (fixed in #PR_NUMBER).

**Action Items:**
None - test code usage is acceptable. Production code usage has been fixed.

---

## Recently Fixed

### ✅ Context.TODO() in Webhook Validation (CRITICAL)

**Status:** ✅ Fixed in PR #[NUMBER]  
**Impact:** High - Could cause webhook timeouts  
**File:** `api/v1alpha1/validation_helpers.go:116`

**Description:**
Production webhook validation code used `context.TODO()` as fallback when context was nil.

**Fix:**
Replaced with timeout-bounded context (`context.WithTimeout(context.Background(), 5s)`) with proper cleanup.

---

## Maintenance Guidelines

### Adding New Technical Debt Items

When adding TODO/FIXME comments in code:

1. **Use this format:**
   ```go
   // TODO(TECH-DEBT-ID): Brief description
   // See docs/TECHNICAL_DEBT.md#section for details
   ```

2. **Add entry to this document** with:
   - Clear description
   - Impact assessment
   - Action items
   - Related files

3. **Create GitHub issue** for tracking:
   - Link to this document
   - Add appropriate labels (technical-debt, enhancement, etc.)
   - Assign to appropriate milestone

### Reviewing Technical Debt

**Quarterly Review:**
- Review all open technical debt items
- Update priority based on impact
- Close completed items
- Re-assess blockers

**Before Major Releases:**
- Address all HIGH priority items
- Document any deferred items in release notes

---

## Summary Statistics

| Priority | Count | Status |
|----------|-------|--------|
| High     | 2     | 1 Blocked, 1 Future |
| Medium   | 1     | Refactoring |
| Low      | 1     | Acceptable |
| **Total Active** | **4** | - |
| Fixed    | 1     | ✅ Complete |

Last Updated: 2026-01-17
