# Technical Debt Tracking

This document tracks known technical debt, TODOs, and future improvements identified in the codebase.

## High Priority

*No high priority technical debt items currently.*

**Tracking Issue:** [Create GitHub issue]

---

## Medium Priority

### 2. Migrate to NewClientset for Event Recorder Tests

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

### 3. Context.TODO() in Test Code

**Status:** ✅ Acceptable - Test code only  
**Impact:** None - Test-specific usage  
**Files:**
- `api/v1alpha1/validation_helpers_test.go` (multiple occurrences)

**Description:**
Test code uses `context.TODO()` for validation function calls. This is acceptable in test code but production code should always use proper contexts (fixed in #248).

**Action Items:**
None - test code usage is acceptable. Production code usage has been fixed.

---

## Recently Fixed

### ✅ Field Selector Performance for Debug Sessions

**Status:** ✅ Fixed (indexed lookups)  
**Impact:** Low - Optimization for scale  
**Files:**
- `pkg/breakglass/debug_session_kubectl.go`
- `pkg/indexer/indexer.go`

**Fix:**
Added controller-runtime field indexers for DebugSession cluster, state, and participant user fields, and updated DebugSession lookups to use `MatchingFields` when indexes are available.

### ✅ TMux Terminal Sharing Support (E2E Tests)

**Status:** ✅ Fixed (tmux image + tests enabled)  
**Impact:** Medium - Terminal sharing tests now run with tmux-enabled image  
**Files:**
- `e2e/images/tmux-debug/Dockerfile`
- `e2e/kind-setup-single.sh`
- `e2e/kind-setup-multi.sh`
- `e2e/kubectl_debug_test.go`
- `e2e/debug_session_e2e_test.go`
- `e2e/api/functional_verification_test.go`
- `e2e/api/debug_session_advanced_test.go`

**Fix:**
Added a tmux-enabled debug image and updated E2E templates/tests to set the tmux provider and assert terminal sharing behavior.

### ✅ Context.TODO() in Webhook Validation (CRITICAL)

**Status:** ✅ Fixed in PR #248  
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
| High     | 0     | - |
| Medium   | 1     | Refactoring |
| Low      | 1     | Acceptable |
| **Total Active** | **2** | - |
| Fixed    | 3     | ✅ Complete |

Last Updated: 2026-01-17
