# Breakglass Controller - AI Coding Instructions

## Architecture Overview

Go-based Kubernetes controller (controller-runtime) + Vue/TypeScript frontend (Vite). Hub-and-spoke topology where a central breakglass service manages temporary privilege escalations across multiple Kubernetes clusters.

**Core Components:**
- `cmd/main.go` — Entry point with 5 deployment patterns (monolith, webhook-only, api-only, frontend-only, cleanup-only)
- `api/v1alpha1/` — CRD types with kubebuilder markers + admission webhooks
- `pkg/breakglass/` — Session/escalation business logic, approval workflows, cleanup routines
- `pkg/api/` — Gin HTTP server, REST endpoints (shared with frontend)
- `pkg/webhook/` — Kubernetes authorization webhook (SubjectAccessReview)
- `pkg/reconciler/` — Controller-runtime manager, metrics, health probes, indexers
- `frontend/` — Vue 3 + Vite web application

**CRD Resources:** `BreakglassEscalation`, `BreakglassSession`, `ClusterConfig`, `IdentityProvider`, `MailProvider`, `DenyPolicy`, `DebugSession`, `DebugSessionTemplate`, `DebugPodTemplate`

## Essential Developer Workflows

```bash
# After modifying api/v1alpha1/*.go types - ALWAYS run both:
make generate    # DeepCopy methods (zz_generated.deepcopy.go)
make manifests   # CRDs, webhooks, RBAC in config/crd/bases/

# Testing & linting
make test        # Unit tests (excludes e2e)
make lint        # golangci-lint (auto-installs to ./bin)

# Local development (kind cluster)
make docker-build-dev
kind create cluster
kind load docker-image breakglass:dev
make install       # Install CRDs
make deploy_dev    # Deploy with Keycloak + MailHog

# Full e2e environment
make e2e           # Runs e2e/kind-setup-single.sh

# Frontend development
cd frontend
npm run dev:mock   # Mock API, no backend needed
npm run dev        # Against real backend (port 5173 → 8080)
npm test           # Vitest
```

## Critical Conventions

1. **CRD Changes**: Edit `api/v1alpha1/*_types.go`, run `make generate && make manifests`, commit generated files (`zz_generated.deepcopy.go`, `config/crd/bases/*.yaml`).

2. **Webhooks**: Use `//+kubebuilder:webhook` markers. Cert generation at startup (`pkg/cert/`). Check `config/webhook/` for kustomize overlays.

3. **Required CRs**: `IdentityProvider` and `MailProvider` CRDs must exist for normal operation. Tests/local runs expect these.

4. **Component Flags**: Environment variables or CLI flags control components:
   - `ENABLE_FRONTEND`, `ENABLE_API`, `ENABLE_WEBHOOKS`, `ENABLE_CLEANUP`
   - `WEBHOOKS_METRICS_BIND_ADDRESS` for separate webhook metrics

5. **Client Usage**: Prefer `reconcilerMgr.GetClient()` (cached) for reads; uncached clients for webhooks/startup (see `cmd/main.go`).

6. **Tooling**: Local tools in `./bin/` via Makefile. Use `make kustomize`, `make controller-gen` for pinned versions.

7. **Linting (MANDATORY)**: Before submitting any code changes:
   - Run `make lint` and fix ALL errors before committing
   - Use `http.MethodGet`, `http.MethodPost`, etc. instead of string literals like `"GET"`, `"POST"`
   - Remove unnecessary type conversions (e.g., `string(x) == string(y)` when types are compatible)
   - CI will reject PRs with lint failures
   - For frontend changes: Run `cd frontend && npm run lint` and fix errors
    - For frontend changes: Run `cd frontend && npm run typecheck` (or `npm run build`) to catch TS/template errors
    - For frontend changes: Run `cd frontend && npm test` and fix failing unit tests before opening PRs

8. **Documentation (MANDATORY)**: Documentation MUST be updated with every code change:
   - API changes → Update `docs/api-reference.md` with endpoint signatures, request/response formats
   - CRD changes → Update relevant docs in `docs/` (e.g., `breakglass-session.md`, `cluster-config.md`)
   - New features → Add to `docs/advanced-features.md` or create new doc, update `docs/README.md` index
   - Configuration changes → Update `docs/configuration-reference.md` and `docs/cli-flags-reference.md`
   - Helm chart changes → Update `charts/escalation-config/README.md` and inline `values.yaml` comments
   - **CHANGELOG updates** → Update `CHANGELOG.md` for every user-facing change (see below)

9. **CHANGELOG Updates (MANDATORY)**: Every PR with user-facing changes MUST update `CHANGELOG.md`:
   - Add entries under `## [Unreleased]` section in the appropriate category
   - Categories: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`
   - Format: `- Brief description of change (PR #123)` - include PR number when available
   - New features → `Added`
   - Breaking changes → `Changed` with migration notes
   - Bug fixes → `Fixed`
   - Security patches → `Security`
   - Dependency updates → Generally skip unless security-related or breaking
   - When releasing: Move `Unreleased` content to new version section with date
   - Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format

10. **Unit Tests (MANDATORY)**: Every code change MUST include unit tests:
   - Go code → Add/update `*_test.go` files colocated with source (min 70% coverage for new code)
   - API endpoints → Test success cases, error cases, validation, authorization
   - Controllers/reconcilers → Test reconciliation logic, status updates, error handling
   - Webhooks → Test validation, mutation, rejection scenarios
   - Frontend → Add/update tests in `frontend/tests/` (Vitest), test components, composables, stores
    - Run `make test` for Go, `cd frontend && npm test` for frontend before committing
    - When refactoring shared frontend helpers, update and re-run unit tests that assert helper behavior
    - For frontend changes touching Vue/TS templates: also run `cd frontend && npm run typecheck`
   - Critical paths require table-driven tests with multiple scenarios

11. **Helm Chart Updates (MANDATORY)**: When adding/modifying CRD fields or configuration:
    - Update `charts/escalation-config/templates/*.yaml` to expose new fields
    - Add examples to `charts/escalation-config/values.yaml` with inline comments
    - Use conditional rendering (`{{- if .Values.field }}`) for optional fields
    - Test with `helm lint charts/escalation-config` and `helm template test charts/escalation-config`
    - For breaking changes, increment chart `version` and add upgrade notes to chart README
    - Ensure all new CRD fields are accessible via helm values

## Key File References

| Area | Files |
|------|-------|
| API types & webhooks | `api/v1alpha1/*_types.go`, `validation_helpers.go` |
| Deployment patterns | `cmd/main.go` (DEPLOYMENT PATTERNS comment block) |
| Session lifecycle | `pkg/breakglass/session_controller.go`, `cleanup_task.go` |
| Escalation logic | `pkg/breakglass/escalation_manager.go`, `escalation_controller.go` |
| Debug sessions | `pkg/breakglass/debug_session_*.go`, `api/v1alpha1/debug_session_types.go` |
| REST API | `pkg/api/server.go`, handlers in `pkg/api/` |
| Cluster connectivity | `pkg/cluster/client_provider.go` |
| Policy evaluation | `pkg/policy/evaluator.go` |
| Dev environment | `config/dev/`, `e2e/kind-setup-single.sh` |
| Helm chart | `charts/escalation-config/` |

## Testing Patterns

- Unit tests colocated: `*_test.go` alongside source
- Fuzz tests: `api/v1alpha1/fuzz_test.go`, `pkg/breakglass/fuzz_test.go`
- Frontend: `frontend/tests/`, `npm test` (Vitest)
- E2E: `make e2e` sets up kind + deps (manual test execution)

### E2E Test Session Creation (CRITICAL)

**ALWAYS use the API to create BreakglassSession and DebugSession resources in e2e tests.**

DO NOT use direct Kubernetes client creation (`cli.Create(ctx, &session)`) except for:
1. Webhook validation tests (testing that invalid data is rejected)
2. Controller behavior tests that need specific internal states (e.g., already-expired timestamps)

**Correct pattern for session creation:**
```go
tc := helpers.NewTestContext(t, ctx)
requesterClient := tc.RequesterClient()
approverClient := tc.ApproverClient()

// Create via API
session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
    Cluster: clusterName,
    User:    helpers.TestUsers.Requester.Email,
    Group:   escalation.Spec.EscalatedGroup,
    Reason:  "Test reason",
})
require.NoError(t, err)

// Add to cleanup (need to create minimal object for cleanup helper)
cleanup.Add(&telekomv1alpha1.BreakglassSession{
    ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
})

// Wait for expected state
helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, 
    telekomv1alpha1.SessionStatePending, 30*time.Second)

// Approve via API (if needed)
err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, session.Namespace)
require.NoError(t, err)
```

**For DebugSession:**
```go
session, err := requesterClient.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
    Cluster:     clusterName,
    TemplateRef: "template-name",
    Reason:      "Debug test",
})
```

**Key API helpers:** `e2e/helpers/api.go`
- `CreateSession()`, `MustCreateSession()`
- `CreateDebugSession()`, `MustCreateDebugSession()`
- `ApproveSessionViaAPI()`, `RejectSessionViaAPI()`
- `TerminateDebugSessionViaAPI()`

### Status Subresource Testing (CRITICAL)

All CRDs with `// +kubebuilder:subresource:status` marker (e.g., `ClusterConfig`, `DebugSession`, `IdentityProvider`) require special handling:

**For production code:**
- MUST use `Client.Status().Update(ctx, obj)` to update status fields
- Using `Client.Update(ctx, obj)` will silently ignore status changes when status subresource is enabled
- This is a common bug pattern that's hard to detect because `Update()` succeeds without error

**For unit tests with fake client:**
- MUST configure fake client with `WithStatusSubresource()` for any CRD that has status subresource enabled:
  ```go
  client := fake.NewClientBuilder().
      WithScheme(Scheme).
      WithObjects(myObj).
      WithStatusSubresource(&v1alpha1.ClusterConfig{}).  // Required!
      Build()
  ```
- Without this, `Status().Update()` will fail silently in tests
- See `pkg/breakglass/cluster_config_checker_test.go` for example helper function `newTestFakeClient()`

**Testing status updates:**
- Always verify status was persisted by reading the object back after update
- Test status transitions (e.g., from Failed to Ready)
- Verify `ObservedGeneration` matches the current `Generation`

## Integration Points

- **Frontend ↔ API**: Gin server in `pkg/api/`, frontend proxies `/api/*` to backend. Update `docs/api-reference.md` when changing endpoints.
- **Cluster Cache**: `pkg/cluster/` watches `ClusterConfig` and kubeconfig Secrets for automatic refresh.
- **Metrics**: Prometheus metrics in `pkg/metrics/`. API and webhook servers can have separate metrics ports.

## Common Mistakes to Avoid (CRITICAL)

### 1. Duplicate Import Headers in Go Files
When creating or editing Go files:
- **ALWAYS read the existing file first** before adding imports
- Check if the `import` block already exists - do NOT create a second one
- When adding imports, merge them into the existing import block
- Go files can only have ONE import block - duplicate headers cause syntax errors

### 2. API Types - Read First, Code Second
Before modifying or using CRD types:
- **ALWAYS read `api/v1alpha1/*_types.go` first** to understand the actual struct fields
- Check the exact field names, types, and JSON tags before writing code that uses them
- Do not assume field names - they may differ from what you expect (e.g., `ClusterConfigRefs` vs `ClusterRefs`)
- Look at existing validation in `*_webhook.go` files before adding new validation logic
- Check `validation_helpers.go` for reusable validation functions

### 3. Go File Structure
When creating new Go files, ensure correct structure:
```go
// Package comment (if needed)
package pkgname

import (
    // standard library first
    "context"
    "fmt"
    
    // external packages second
    "github.com/gin-gonic/gin"
    
    // internal packages last
    "github.com/telekom/breakglass/api/v1alpha1"
)

// Code follows...
```

### 4. Before Writing Any Code (CHECKLIST)
1. Read the relevant `*_types.go` file to understand the API
2. Read existing similar implementations in the codebase
3. Check for helper functions that already exist
4. Verify import paths by looking at similar files
5. Plan unit tests - what scenarios need coverage?
6. Identify documentation that needs updating
7. Check if helm chart needs updates for new fields

### 5. After Writing Code (CHECKLIST)
1. Run `make generate && make manifests` if API types changed
2. Run `make lint` and fix all errors
3. Run `make test` and ensure all tests pass
4. Add/update unit tests for new/modified code (aim for >70% coverage)
5. Update relevant documentation in `docs/`
6. Update helm chart if CRD fields or config changed
7. Test helm chart: `helm lint` and `helm template`
8. Run E2E tests locally if making significant changes: `make e2e`
9. For frontend changes: `cd frontend && npm run lint && npm test`
10. Review the diff - does every change have tests and docs?

