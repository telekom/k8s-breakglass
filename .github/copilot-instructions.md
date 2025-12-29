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

## Integration Points

- **Frontend ↔ API**: Gin server in `pkg/api/`, frontend proxies `/api/*` to backend. Update `docs/api-reference.md` when changing endpoints.
- **Cluster Cache**: `pkg/cluster/` watches `ClusterConfig` and kubeconfig Secrets for automatic refresh.
- **Metrics**: Prometheus metrics in `pkg/metrics/`. API and webhook servers can have separate metrics ports.

