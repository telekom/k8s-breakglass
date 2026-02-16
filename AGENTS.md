# Breakglass Controller — Agent Instructions

This document provides conventions for AI coding agents working on this repository.
For full project context, see [`.github/copilot-instructions.md`](.github/copilot-instructions.md).

## Quick Start

```bash
make generate && make manifests  # After editing api/v1alpha1/*_types.go
make lint                        # golangci-lint
make test                        # Unit tests (excludes e2e)
cd frontend && npm test          # Frontend tests
```

## Architecture

Go-based Kubernetes controller (controller-runtime) + Vue 3/TypeScript frontend (Vite).
Hub-and-spoke topology: central breakglass service manages temporary privilege escalations across multiple K8s clusters.

## Directory Layout

```
cmd/main.go                    Entry point (5 deployment patterns)
api/v1alpha1/                  CRD types, webhooks, fuzz tests
pkg/breakglass/                Session/escalation business logic
pkg/api/                       Gin HTTP server, REST API
pkg/webhook/                   K8s authorization webhook
pkg/reconciler/                Controller-runtime manager
pkg/cluster/                   Multi-cluster client management
frontend/                      Vue 3 + Vite web application
charts/escalation-config/      Helm chart
e2e/                           E2E test infrastructure
config/                        Kustomize overlays
```

## Critical Rules

1. **Never edit auto-generated files** — `config/crd/bases/`, `config/rbac/`, `zz_generated.deepcopy.go`.
2. **Never remove** `// +kubebuilder:scaffold:*` comments.
3. **After editing `*_types.go`**: Run `make generate && make manifests`.
4. **Error wrapping**: Always use `fmt.Errorf("context: %w", err)`.
5. **HTTP constants**: Use `http.MethodGet` not `"GET"`.
6. **Unit tests mandatory**: Every code change needs `*_test.go` (>70% coverage).
7. **Documentation mandatory**: Update `docs/` with every code change.
8. **CHANGELOG mandatory**: Update `CHANGELOG.md` for user-facing changes.
9. **E2E sessions**: Use API helpers (`e2e/helpers/api.go`), not direct K8s client creation.
10. **Fuzz tests**: Exist at `api/v1alpha1/fuzz_test.go` and `pkg/breakglass/fuzz_test.go`.

## Build Tags

- `//go:build e2e` — E2E tests (compiled with `-tags=e2e`; at runtime, tests skip unless `E2E_TEST=true`)
- Standard unit tests have no build tags

## CRD Resources

`BreakglassEscalation`, `BreakglassSession`, `ClusterConfig`, `IdentityProvider`, `MailProvider`, `DenyPolicy`, `DebugSession`, `DebugSessionTemplate`, `DebugPodTemplate`

## CI Checks

All PRs must pass: golangci-lint, unit tests, frontend tests (Vitest), Helm lint, Docker build, manifest validation, REUSE compliance, Trivy scan, OpenSSF Scorecard.
