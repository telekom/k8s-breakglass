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
pkg/breakglass/                Session lifecycle, group checking, identity
  clusterconfig/               Cluster config checker & binding API
  debug/                       Debug session API, reconciler, kubectl exec
  escalation/                  Escalation controller, manager, status updater
  eventrecorder/               Kubernetes event recorder wrapper
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
10. **Fuzz tests**: Exist at `api/v1alpha1/fuzz_test.go`, `pkg/breakglass/fuzz_test.go`, and `pkg/breakglass/debug/fuzz_test.go`.

## Build Tags

- `//go:build e2e` — E2E tests (compiled with `-tags=e2e`; at runtime, tests skip unless `E2E_TEST=true`)
- Standard unit tests have no build tags

## CRD Resources

`BreakglassEscalation`, `BreakglassSession`, `ClusterConfig`, `IdentityProvider`, `MailProvider`, `DenyPolicy`, `DebugSession`, `DebugSessionTemplate`, `DebugPodTemplate`

## CI Checks

All PRs must pass: golangci-lint, unit tests, frontend tests (Vitest), Helm lint, Docker build, manifest validation, REUSE compliance, Trivy scan, OpenSSF Scorecard.

## Reusable Prompts (19 total)

Prompts are in [`.github/prompts/`](.github/prompts/) and can be invoked by name:

| Prompt | Category | Purpose |
|--------|----------|---------|
| **Task Prompts** | | |
| `review-pr` | General | PR checklist (code quality, testing, security, docs) |
| `add-crd-field` | Task | Step-by-step guide for adding a new CRD field |
| `github-pr-management` | Workflow | GitHub PR workflows: review threads, rebasing, squashing, CI checks |
| **Code Quality Reviewers** | | |
| `review-go-style` | Lint | golangci-lint v2 compliance: `importas`, `errorlint`, `usestdlibvars`, formatting |
| `review-concurrency` | Safety | Multi-replica races, SSA ownership, monotonic merges, cache staleness, time handling |
| `review-k8s-patterns` | Ops | Error handling, context propagation, reconciler idempotency, structured logging |
| `review-performance` | Perf | Webhook latency, API server load, memory allocation, informer indexes, metrics cardinality |
| `review-integration-wiring` | Wiring | Dead code, unwired fields, unused interfaces, uncalled functions, config propagation |
| **API & Security Reviewers** | | |
| `review-api-crd` | API | CRD schema correctness, backwards compatibility, webhook validation |
| `review-security` | Security | RBAC least privilege, webhook safety, input validation, credential handling |
| `review-rest-api` | API | Gin HTTP endpoints: validation, response format, auth, pagination, concurrency |
| **Documentation & Testing Reviewers** | | |
| `review-docs-consistency` | Docs | Documentation ↔ code alignment: field names, metrics tables, headings, links |
| `review-ci-testing` | Testing | Test coverage, assertion quality, switch exhaustiveness, CI workflow alignment |
| `review-edge-cases` | Testing | Zero/nil/empty values, boundary conditions, clock edge cases, fuzz properties |
| `review-qa-regression` | QA | Regression impact, state machine integrity, backwards compat, rollback safety |
| **Domain-Specific Reviewers** | | |
| `review-frontend-ui` | Frontend | Vue 3 accessibility (WCAG 2.1 AA), TypeScript strict, state display, filters |
| `review-cli-usability` | CLI | `bgctl` command structure, flag naming, output formats, error messages, completion |
| `review-helm-chart` | Helm | Chart values, template correctness, CRD sync, RBAC alignment, upgrade safety |
| `review-end-user` | UX | End-user experience: SRE during incidents, platform admin, security auditor |

### Running a Multi-Persona Review

Invoke each review prompt in sequence against a code change and collect findings.
The 16 reviewer personas cover every issue class found by automated reviewers
(Copilot, etc.) and more:

**Code quality** (4 personas):
- **Go style** catches import alias violations, `%v` error wrapping, string literals, lint failures, duplicate comment lines, string whitespace hygiene
- **Concurrency** catches SSA races, lost updates, stale cache reads, `time.Now()` vs `.UTC()`, failure-path channel deadlocks, mis-wired channel targets, unbuffered channel drops, premature channel closes
- **K8s patterns** catches missing context timeouts, non-idempotent reconcilers, unbounded lists, exit code integrity
- **Performance** catches webhook latency regressions, unbounded memory, high-cardinality metrics

**Correctness** (4 personas):
- **Integration wiring** catches new code that is defined but never called or connected, state pipeline overwrites, dead channel branches, error swallowing at shutdown, **stale generated CRD descriptions after Go comment changes**
- **API & CRD** catches missing validation markers, backwards-compatibility breaks
- **Edge cases** catches untested boundary conditions, zero-value bugs, clock skew issues, **state × time interaction gaps** (e.g., missing edge-case tests for expiry functions across session states and timestamp combinations)
- **QA regression** catches state machine violations, data migration gaps, rollback hazards

**Security & documentation** (3 personas):
- **Security** catches privilege escalation, credential leaks, input injection, CSRF gaps
- **Docs consistency** catches field name mismatches, missing metrics docs, duplicate headings, duplicate comment lines, log-level claim inaccuracies, function-description table drift, **generated artifact staleness** (Go comment ↔ CRD YAML description divergence)
- **CI & testing** catches coverage gaps, wrong test names in docs, missing enum cases, **count-only assertions** (tests asserting `.length` without verifying item content)

**User-facing** (5 personas):
- **Frontend UI** catches missing session states in filters, accessibility gaps, XSS risks, **roving tabindex bugs after filtering**, **duplicate type definitions** that mirror shared models, **identifier misspellings** in route constants and component names
- **CLI usability** catches unclear error messages, missing completions, flag inconsistencies
- **REST API** catches validation gaps, inconsistent response formats, auth bypasses, 401-vs-403 misuse
- **Helm chart** catches RBAC drift, stale CRDs, upgrade failures, missing security contexts
- **End-user** catches UX pain for SREs during incidents, admin config friction, audit gaps
