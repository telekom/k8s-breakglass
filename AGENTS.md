<!--
SPDX-FileCopyrightText: 2024 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

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

## Agent Documentation Hierarchy

This project uses hierarchical `AGENTS.md` files to provide context-specific instructions to AI agents based on the directory they are working in:
- **Root**: `AGENTS.md` (This file) - General project structure and reviewer personas.
- **Frontend**: [`frontend/AGENTS.md`](frontend/AGENTS.md) - Vue 3, Vite, and Scale UI component conventions.
- **Backend**: [`pkg/AGENTS.md`](pkg/AGENTS.md) - Go controller-runtime, error wrapping, and Gin API rules.
- **API Types**: [`api/AGENTS.md`](api/AGENTS.md) - CRD kubebuilder markers, generation, and backwards compatibility.

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

## Standalone utility images

Images under `utils/images/` are generic, independently runnable OCI images;
they must not depend on private registries, internal filesystem layouts, or
controller-only assumptions. Keep each image's Docker build context inside its
own directory, pin the base by digest and every package/tool version, declare
`linux/amd64` and `linux/arm64` support in `image-metadata.yaml`, and run as a
numeric non-root UID with no capabilities unless a reviewed exception exists.
The metadata file is the release contract for immutable digests, SBOM,
provenance, and signature verification.

Utility helpers must provide `--help`, deterministic bounded reports, explicit
input/output mount boundaries, cleanup on success and failure, and refuse
symlink/traversal escapes and destination overwrites. Add adversarial shell
tests for missing files, symlinks, traversal, bounds, and cleanup. The
mandatory `make -C utils/images integration` fixture must build and run every
image with its declared non-root/read-only settings, execute real packaged
tools (not mocks), exercise every report/inspection mode, and fail rather than
silently skip when Docker is unavailable. Run the image tests, ShellCheck,
Dockerfile linting, YAML validation, REUSE, and a multi-architecture BuildKit
build before release. Keep image docs, MOTD, runbooks, `CHANGELOG.md`, and
machine-readable metadata synchronized with the actual command surface.
Release CI must attach an SBOM and provenance attestation and sign the immutable
manifest with keyless Cosign.

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
11. **Strict Readiness Enforcement**: Unready clusters (`Ready=False`) MUST be hidden from Escalation API by default (`activeOnly=true`) and MUST be blocked from session requests at the controller level.
12. **Utility-image mutation boundary**: Bind every supplied repair flag to an immutable controller-owned approval tuple, reject duplicates and irrelevant flags, pin kernel object identity (for example ifindex) across preflight and mutation, and make volume leases crash-recoverable only for the same immutable operation.

## Utility images (`utils/network-debug/`)

- Keep the network-debug image standalone and distribution-neutral: no internal
  cluster names, private registries, credentials, cloud settings, or T-CaaS/TDG
  assumptions belong in the image, helpers, MOTD, or runbook.
- Pin the base and build images by OCI digest, pin direct Alpine packages, and
  record every upstream tool release, source commit, checksum, and license in
  `utils/network-debug/versions.env` and `LICENSES/THIRD_PARTY.md`. Verify
  downloaded archives before copying them into the runtime stage.
- The supported platforms are `linux/amd64` and `linux/arm64`; test both with
  BuildKit before changing release metadata. Use
  `make -C utils/network-debug test` (helper determinism), ShellCheck,
  Hadolint, and a local Docker build as the minimum image checks.
- Image changes must preserve OCI source/revision/version/base labels and the
  SBOM/provenance flags in the image Makefile. Release automation signs the
  final manifest digest; do not put signing keys or registry credentials in a
  Dockerfile.
- Keep `utils/network-debug/IMAGE-METADATA.yaml` synchronized with the image
  labels, dependency lock, supported platforms, shared `network-diagnostics`
  intent, and digest-gated `cosign` targets. Multi-architecture builds should
  produce a reviewable local OCI archive; never push a mutable tag as an
  implicit side effect of a local build.
- `net-report` output must not include timestamps, hostnames, credentials, or
  random IDs. Changes to tools or permissions require an update to the image
  README, `docs/network-debug-image.md`, and the Unreleased changelog entry.

## Standalone cluster-validator image (TCAAS-1619)

The provider-neutral validator is intentionally isolated in `pkg/clustervalidator`
and `cmd/cluster-validator`; its image is built only by `Dockerfile.validator`.
Keep this boundary intact: built-in checks may use only public, read-only
Kubernetes APIs and must not assume internal T-CaaS namespaces, operators,
CRDs, or services. New checks require stable names, unit tests with fake
clients, and an update to `docs/cluster-validator.md` and the post-upgrade
runbook. Extend through the exported `Check` interface rather than adding
provider-specific behavior to the public image.

The report contract (`cluster-validator.telekom.com/v1alpha1`) must remain
deterministic: sort check results by name, omit timestamps by default, and
preserve exit codes 0 (ready), 1 (not-ready), and 2 (usage/configuration).
Changes to the contract require a versioned API decision and changelog entry.
Run `make test-validator` before committing. Image changes must preserve the
digest-pinned base images, `linux/amd64` + `linux/arm64` build, OCI revision /
SBOM / signing labels, and the pinned-action workflow's provenance, SPDX SBOM,
and Sigstore attestation steps. Run REUSE and YAML validation for new docs,
MOTD, Dockerfile, and workflow files; never use floating image or action tags.
Run `make test-validator-integration` when Docker, kind, kubectl, jq, and Go
are available. The integration harness must build the image, execute every
built-in check and the extension contract against a disposable real cluster
with least-privilege RBAC, assert the documented exit codes and deterministic
reports, prove forbidden mutations and secret isolation, and verify cleanup;
it must fail loudly when a required tool or cluster is unavailable. Keep the
machine-readable intent in `hack/cluster-validator-integration.contract.json`
in sync with the harness and any consolidated utility workflow.
The harness must also exercise exit code 1 with an unhealthy disposable
resource, and cleanup may delete only resources (including the image and kind
cluster) created by that invocation.

## Build Tags

- `//go:build e2e` — E2E tests (compiled with `-tags=e2e`; at runtime, tests skip unless `E2E_TEST=true`)
- Standard unit tests have no build tags

## CRD Resources

`BreakglassEscalation`, `BreakglassSession`, `ClusterConfig`, `IdentityProvider`, `MailProvider`, `DenyPolicy`, `DebugSession`, `DebugSessionTemplate`, `DebugPodTemplate`

## CI Checks

All PRs must pass: golangci-lint, unit tests, frontend tests (Vitest), Helm lint, Docker build, manifest validation, REUSE compliance, Trivy scan, OpenSSF Scorecard.

Tests must prove observable behavior. Do not add assertions that merely search
source files, workflows, manifests, or documentation for expected strings or
check that an implementation file exists. Exercise the public command, API,
rendering, release script, or controller transition and assert its output,
failure mode, security boundary, and cleanup. If the behavior cannot be
executed reliably in the available test environment, document the missing
acceptance gate instead of adding a presence-only test.

## Debug Session Catalogue

The standalone `charts/debug-session-catalogue` chart renders paired,
cluster-scoped `DebugPodTemplate` and `DebugSessionTemplate` objects. Keep
`profiles` as an ordered list of concise, generic intent items; do not restore
the historical map shape or add platform/tenant names. Each item has a unique
DNS-safe `name`, stable `intent`, display metadata, explicit `enabled` and
`elevated` flags, command/args, and an `imageKey` or direct image reference.
Shared authorization, lifecycle, audit, image, workload, pod-hardening, and
resource behavior belongs in named Helm helpers. Generic presets may be
extended, but restricted profiles must always remain non-root, seccomp
RuntimeDefault, drop ALL capabilities, no privilege escalation, no host
namespaces, and no service-account token.

For catalogue changes run `charts/debug-session-catalogue/ci/validate.sh` and
`helm lint charts/debug-session-catalogue --strict`. The validation fixture
must cover default counts, custom list profiles, duplicate and invalid names,
missing image references, explicit elevated opt-in, and attempts to weaken
restricted security. Also run ShellCheck on the validator, `yamllint` on chart
values, `reuse lint` in CI, and package/render the chart with a clean build
context. Helm list profiles cannot be patched reliably with dotted map-style
`--set` paths; use a values fixture when testing a profile item.

## Utility Images

Standalone diagnostic and maintenance images live under `utils/<image-name>/`.
Each image directory owns its Dockerfile, pinned dependency inventory, helper
tests, README, MOTD, and a Makefile with `test`, `build`, and
`build-multiarch` targets. Keep image names and examples stable across utility
images; use the shared DebugSession intent `workload-diagnostics` for workload
diagnostics instead of inventing per-image intent names.

Runtime images must pin the base manifest by digest and pin every explicitly
installed APK package to a version recorded in `deps.lock` and
`IMAGE-METADATA.yaml`. Keep runtime users non-root with no capabilities unless
the operation demonstrably needs more privilege. Helpers must use bounded
timeouts/output, avoid implicit credentials or controller metadata, and never
write secrets to logs or command-line arguments. `build-multiarch` must produce
a usable OCI archive locally (or explicitly push in a publishing workflow),
and release automation signs and attests the immutable manifest digest only.

The root CI should run each utility's helper tests, ShellCheck, Hadolint, and
metadata/YAML validation through one shared matrix job; do not duplicate a
separate workflow for every image. BuildKit SBOM/provenance requests and
Cosign signing/SBOM attestation are release concerns and must be wired to the
same digest rather than a mutable tag.

## Node-Maintenance Utility

The standalone `utils/node-maintenance/` image is intentionally separate from
the Breakglass controller image. Keep its runtime limited to the fixed
`node-recovery` and `network-repair` dispatchers; do not add an
unrestricted shell, package manager, compiler, packet capture, scanner, or
general-purpose network toolbox. The Alpine base manifest and direct APK
dependencies are pinned in `Dockerfile` and `deps.lock`.

Every helper must require an explicit target node, interface, evidence
directory, and command-specific confirmation token. Repair actions must be
allowlisted and record protected before/after evidence, including failure
statuses. Update the utility README and both runbooks for behavior changes.

Use `make -C utils/node-maintenance test` and `shellcheck` for helper changes;
use `make -C utils/node-maintenance integration` on a Linux Docker runner for
the real-tool proof. The integration harness must use `--network none`, a
disposable evidence volume, `--read-only`, `--cap-drop ALL`, `--cap-add
NET_ADMIN`, and `no-new-privileges`; it must fail when Docker or any required
security feature is unavailable rather than skip. Never join or mutate the
runner host network. Every fixture must remove its container and volume and
verify cleanup. Keep `tests/integration-contract.json` in sync with the
commands, expected evidence, and security boundary.
`make -C utils/node-maintenance build` validates the pinned single-platform
image and `build-multiarch` requests BuildKit provenance and SBOM metadata.
Signing and SBOM attestation target an immutable registry digest only.

## Catalogue Supply Chain

Catalogue utility images and the standalone OCI chart are release artifacts,
not unverified Helm defaults. Release gates must resolve immutable digests,
require linux/amd64 and linux/arm64 manifests for utility images, and fail
closed unless keyless Cosign signatures, SPDX SBOM attestations, and SLSA
provenance are present. Keep this gate separate from ordinary unit, lint, and
image build jobs.
The consolidated `.github/workflows/catalogue-utility-integration.yml` is the
separate real-tool proof for `network-debug` and `node-maintenance`; keep its
matrix entries as distinct required checks and do not copy those tests into
the ordinary CI suite.

For workload diagnostics, `make -C utils/workload-debug integration-test` is
the required upstream proof. It builds the image and runs it as UID 65532 with
a read-only root filesystem, all capabilities dropped, and privilege
escalation disabled. The proof uses disposable DNS, TLS, and HTTP fixtures and
a disposable kind service account; it must fail clearly when Docker, kind, or
kubectl is unavailable rather than silently skipping. The fixture namespace,
processes, containers, and temporary credentials are removed in an EXIT trap,
and the test verifies the kind cluster is gone. Keep the JSON report stable and
never place service-account tokens in argv or captured output. Assert only
runtime behavior or rendered public output: do not replace integration checks
with source/file-presence tests, host-network fixtures, or host-privileged
containers.

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
| `review-performance` | Perf | Webhook latency, API server load, memory allocation, informer indexes, metrics cardinality, monotonic clock, read-only vs mutating state checks |
| `review-integration-wiring` | Wiring | Dead code, unwired fields, unused interfaces, uncalled functions, config propagation, error classification granularity |
| **API & Security Reviewers** | | |
| `review-api-crd` | API | CRD schema correctness, backwards compatibility, webhook validation |
| `review-security` | Security | RBAC least privilege, webhook safety, input validation, credential handling |
| `review-rest-api` | API | Gin HTTP endpoints: validation, response format, auth, pagination, concurrency |
| **Documentation & Testing Reviewers** | | |
| `review-docs-consistency` | Docs | Documentation ↔ code alignment: field names, metrics tables, headings, links, silent-fallback attribution |
| `review-ci-testing` | Testing | Test coverage, assertion quality, switch exhaustiveness, CI workflow alignment, Playwright navigation assertions |
| `review-edge-cases` | Testing | Zero/nil/empty values, boundary conditions, clock edge cases, fuzz properties |
| `review-qa-regression` | QA | Regression impact, state machine integrity, backwards compat, rollback safety |
| **Domain-Specific Reviewers** | | |
| `review-frontend-ui` | Frontend | Vue 3 accessibility (WCAG 2.1 AA), TypeScript strict, state display, filters, Scale/Stencil migration |
| `review-cli-usability` | CLI | `bgctl` command structure, flag naming, output formats, error messages, completion |
| `review-helm-chart` | Helm | Chart values, template correctness, CRD sync, RBAC alignment, upgrade safety |
| `review-end-user` | UX | End-user experience: SRE during incidents, platform admin, security auditor |

### Running a Multi-Persona Review

Invoke each review prompt in sequence against a code change and collect findings.
The 16 reviewer personas cover every issue class found by automated reviewers
(Copilot, etc.) and more:

**Code quality** (4 personas):
- **Go style** catches import alias violations, `%v` error wrapping, string literals, lint failures, duplicate comment lines, string whitespace hygiene, **import alias consistency** across files
- **Concurrency** catches SSA races, lost updates, stale cache reads, `time.Now()` vs `.UTC()`, failure-path channel deadlocks, mis-wired channel targets, unbuffered channel drops, premature channel closes, **circuit breaker probe-slot lifecycle** (Allow increment, Record* decrement, eviction cleanup)
- **K8s patterns** catches missing context timeouts, non-idempotent reconcilers, unbounded lists, exit code integrity, **resilience mechanism wiring** (breaker/retry actually connected to HTTP client), **Prometheus metric lifecycle** (gauge cleanup on resource deletion)
- **Performance** catches webhook latency regressions, unbounded memory, high-cardinality metrics, **circuit breaker key normalization** inconsistencies across create/lookup/eviction paths

**Correctness** (4 personas):
- **Integration wiring** catches new code that is defined but never called or connected, state pipeline overwrites, dead channel branches, error swallowing at shutdown, **stale generated CRD descriptions after Go comment changes**, **cache/registry key normalization** mismatches (creation vs. eviction using different key forms), **deleted functions with surviving test references** across PRs
- **API & CRD** catches missing validation markers, backwards-compatibility breaks
- **Edge cases** catches untested boundary conditions, zero-value bugs, clock skew issues, **state × time interaction gaps** (e.g., missing edge-case tests for expiry functions across session states and timestamp combinations), **circuit breaker edge cases** (half-open probe exhaustion, concurrent state transitions, unbounded breaker creation)
- **QA regression** catches state machine violations, data migration gaps, rollback hazards, **resilience mechanism regression** (error reclassification, threshold changes), **verification discipline** (search codebase before flagging missing features)

**Security & documentation** (3 personas):
- **Security** catches privilege escalation, credential leaks, input injection, CSRF gaps, **log-volume DoS** from unbounded warning logs in hot paths, **error classification breadth** (treating broad error interfaces like `net.Error` / `url.Error` as uniformly transient)
- **Docs consistency** catches field name mismatches, missing metrics docs, duplicate headings, duplicate comment lines, log-level claim inaccuracies, function-description table drift, **generated artifact staleness** (Go comment ↔ CRD YAML description divergence), **runtime behavior claims without hot-reload support**, **misleading API method docs** that cause double-counting
- **CI & testing** catches coverage gaps, wrong test names in docs, missing enum cases, **count-only assertions** (tests asserting `.length` without verifying item content), **orphaned test references** to deleted/renamed symbols, **`no-explicit-any`** violations in test files

**User-facing** (5 personas):
- **Frontend UI** catches missing session states in filters, accessibility gaps, XSS risks, **roving tabindex bugs after filtering**, **duplicate type definitions** that mirror shared models, **identifier misspellings** in route constants and component names, **`any` in all forms** (`Record<string, any>`, `as any`, explicit `any` params) in source and test files
- **CLI usability** catches unclear error messages, missing completions, flag inconsistencies
- **REST API** catches validation gaps, inconsistent response formats, auth bypasses, 401-vs-403 misuse
- **Helm chart** catches RBAC drift, stale CRDs, upgrade failures, missing security contexts, **orphaned resources** (ConfigMaps/Secrets rendered but never consumed or documented)
- **End-user** catches UX pain for SREs during incidents, admin config friction, audit gaps
