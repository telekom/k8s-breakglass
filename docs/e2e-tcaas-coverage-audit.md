<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# T-CaaS deployment-model E2E coverage audit

This audit compares the Breakglass test suites with the management-cluster /
tenant-cluster deployment used by T-CaaS. The repository's multi-cluster job
already provides the closest executable model; it is opt-in locally and runs
in CI as the `Multi-Cluster E2E Tests` job.

## Phase 1 inventory

| Suite | Shape exercised | Evidence |
| --- | --- | --- |
| `e2e/bootstrap_e2e_test.go` | One Kind management cluster; controller deployment wiring, generated webhook kubeconfig and ClusterConfig bootstrap. | `e2e/bootstrap_e2e_test.go:422-475`, `:462-622` |
| `e2e/api/*` without `multicluster` | Single cluster API/UI-facing flows; most sessions are created through API helpers. | `e2e/api/approval_workflow_test.go:56-67`, `e2e/helpers/api.go` |
| `e2e/api/*` with `multicluster` | One hub plus two real Kind spokes. Spokes use structured authentication and authorization, OIDC tokens, and the hub's authorization route. | `e2e/kind-setup-multi.sh:137-218`, `e2e/api/spoke_hub_authorization_test.go:145-236` |
| `e2e/cli` | CLI flows against the configured test cluster; shell coverage is opt-in. | `Makefile:183-184`, `.github/workflows/ci.yml:1098-1107` |
| `pkg/*_test.go` | Unit tests, including fake clients, controller logic, webhook logic, limits, OIDC parsing and email behavior. | `Makefile:121-123` |
| `pkg/api/api_end_to_end_test.go` | In-process API-to-session/controller integration, not a deployed management/tenant topology. | `pkg/api/api_end_to_end_test.go:1-70` |
| GitHub Actions | Bootstrap smoke, single-cluster, OIDC comprehensive, UI and multi-cluster jobs. Multi-cluster runs `go test -tags=multicluster ./e2e/api/...`. | `.github/workflows/e2e-smoke.yml:35-70`, `.github/workflows/ci.yml:719-1120`, `1293-1550`, `2291-2735` |

`MAINTAINING.md` and `internal/test/envtest/` are not present in this checkout;
the envtest-like coverage is colocated with package tests and the Makefile
uses controller-runtime's standard test dependencies rather than a repository
`internal/test/envtest` harness.

## Gap matrix

Legend: **covered** means the suite exercises the behavior; **partial** means
only a unit/static or single-cluster approximation exists; **gap** means the
T-CaaS shape is not exercised.

| Deployment aspect | Single E2E | Multi-cluster E2E | Package tests | Gap |
| --- | --- | --- | --- | --- |
| Frontend/API/cleanup/webhooks/validating-webhooks flags | partial: dev overlay defaults | partial: same overlay | covered as parser/setup-plan cases | No deployed matrix for every toggle |
| `--enable-controllers` on and off | partial: default-on only | partial: default-on only | covered for parser and setup plan | No deployed controller-off session-selection test on the default branch |
| Deployed flag combination | partial: `config/deployment/app.yaml:31-50` | partial: overlay-derived | gap | Added deployment-contract assertions in this change |
| ConfigMap-mounted `--config-path` | covered by `TestBootstrapW003_DeploymentModel` (live Deployment and ConfigMap) | covered: hub setup uses the mounted overlay ConfigMap | covered by config loader tests | — |
| Different tenant cluster authorizes through management webhook | gap | covered by `spoke_hub_authorization_test.go:145-236` | gap | Existing path is HTTP in the Kind harness, not the T-CaaS external TLS path |
| Create → approve → real webhook session selection | partial | covered by `spoke_hub_authorization_test.go:174-236` | misleading cases below | Existing test is the primary regression guard |
| OIDC prefixes and group claims | partial | partial: plain `groups` claims and two realms | covered for prefix stripping | TDI/TDG prefix/delimiter combinations are not deployed |
| Four-eyes approval and self-approval rejection | covered through API approval suites | partial | covered | No cross-cluster authorization assertion after four-eyes approval |
| Revocation and expiry remove access | partial | covered: revocation at `spoke_hub_authorization_test.go:238-289`, expiry at `:421+` | covered | — |
| Per-user, total and group-overridden session limits | gap in deployed E2E | gap in deployed E2E | covered extensively | Expensive setup needed for API lifecycle assertions |
| Leader election namespace/id | partial: `TestBootstrapW003_DeploymentModel` verifies the live Lease | partial: no multi-replica failover test | partial parser/resource-lock tests | No multi-replica failover test |
| Email enabled and `--disable-email` | enabled MailHog smoke | disabled path is not deployed | covered with fakes | No deployed toggle matrix |
| Webhook TLS/cert path | validating webhook resources are installed | CA is generated, but SAR route uses hub HTTP API NodePort | partial | The cross-cluster harness does not currently exercise `:9443` TLS |
| Metrics, health and webhook ports (`8081`, `8082`, `8083`, `9443`) | metrics/health partial | `8081` partial | covered in server tests | No deployed assertion for all endpoints |
| `authorizedTTL`/`unauthorizedTTL` authorization caching | gap | gap: cache explicitly disabled in `kind-setup-multi.sh:185-190` | gap | Needs a Kubernetes apiserver configuration test |

## Tests that bypass production wiring

* `pkg/webhook/authorize_helpers_test.go:96-103` and `:131-141` assign
  `authorizeState.sessions` directly. They test reason formatting, but cannot
  detect a broken session list, cache, or field-index registration.
* `pkg/webhook/controller_test.go:80-95` and the repeated builders in that file
  hand-register indexes on fake clients. This proves the selector logic only
  when the test has already supplied the wiring that production startup may
  omit.
* `pkg/webhook/error_scenarios_test.go:28-44` and
  `ratelimit_test.go:246-258` use the same hand-built indexed fake-client
  pattern; they do not prove `reconciler.Setup` registered those indexes.
* `e2e/api/hub_spoke_test.go:286-310` and `:326-348` create
  `BreakglassSession` objects directly with the hub client. These tests verify
  resource visibility, not the authenticated API request and approval path.
* `pkg/api/api_end_to_end_test.go:31-50` supplies fake clients and indexes in
  process. It is useful integration coverage but is not a deployed manager/cache
  or tenant-apiserver test.
* `e2e/api/controller_resilience_test.go:260-278` records leader-election
  claims as log messages only; it does not inspect a Lease or run a second
  replica.

These tests are not removed: their narrow unit/integration assertions remain
valuable. They are explicitly not counted as evidence for the T-CaaS
create/approve/authorize path.

## Existing PRs checked

* [PR #1297](https://github.com/telekom/k8s-breakglass/pull/1297), draft,
  `fix/webhook-session-index-registration`, base
  `36c7ce67ddad7ac6b05d6e541f946a4972195eff`, head
  `50f26e4d81bbb674c8e345fe510e0186df0b4246`. CI was still running when
  audited; lint, unit, CodeQL, security and manifest checks were green.
* [PR #1298](https://github.com/telekom/k8s-breakglass/pull/1298), draft,
  `fix/bgctl-session-drop-request`, base
  `36c7ce67ddad7ac6b05d6e541f946a4972195eff`, head
  `2471e9bf11fa76cc5af3bf10a4c746471f99054d`. CI was still running when
  audited; lint, unit, CodeQL, security and manifest checks were green.

Neither PR is modified by this work.
