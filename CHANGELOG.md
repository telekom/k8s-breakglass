# Changelog

All notable changes to the Breakglass Controller project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Kustomize deployment targets restructuring**: New shared base configuration for all deployment targets
  - `config/base`: New canonical production deployment target with webhooks enabled
  - `config/debug`: Production deployment with debug logging
  - `config/dev`: Development/E2E environment with keycloak, mailhog, kafka
  - `config/default`: Now deprecated alias to `config/base` for backward compatibility
  - New `make deploy_debug` and `make undeploy_debug` targets
- **CI manifest validation and comparison**: New CI job that builds all kustomize targets and compares against previous release
  - Posts manifest diff as PR comment highlighting changes
  - Uploads manifest artifacts for each build
- **Deployment documentation**: New `docs/deployment-targets.md` with comprehensive guide for all kustomize targets
- **Release manifest artifacts**: Releases now include pre-built `manifests-base.yaml`, `manifests-debug.yaml`, and `manifests-crds.yaml`
- **CLI Tool (`bgctl`)**: Command-line interface for Breakglass API with session management, debug sessions, escalation queries, and kubectl-debug operations
  - OIDC authentication flows (browser-based, device code, client credentials)
  - Multi-context configuration with reusable OIDC providers
  - Session lifecycle management (list, request, approve, reject, withdraw, drop, cancel)
  - Debug session support (create, join, leave, renew, terminate, approve, reject)
  - Kubectl-debug operations (inject ephemeral containers, copy pods, node debugging)
  - Multiple output formats (table, JSON, YAML, wide) with pagination
  - Shell completion (bash, zsh, fish, powershell)
  - Self-update mechanism with SHA256 verification and rollback support
  - Token caching with automatic refresh
  - Watch mode for real-time session monitoring (polling-based)
  - **Version command works without configuration** - `bgctl version` now functions without config file
  - **Dev builds show commit ID and dirty flag** - Build process injects git metadata into version info
  - **Comprehensive multi-cluster E2E tests** - Full test coverage for multi-cluster scenarios
  - **Comprehensive CLI E2E test suite** - Added `cli_comprehensive_test.go` with tests for all CLI commands and features including auth, config, session, escalation, debug, update, version, completion, output formats, pagination, error handling, global flags, and edge cases
- Graceful HTTP server shutdown with configurable timeouts
- Index registration assertions for escalation queries with metrics for fallback scans
- End-to-end example documentation for complete production setup
- Additional unit tests for `pkg/reconciler` and `pkg/leaderelection`
- ARM64 builds re-enabled for release workflow
- CI log and artifact retrieval guidance in docs/ci-logs.md
- Tmux-enabled debug image for terminal sharing E2E coverage
- Unit tests for `pkg/bgctl/output` package
- Unit tests for `pkg/apiresponses` and webhook manager helpers
- Unit tests for `pkg/bgctl/cmd` update helpers
- Unit tests for `pkg/bgctl/cmd` auth/client helpers
- Unit tests for `pkg/bgctl/cmd` config commands
- Contributing guide with test policy, coding standards, and review requirements
- Release process documentation covering artifact signing and provenance
- Additional unit tests for `pkg/bgctl/auth` token cache
- Additional unit tests for `pkg/bgctl/cmd` client building
- Additional unit tests for `pkg/bgctl/cmd` config commands
- Additional unit tests for `pkg/bgctl/cmd` runtime helpers
- Unit tests for `cmd/bgctl` entrypoint
- Additional unit tests for `pkg/config` IdentityProvider reconciler
- Additional unit tests for `pkg/bgctl/cmd` config commands
- Additional unit tests for `pkg/bgctl/cmd` session commands
- Additional unit tests for `pkg/bgctl/cmd` update helpers
- Additional unit tests for `pkg/bgctl/cmd` update helpers (archive edge cases)
- Additional unit tests for `pkg/bgctl/cmd` client building
- **CLI Correlation ID logging**: All API requests now include `X-Correlation-ID` header and support verbose mode via `WithVerbose()` for CI debugging
- **CLI `--verbose` flag**: New `-v/--verbose` flag and `BGCTL_VERBOSE` environment variable for detailed request/response logging with correlation IDs
- CLI E2E tests now run with verbose mode enabled for better CI debugging

### Changed

- Webhook variables now use sync.Once pattern to prevent race conditions
- Approver logging now uses counts instead of identities to reduce PII exposure
- Standardized error wrapping to use `fmt.Errorf("...: %w", err)` pattern
- Centralized frontend duration parsing and reason sanitization utilities for consistent validation
- Enforced server-side 1024-character limit for session request reasons
- DebugSession lookups now use indexed field selectors for cluster, state, and participant filters
- Bumped controller-runtime to v0.23.0 and adopted typed webhooks with `events.k8s.io` RBAC for event recording
- Switched internal event emission to the `events.k8s.io` recorder API
- Adopted SSA for controller-managed status updates with field manager `breakglass-controller`
- Enabled controller warmup and a 5-minute reconciliation timeout for manager-registered controllers
- E2E event verification now queries `events.k8s.io/v1` instead of the legacy core/v1 events API
- DebugSessionTemplate and DebugPodTemplate status updates now use SSA via `ssa.ApplyDebugSessionTemplateStatus` and `ssa.ApplyDebugPodTemplateStatus`

### Fixed

- Documentation incorrectly referenced `allowed.users` field which doesn't exist in BreakglassEscalation CRD
- Documentation incorrectly referenced `idleTimeout` as functional; now marked as NOT IMPLEMENTED
- Helm chart template no longer renders non-existent `allowed.users` field
- Breakglass request modal state reset now avoids duplicate updates
- Re-enabled tmux terminal sharing E2E assertions and templates
- Escaped cluster names in webhook deny reason URLs
- Technical debt documentation now references the correct PR for webhook validation fix
- **CLI completion** now writes to configured output writer instead of hardcoded stdout
- **CLI E2E tests** fixed to use correct flag names (`--context` instead of `--context-name`)
- Leader election now emits Kubernetes events for lease transitions
- BreakglassSession webhooks now reject invalid status transitions
- DenyPolicy validation now rejects negative precedence values
- Breakglass session list reads now use a fresh API reader for consistent filtering results
- BreakglassSession SSA status updates now resolve namespace/resourceVersion and force ownership to avoid field manager conflicts
- SSA status apply conflicts are now logged for CI visibility
- Multi-cluster e2e setup now applies debug session templates
- Documentation now covers full CRD set, validating webhook scope, and email optionality
- **Dev kustomize overlay**: Disabled hash suffix for `keycloak-realm`, `keycloak-tls`, and `breakglass-certs` to fix volume mount failures in E2E tests
- **Dev kustomize overlay**: Renamed dev services/deployments to use `breakglass-` prefix (`breakglass-keycloak`, `breakglass-mailhog`, `breakglass-kafka`, `breakglass-audit-webhook-receiver`) to match FQDN references in config files and e2e helpers
- **Debug session API handlers** now return session object instead of message for terminate, approve, and reject endpoints to match client expectations
- **CLI verbose logging** now writes to stderr instead of stdout to avoid corrupting JSON/YAML output

### Security

- Reduced PII in logs by logging approver counts instead of individual identities
- Added structured audit events with automatic PII redaction
- Blocked mock JWT generation in production builds
- **Fixed Zip Slip vulnerability** in CLI self-update archive extraction (CodeQL finding)
- Updated security dependencies: `golang-jwt/jwt/v5` to v5.3.0, `coreos/go-oidc/v3` to v3.17.0, `google/cel-go` to v0.26.1

---

## [0.1.0-beta.0] - 2026-01-15

### Added

- **Debug Sessions**: kubectl-debug mode with terminal sharing and auto-approve by group (#229)
- **Pod Security Evaluation**: Risk-based pod security evaluation for breakglass sessions (#184)
- **E2E Test Framework**: Comprehensive E2E test framework with multi-cluster OIDC support
- **UI E2E Tests**: Frontend E2E tests with Playwright
- **Rate Limiting**: Request rate limiting and security hardening utilities
- **AuditConfig CRD**: Audit event routing to Kafka, Webhooks, and logs
- Comprehensive use case tests and DebugSession reconciler tests (#209)

### Changed

- Updated to Kubernetes API v0.35.0 (k8s.io/api, k8s.io/client-go)
- Consolidated CI workflows and cleaned up deprecated files
- Improved session views and cards in frontend

### Fixed

- Code review findings across frontend and backend (#179)

---

## [0.0.11] - 2025-12-20

### Added

- Increased test coverage across the codebase (#178)

### Changed

- Refreshed session views and cards in UI (#177)

### Fixed

- Code review findings across frontend and backend (#179)

---

## [0.0.10] - 2025-12-15

### Fixed

- Metrics blocking SubjectAccessReview requests (#166)

---

## [0.0.9] - 2025-12-10

### Added

- Cert-controller support for automatic webhook certificate management (#154)
- Test cases for cert watcher and conditions (#156)
- Mock API and flavour overrides for frontend development (#165)

### Changed

- Major UI refactor with improved UX (#137)
- Hardened breakglass flows with additional metrics, validation, and webhook coverage (#162)
- Tightened CORS and OIDC proxy TLS defaults (#164)
- Cleaned up main.go entry point (#163)

### Fixed

- Approval buttons missing in UI (#159)
- Improved error handling throughout the codebase (#158)
- Fixed broken OpenSSF scorecard link in README (#160)

---

## [0.0.8] - 2025-12-01

### Added

- **MailProvider CRD**: New CRD to manage mail server configuration (#135)

### Fixed

- Issues found after rollout with v0.0.7 (#133)
- Bug report key validations (#136)

### Security

- Bumped golang.org/x/crypto for security fixes (#134)

---

## [0.0.7] - 2025-11-25

### Added

- **Multi-IDP Setup**: Support for multiple identity providers (#124)
- **Leader Election**: Implemented leader election for flows with concurrency issues (#123)
- Issue templates: bug report, feature request, documentation templates

### Changed

- Reworked CLI arguments and enabled cert-manager for webhook certs (#122)
- Removed Helm chart temporarily (helmify issues) (#119)

### Fixed

- Errors in user tests (#119)
- Semicolon insertion issues (#115)

---

## [0.0.6] - 2025-11-15

### Added

- **IdentityProvider CRD**: Introduced IDPConfig for OIDC configuration (#109, #112)
- Notification exclusions and hidden approvers support (#110)
- Breakglass production readiness improvements: debug logging, UI/UX enhancements (#98)

### Fixed

- "Why" information in notification emails (#111)
- Mail test case flakiness (#107)

---

## [0.0.5] - 2025-11-01

### Added

- Prometheus metrics for SubjectAccessReviews and Sessions (#56)
- Unbranded UI option (#59)
- Configurable naming/branding (#58)
- Helm chart for deployment (#87)
- Email queue with retry logic (#72)
- Pre-scheduling of access requests (#71)
- Runtime-based flavour approach for single image deployments (#70)
- REUSE compliance workflow (#62)
- OpenSSF security workflow (#63)
- ORT (OSS Review Toolkit) workflow (#61)
- Code of Conduct (#73)
- Dependabot configuration (#74)

### Changed

- Renamed repository from das-schiff-breakglass to k8s-breakglass (#66)
- Updated documentation for recent API changes

### Fixed

- Identical operands code scanning issue (#60)
- Workflow permissions for code scanning (#57)

### Security

- Applied StepSecurity best practices (#89)
- Added build provenance attestation

---

## [0.0.4] - 2025-10-20

### Fixed

- CI pipeline fixes (#52)

---

## [0.0.3] - 2025-10-15

### Added

- TLS flag for auth provider

### Fixed

- CI pipeline fixes (#51)

---

## [0.0.2] - 2025-10-10

### Fixed

- Release CI workflow (#49)

---

## [0.0.1] - 2025-10-01

### Added

- Initial release of Breakglass Controller
- **BreakglassSession CRD**: Temporary privilege escalation requests
- **BreakglassEscalation CRD**: Escalation policy definitions
- **ClusterConfig CRD**: Multi-cluster management
- **DenyPolicy CRD**: Fine-grained access restrictions
- Vue.js frontend for session management
- SubjectAccessReview webhook for Kubernetes authorization
- Validating webhooks for CRD validation
- Email notifications for session lifecycle events
- Basic Prometheus metrics

---

[Unreleased]: https://github.com/telekom/k8s-breakglass/compare/v0.1.0-beta.0...HEAD
[0.1.0-beta.0]: https://github.com/telekom/k8s-breakglass/compare/v0.0.11...v0.1.0-beta.0
[0.0.11]: https://github.com/telekom/k8s-breakglass/compare/v0.0.10...v0.0.11
[0.0.10]: https://github.com/telekom/k8s-breakglass/compare/v0.0.9...v0.0.10
[0.0.9]: https://github.com/telekom/k8s-breakglass/compare/v0.0.8...v0.0.9
[0.0.8]: https://github.com/telekom/k8s-breakglass/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/telekom/k8s-breakglass/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/telekom/k8s-breakglass/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/telekom/k8s-breakglass/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/telekom/k8s-breakglass/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/telekom/k8s-breakglass/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/telekom/k8s-breakglass/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/telekom/k8s-breakglass/releases/tag/v0.0.1
