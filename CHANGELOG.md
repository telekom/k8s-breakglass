# Changelog

All notable changes to the Breakglass Controller project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Graceful HTTP server shutdown with configurable timeouts
- Index registration assertions for escalation queries with metrics for fallback scans
- End-to-end example documentation for complete production setup
- Additional unit tests for `pkg/reconciler` and `pkg/leaderelection`
- ARM64 builds re-enabled for release workflow

### Changed

- Webhook variables now use sync.Once pattern to prevent race conditions
- Approver logging now uses counts instead of identities to reduce PII exposure
- Standardized error wrapping to use `fmt.Errorf("...: %w", err)` pattern
- Centralized frontend duration parsing and reason sanitization utilities for consistent validation
- Enforced server-side 1024-character limit for session request reasons

### Fixed

- Documentation incorrectly referenced `allowed.users` field which doesn't exist in BreakglassEscalation CRD
- Documentation incorrectly referenced `idleTimeout` as functional; now marked as NOT IMPLEMENTED
- Helm chart template no longer renders non-existent `allowed.users` field
- Breakglass request modal state reset now avoids duplicate updates
- Technical debt documentation now references the correct PR for webhook validation fix

### Security

- Reduced PII in logs by logging approver counts instead of individual identities
- Added structured audit events with automatic PII redaction
- Blocked mock JWT generation in production builds

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
