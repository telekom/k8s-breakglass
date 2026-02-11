# Changelog

All notable changes to the Breakglass Controller project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Debug Session / Deny Policy Bypass Documentation**: Documented that active debug sessions bypass deny policy evaluation for pod-level operations (`exec`, `attach`, `portforward`, `log`)
- **Webhook Evaluation Order Documentation**: Updated deny-policy, debug-session, and advanced-features docs to clarify the webhook evaluation order
- **Debug Session Roadmap Table Correction**: Corrected the debug session roadmap table to reflect the implemented behavior
- **Auto-Approve Preview in Debug Session API**: The `/templates/:name/clusters` endpoint now returns `canAutoApprove` and `approverUsers` fields in the approval info, allowing the UI to preview whether a session will be auto-approved before creation
- **Best-Effort Cleanup on Session Failure**: `failSession()` now calls `cleanupResources()` before transitioning to Failed state, ensuring partially deployed resources (ResourceQuota, PDB, workloads) are cleaned up even on failure
- **Comprehensive Cleanup Edge Case Tests**: Added 22 unit tests covering failSession and cleanupResources behavior across all failure scenarios including partial deploys, nil cluster providers, idempotent re-fail, and spec preservation

### Changed

- **Frontend Debug Session Variables**: Improved variable form validation with inline hints showing allowed values, default indicators, and dark theme support for approval cards

### Fixed

- **Standardized API Error Responses**: Replaced raw `c.JSON(status, "string")` and `gin.H{"error": ...}` patterns with standardized `apiresponses` helpers across escalation controller, debug session API, cluster binding API, session controller, and OIDC proxy. All error responses now include a consistent `"code"` field (e.g., `INTERNAL_ERROR`, `BAD_REQUEST`, `UNPROCESSABLE_ENTITY`) alongside the `"error"` message
- **Auto-Approve in resolveApproval API**: The `resolveApproval()` handler now evaluates auto-approve eligibility using `evaluateAutoApprove()`, correctly populating `canAutoApprove` in API responses
- **Frontend Log Spam**: Removed excessive console logging of full approval objects during debug session creation

- **IDP-Based Session Limits**: Session limits are now configured at the IdentityProvider level with support for group-based overrides and escalation-level overrides
  - New `IdentityProvider.spec.sessionLimits` field with `maxActiveSessionsPerUser` default limit
  - New `sessionLimits.groupOverrides[]` for group-specific limits (platform teams, SRE, etc.)
  - Group overrides support `unlimited: true` to disable limits for privileged groups
  - `BreakglassEscalation.spec.sessionLimitsOverride` allows escalations to override IDP limits
  - Escalation overrides support `unlimited`, `maxActiveSessionsPerUser`, and `maxActiveSessionsTotal`
  - Limit resolution order: Escalation override → IDP group override → IDP default → No limit
  - Glob pattern matching supported for IDP group overrides (e.g., `platform-*` matches `platform-team`)
  - See [IdentityProvider documentation](docs/identity-provider.md#session-limits) for details

- **SAR Processing Phase Metrics**: New Prometheus histogram `breakglass_webhook_sar_phase_duration_seconds` tracks timing for each phase of SubjectAccessReview authorization
  - Phases tracked: `parse`, `cluster_config`, `sessions`, `debug_session`, `deny_policy`, `rbac_check`, `session_sars`, `escalations`, `total`
  - Enables bottleneck identification and performance optimization
  - See [metrics documentation](docs/metrics.md#sar-processing-phase-timing) for PromQL examples

- **Enhanced Test Coverage**: Added comprehensive tests for cluster communication failures and cleanup/finalizer scenarios
  - `pkg/cluster/communication_failure_test.go`: Tests for `ClientProvider` error handling including secret not found, invalid kubeconfig, network errors, and API error classification
  - `pkg/config/cluster_config_cleanup_test.go`: Tests for partial cleanup failure, list errors blocking cleanup, mixed session types, multi-namespace cleanup, terminal session handling

- **kstatus Compliance**: All CRDs now fully comply with [kstatus](https://github.com/kubernetes-sigs/cli-utils/blob/master/pkg/kstatus/README.md) requirements for proper reconciliation status detection
  - Added `observedGeneration` field to `MailProviderStatus`, `AuditConfigStatus`, `BreakglassSessionStatus`, and `DebugSessionStatus`
  - Controllers now populate `status.observedGeneration` when updating status to enable generation tracking
  - Added proper `listType=map` and `listMapKey=type` markers to all condition arrays for strategic merge patch support
  - Added `Ready` print column to `AuditConfig`, `DebugPodTemplate`, and `DebugSessionTemplate` CRDs
  - This enables tools like `kubectl wait --for=condition=Ready` and GitOps reconciliation status tracking

- **Granular Pod Operations for Debug Sessions**: Control which kubectl operations are allowed on debug session pods
  - New `AllowedPodOperations` type with toggles for `exec`, `attach`, `logs`, and `portForward`
  - `DebugSessionTemplateSpec.allowedPodOperations` field to configure permitted operations at template level
  - `DebugSessionStatus.allowedPodOperations` caches resolved operations for webhook enforcement
  - Backward compatible: nil `AllowedPodOperations` defaults to exec, attach, portforward (existing behavior)
  - Use case: logs-only access for read-only debugging
  - Webhook now supports `log` subresource in addition to exec, attach, portforward
  - **CLI**: `bgctl debug session list -o wide` now includes OPERATIONS column showing enabled operations
  - **UI**: DebugSessionDetails page shows "Allowed Pod Operations" card with visual ✓/✗ indicators
  - **API**: `DebugSessionSummary` response includes `allowedPodOperations` field for list responses
  - Example configurations:
    - Logs-only: `exec: false, attach: false, logs: true, portForward: false`
    - Full debug: `exec: true, attach: true, logs: true, portForward: true`
  - Note: `kubectl cp` uses the exec subresource internally, so it requires `exec: true` to function

- **CLI Support for ExtraDeploy Variables**: Added `--set` flag to `bgctl debug session create` command
  - Use `--set key=value` to provide values for template `extraDeployVariables`
  - Can be repeated multiple times: `--set logLevel=debug --set enableTracing=true`
  - Values are passed to the API as `extraDeployValues` in the create request

- **ExtraDeploy Variables (Complete Implementation)**: Full implementation of user-provided variables in debug session templates
  - **API Types (Phase 1-2)**:
    - `ExtraDeployVariable` type with support for boolean, text, number, storageSize, select, and multiSelect input types
    - `DebugSessionTemplateSpec.extraDeployVariables` field for defining template variables
    - `DebugSessionTemplateSpec.podTemplateString` field for inline templated pod specs
    - `DebugSessionTemplateSpec.podOverridesTemplate` field for templated pod overrides
    - `DebugSessionSpec.extraDeployValues` field for user-provided values at session request time
    - `AuxiliaryResource.templateString` field for multi-document YAML templates with Go templating
    - Webhook validation for variable names, options, and type-specific validation rules
  - **Pod Template Rendering (Phase 3)**:
    - Support for `podTemplateString` - fully templated pod specs with Go template + Sprig functions
    - Support for `podOverridesTemplate` - templated pod overrides (image, command, args, env)
    - Template context includes `.Session`, `.Template`, `.Cluster`, `.Namespace`, `.Vars`, and `.Impersonation`
    - Access user values in templates as `{{ .Vars.variableName }}`
  - **Value Validation**:
    - `ValidateExtraDeployValues()` validates user-provided values against template variable definitions
    - Type-specific validation: pattern/length for text, min/max for numbers, size ranges for storage
    - Required field validation, select option validation, and multiSelect item count constraints
  - **Frontend Form Generation (Phase 4)**:
    - `VariableForm.vue` component dynamically renders forms based on template variable definitions
    - Support for all input types: boolean, text, number, storageSize, select, multiSelect
    - Variable grouping by `group` field with collapsible sections
    - Advanced variable toggle (show/hide `advanced: true` variables)
    - Group-based visibility filtering via `allowedGroups` field
    - Client-side validation with inline error messages
    - Integration with `DebugSessionCreate.vue` workflow
  - See `docs/proposals/extra-deploy-variables.md` for full design and examples

- **YAML Security Template Functions**: New template functions to prevent YAML injection attacks
  - `yamlQuote` - safely quotes strings for YAML values, escaping special characters
  - `yamlSafe` - sanitizes strings by replacing dangerous YAML characters
  - `isYAMLSpecialWord` - detects YAML keywords (true, false, null, etc.) that need quoting
  - Documentation: See `docs/extra-deploy-variables.md` for security best practices

- **DebugSessionClusterBinding Pod Operations**: Added `allowedPodOperations` field to bindings
  - Bindings can now restrict which kubectl operations are allowed on debug session pods
  - Supports `exec`, `attach`, `logs`, and `portForward` toggles
  - Binding restrictions are merged with template restrictions (most restrictive wins)
  - Use case: Create logs-only read access bindings for auditors or developers

- **Helm Chart: DenyPolicy Support**: Added `denyPolicies` section to the escalation-config chart
  - Full support for cluster-scoped DenyPolicy resources

### Changed

- Hide the Debug Panel UI in production builds unless `VITE_ENABLE_DEBUG_PANEL` is set.
- Use generated apply-configurations for SSA object updates where available (CRDs and Secrets).
  - Configure `appliesTo` (groups/users), `rules` (verbs/resources), `podSecurityRules`
  - Supports `precedence` field for policy priority ordering
  - Test values in `test-values/deny-policies.yaml` with 7 example policies

- **Helm Chart: Expanded Binding Configuration**: Extended debugSessionBindings support
  - `allowedPodOperations` for exec/attach/logs/portForward control
  - `notification` with `notifyOnRequest`, `notifyOnApproval`, `notifyOnExpiry`, `notifyOnTermination`
  - `notification.additionalRecipients` and `excludedRecipients` for mail routing
  - `requestReason` with `mandatory`, `minLength`, `maxLength`, `description`, `suggestedReasons`
  - `approvalReason` with `mandatory`, `mandatoryForRejection`, `minLength`, `description`
  - Chart version bumped to 0.3.0

- **Helm Chart: ClusterConfig mailProvider**: Added `mailProvider` field to clusterConfigs
  - Reference a MailProvider by name for cluster-specific email configuration

### Security

- **Approver Group Resource Protection**: Added limits to prevent resource exhaustion during approver resolution
  - `MaxApproverGroupMembers=1000`: Maximum members per approver group to prevent oversized group processing
  - `MaxTotalApprovers=5000`: Maximum total approvers across all groups to cap memory/CPU usage
  - Prevents denial-of-service from maliciously large group memberships
  - Groups exceeding limits are logged with warnings and truncated rather than failing the session

- **AllowedGroups Server-Side Enforcement**: The API now validates `allowedGroups` on both variables and select options
  - Variable-level `allowedGroups` prevents unauthorized users from setting restricted variables
  - Option-level `allowedGroups` on `select`/`multiSelect` options restricts high-risk choices
  - Returns clear error messages indicating which groups are required
  - Enables persona-based separation of concerns (e.g., tenants see reduced options vs platform admins)

- **YAML Injection Prevention**: User-provided `extraDeployValues` are now properly sanitized when rendered into templates
  - Template authors should use `{{ .Vars.value | yamlQuote }}` for all user inputs
  - New functions handle colons, hashes, newlines, quotes, YAML anchors/aliases
  - Comprehensive test coverage for injection attempts

### Fixed

- **REST Config Cache Race Condition**: Fixed race condition in REST config cache that could cause redundant ClusterConfig fetches and REST config creation (PR #296)
  - Uses double-checked locking pattern to prevent multiple threads from building the same REST config simultaneously
  - Added `getInNamespaceLocked` and `getAcrossAllNamespacesLocked` helpers for lock-held cache operations
  - Reduces unnecessary API calls and improves performance under concurrent load

- **DebugPodTemplate Template Validation**: Fixed nil pointer panic in DebugPodTemplate validation when `templateString` is used instead of the `template` field (PR #309)
  - Added validation to enforce mutual exclusivity between `template` and `templateString` fields
  - Added Go template syntax validation at admission time so invalid templates are rejected early

- **Strict JSON Request Validation**: Session creation API now rejects requests with unknown/typo'd fields
  - Unknown fields in JSON request body now return `422 Unprocessable Entity` instead of being silently ignored
  - Trailing JSON data after the main object is rejected
  - Helps catch client bugs and typos early (e.g., `cluter` instead of `cluster`)

- **API Request Timeout Configuration**: Added configurable request timeout to frontend HTTP client (PR #304)
  - Default timeout of 30 seconds for all API requests (previously no timeout configured)
  - `ApiClientOptions.timeout` allows custom timeout configuration in milliseconds
  - Proper detection of timeout errors using Axios `ECONNABORTED` error code
  - Enhanced error logging includes timeout value when requests time out
  - Prevents requests from hanging indefinitely on slow or unresponsive backends

- **OIDC Token Cache Namespace Collision**: Fixed a bug where OIDC tokens for ClusterConfigs with the same name in different namespaces would collide in the cache, causing authentication failures or use of tokens for the wrong cluster (PR #301)
  - Tokens are now cached using `namespace/name` format instead of just `name`
  - Added `tokenCacheKey()` helper function for consistent cache key generation
  - `Invalidate()` now handles both old-style and new-style cache keys using suffix matching
  - Added `InvalidateWithNamespace()` for precise invalidation when namespace is known

- **Configurable REST Config Cache TTL**: Added environment variable configuration for REST config cache TTL (PR #295)
  - `BREAKGLASS_REST_CONFIG_CACHE_TTL`: Override default 5-minute TTL for OIDC cluster configs (e.g., "10m", "300s")
  - `BREAKGLASS_KUBECONFIG_CACHE_TTL`: Override default 15-minute TTL for kubeconfig-based configs
  - Logs warning to stderr when invalid duration strings are provided (falls back to default)
  - Enables tuning cache behavior for different deployment scenarios

- **Orphaned DebugSession Cleanup**: Fixed infinite retry loop when ClusterConfig is deleted while DebugSessions are still active
  - `cleanupResources` now gracefully handles `ErrClusterConfigNotFound` error
  - When target cluster no longer exists, cleanup is treated as complete instead of retrying every 5 seconds indefinitely
  - Clears `DeployedResources` and `AllowedPods` status fields since resources cannot be cleaned up anyway
  - Logs a warning to indicate the orphaned session was handled gracefully

### Changed

- **Approval Denial Responses**: Improved HTTP status codes and error messages for session approval denials
  - Return 403 Forbidden (not 401) when user is authenticated but not authorized to approve
  - Specific error messages for each denial reason: self-approval blocked, domain not allowed, not an approver
  - Frontend now receives actionable messages explaining why approval was denied

- **DebugSession Namespace Constraints**: Bindings can now override template namespace constraints
  - Binding's `namespaceConstraints.allowUserNamespace: true` overrides template's `false`
  - Binding's `allowedNamespaces` patterns are merged with template's patterns
  - Enables bindings to grant more namespace access than the base template allows

- **EscalatedGroup Pattern**: Allow colons (`:`) in `escalatedGroup` field to support breakglass group naming convention `breakglass:persona:scope:level` (e.g., `breakglass:platform:emergency`, `breakglass:tenant:myapp:poweruser`)

- **Self-Approval Block UI Enhancement**: Improved frontend indication for self-approval blocked scenarios
  - Dedicated warning notification with yellow styling instead of generic error
  - User-friendly message explaining security policy and next steps
  - Uses warning icon and styling to differentiate from other errors

### Added

- **DebugSessionClusterBinding Advanced Features**: Full implementation of binding lifecycle and session control fields
  - Time-bounded bindings: `expiresAt` and `effectiveFrom` fields control when bindings are active
  - Session limits: `maxActiveSessionsPerUser` and `maxActiveSessionsTotal` prevent resource exhaustion
  - UI control: `hidden` field hides bindings from UI, `priority` controls display ordering
  - Session metadata: `labels` and `annotations` propagated to created sessions and workloads
  - Reason configuration: `requestReason` and `approvalReason` with mandatory flags, length constraints, and suggested reasons
  - Notification configuration: `notification` field overrides template notification settings
  - API returns `isActive` status and time fields in binding list responses
  - `IsBindingActive()` function validates disabled state, expiry, and effective dates

- **Comprehensive Binding Matching Tests**: Added extensive test coverage for template and cluster matching
  - Tests for `matchExpressions` with In, NotIn, Exists, DoesNotExist operators
  - Tests for combined `matchLabels` and `matchExpressions`
  - Tests verifying precedence behavior when both explicit clusters and clusterSelector are set

- **Binding Resolution Documentation**: Enhanced documentation for binding discovery and constraint merging
  - Detailed explanation of template matching (templateRef vs templateSelector)
  - Detailed explanation of cluster matching (clusters vs clusterSelector)
  - Namespace constraints merge behavior now correctly documented as field-level merge
  - Examples of production patterns from schiff templates

- **DebugPodSpec Extended Fields**: All corev1.PodSpec scheduling and runtime fields now supported
  - `priorityClassName`, `runtimeClassName`, `preemptionPolicy` for resource priority
  - `topologySpreadConstraints` for pod distribution across failure domains
  - `shareProcessNamespace` for container process visibility
  - `hostAliases` for custom /etc/hosts entries
  - `imagePullSecrets` for private registry authentication
  - `enableServiceLinks` for service environment variable control
  - `schedulerName` for custom scheduler selection
  - `overhead` for pod resource overhead

- **ClusterConfig Deletion Session Cleanup**: Finalizer-based session cleanup when clusters are deleted
  - Adds `breakglass.t-caas.telekom.com/cluster-cleanup` finalizer to ClusterConfig resources
  - Automatically expires active BreakglassSessions targeting deleted clusters
  - Automatically fails active DebugSessions targeting deleted clusters
  - Preserves already-terminal session states (Expired, Rejected, etc.)
  - New `breakglass_cluster_configs_deleted_total` Prometheus metric
  - Prevents orphaned sessions when clusters are removed

- **Multiple Binding Options Support**: When multiple DebugSessionClusterBindings match the same cluster, all options are now presented to users
  - API returns `bindingOptions[]` array in cluster details with each binding's resolved configuration
  - Frontend displays binding selection cards only when multiple bindings are available
  - Users can select their preferred binding (e.g., "SRE Access" vs "On-Call Emergency") when creating debug sessions
  - Session creation accepts optional `bindingRef` as string format `namespace/name` for explicit binding selection
  - Backward compatible: primary `bindingRef` field still set for clients not using binding selection
  - CLI: New `bgctl debug template bindings <template> <cluster>` command shows all binding options for a cluster
  - CLI: `--binding namespace/name` flag on `debug session create` for explicit binding selection
  - CLI: `bgctl debug template clusters` now shows binding count and MAX_DURATION columns
  - Performance: Parallel API calls for ClusterConfig and DebugSessionClusterBinding fetching

### Changed

- **API Breaking Change**: `bindingRef` in `CreateDebugSessionRequest` changed from object `{name, namespace}` to string format `namespace/name`
  - Simpler API contract using standard Kubernetes namespaced name format
  - CLI and frontend updated to use new format

- **Binding Auto-Discovery Documentation**: Comprehensive documentation for DebugSessionClusterBinding resolution and config merging
  - Mermaid flow diagram showing binding resolution process
  - Detailed merge rules for all configuration fields
  - Edge case handling documentation
  - Debugging tips for binding resolution

- **Configurable IDP Hint Disclosure**: New `server.hardenedIDPHints` configuration option controls whether identity provider names are exposed in authorization error messages
  - Default (`false`): Lists available IDPs in error messages to help users troubleshoot authentication issues
  - Hardened (`true`): Returns generic error messages to prevent IDP reconnaissance

- **DebugSessionClusterBinding CRD**: Delegate debug session access across clusters with templated configurations
  - `spec.templateRef` / `spec.templateSelector`: Reference templates by name or label selector
  - `spec.clusters` / `spec.clusterSelector`: Target clusters by name or label selector
  - `spec.allowed` / `spec.approvers`: Override access control per binding
  - `spec.schedulingConstraintOverrides` / `spec.namespaceConstraintOverrides`: Cluster-specific overrides
  - `spec.auxiliaryResourceOverrides`: Control auxiliary resource deployment per cluster
  - Status tracks resolved templates, clusters, and active session count
  - ClusterBinding reconciler validates and resolves references
- **Auxiliary Resources for DebugSessionTemplate**: Deploy supporting resources alongside debug pods
  - `auxiliaryResources[]` in template spec defines resources to deploy
  - Go template rendering with session/cluster context using Sprig functions
  - Category-based organization (network-policy, rbac, configmap, secret, service, etc.)
  - Template-level defaults with per-resource and per-binding override capability
  - Required categories for mandatory resources (e.g., network isolation)
  - User-selectable optional resources with UI visibility control
  - AuxiliaryResourceManager handles deployment, tracking, and cleanup
  - Deployed resources tracked in session status with source field
  - Metrics for auxiliary resource deployments and failures
  - Audit events emitted for resource deployment and cleanup (`debug_session.resource_deployed`, `debug_session.resource_cleanup`)
- **DeployedResourceRef Source tracking**: Track origin of deployed resources in DebugSession status
  - `source` field indicates resource origin (e.g., "debug-pod", "auxiliary:network-policy")
  - `uid` field for precise resource identification
- **Namespace Constraints for DebugSessionTemplate**: Control where debug pods can be deployed
  - `namespaceConstraints.allowedNamespaces`: Pattern and label-based namespace filtering
  - `namespaceConstraints.deniedNamespaces`: Block specific namespaces (deny takes precedence)
  - `namespaceConstraints.defaultNamespace`: Default when user doesn't specify
  - `namespaceConstraints.allowUserNamespace`: Enable/disable user namespace selection
  - `namespaceConstraints.createIfNotExists`: Auto-create missing namespaces
  - API validates user-selected namespaces against template constraints
- **Impersonation for DebugSessionTemplate**: Deploy debug resources with constrained identity
  - `impersonation.serviceAccountRef`: Use existing ServiceAccount on spoke cluster
  - Enables least-privilege deployment patterns via pre-configured ServiceAccounts
- **Cluster Selector for DebugSessionTemplate**: Select clusters by labels (in addition to patterns)
  - `allowed.clusterSelector`: Label selector for dynamic cluster matching

  - Combined with `allowed.clusters` patterns (OR logic)
- **Resolved Fields in DebugSession**: Session stores resolved configuration at creation time
  - `spec.targetNamespace`: Resolved target namespace for debug pods
  - `spec.selectedSchedulingOption`: Name of selected scheduling option
  - `spec.resolvedSchedulingConstraints`: Merged constraints from template and option
  - Ensures consistent behavior even if template changes after session creation
- **Name Collision Detection for ClusterBindings**: Webhook validates unique display names across all bindings targeting the same template-cluster pair
  - `NameCollision` type with `EffectiveDisplayName`, `ConflictingBinding`, and severity
  - `GetEffectiveDisplayName()` and `CheckNameCollisions()` helper methods
- **Template Clusters API Endpoint**: `GET /templates/{name}/clusters` returns detailed cluster availability for templates
  - Resolves bindings, constraints, impersonation config per cluster
  - Includes scheduling options, namespace constraints, approval requirements
- **Impersonation Runtime Support**: Deploy debug resources using impersonated spoke cluster ServiceAccounts
  - `validateSpokeServiceAccount()`: Runtime validation of SA existence in spoke cluster
  - `createImpersonatedClient()`: Create Kubernetes client with impersonation
  - `resolveImpersonationConfig()`: Merge template and binding impersonation settings
- **CLI commands for templates and bindings**:
  - `bgctl debug template list` - List available debug session templates
  - `bgctl debug template get <name>` - Get template details
  - `bgctl debug template clusters <name>` - List available clusters for a template with resolved constraints
  - `bgctl debug binding list` - List cluster bindings with filtering by namespace/template/cluster
  - `bgctl debug binding get <name>` - Get binding details
  - `bgctl debug binding for-cluster <cluster>` - List bindings that apply to a specific cluster
- **Scheduling Constraints and Options for DebugSessionTemplate**: Enhanced scheduling control for debug pods
  - `schedulingConstraints`: Define mandatory node affinity, tolerations, topology spread, and denied node rules
  - `schedulingOptions`: Allow users to choose from predefined scheduling configurations (e.g., SRIOV vs standard nodes)
  - Support for `deniedNodes` (glob patterns) and `deniedNodeLabels` to block specific nodes
  - Option-level access control with `allowedGroups` and `allowedUsers`
  - Webhook validation for scheduling options (unique names, single default, required fields)
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
- Full integration test for `ScheduledSessionActivator.ActivateScheduledSessions()` covering session state transitions, email notifications, and edge cases

### Fixed

- **Helm chart documentation**: Fixed incorrect `kubeconfigSecretRef.key` default value in `charts/escalation-config/values.yaml` and `README.md` (was "kubeconfig", now correctly documents "value" for Cluster API compatibility)
- Align session ownership checks with configured user identifier claims to avoid duplicate or missing sessions.
- Guard against zero `retainedUntil` timestamps so sessions are not treated as retained immediately.
- Avoid startup panics on malformed email templates by returning controlled render errors.
- Ensure JWKS HTTP clients use timeouts to prevent auth verification hangs.
- Debug session notification settings now gate request/approval/expiry emails and honor additional/excluded recipients.
- Debug session template/binding labels and annotations now propagate to workloads and related resources.
- Debug session resource quotas and pod disruption budgets are now created and cleaned up when configured.

### Security

- Enforce authenticated identity matching for session requests to prevent username spoofing when token groups are missing.
- Limit webhook SubjectAccessReview request body size to reduce memory DoS risk.
- Enforce JWT signing algorithm allowlist during verification.
- Strip Authorization headers on optional-auth endpoints to reduce accidental token leakage in logs.
- Additional unit tests for `pkg/bgctl/cmd` config commands
- Additional unit tests for `pkg/bgctl/cmd` session commands
- Additional unit tests for `pkg/bgctl/cmd` update helpers
- Additional unit tests for `pkg/bgctl/cmd` update helpers (archive edge cases)
- Additional unit tests for `pkg/bgctl/cmd` client building
- **CLI Correlation ID logging**: All API requests now include `X-Correlation-ID` header and support verbose mode via `WithVerbose()` for CI debugging
- **CLI `--verbose` flag**: New `-v/--verbose` flag and `BGCTL_VERBOSE` environment variable for detailed request/response logging with correlation IDs
- CLI E2E tests now run with verbose mode enabled for better CI debugging
- **E2E Tests for ClusterBinding and Template Clusters API**: Comprehensive end-to-end tests for cluster bindings
  - `TestClusterBindingWithAuxiliaryResources` - Validates auxiliary resource configuration in bindings
  - `TestDebugSessionAPITemplateClusters` - Tests the template clusters API endpoint for the two-step wizard flow
- **Frontend Mock API for Template Clusters**: Mock data implementation for `GET /api/debugSessions/templates/:name/clusters`
  - Mock cluster metadata (environment, location, status)
  - Mock cluster bindings with constraints and approvals
  - `getTemplateClusters()` function for frontend development
- **Comprehensive ClusterBinding Documentation**: New dedicated documentation for DebugSessionClusterBinding
  - [docs/debug-session-cluster-binding.md](docs/debug-session-cluster-binding.md) with full specification reference
  - Use cases for multi-tenant access, environment-specific constraints, and least-privilege patterns
  - Integration with the template clusters API

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

### Removed

- **Per-session ServiceAccount support**: Removed `createPerSession`, `perSessionTemplate`, and `clusterRoleRef` from `ImpersonationConfig`
  - Use pre-existing ServiceAccounts via `serviceAccountRef` instead
  - Removed `perSessionServiceAccount` from `DebugSessionStatus`
  - Simplifies impersonation to use only pre-configured spoke cluster ServiceAccounts

### Fixed

- **Auxiliary resources now deployed and cleaned up**: Wired `AuxiliaryResourceManager` into `DebugSessionController` reconciler
  - Auxiliary resources are deployed after main workload creation using `DeployAuxiliaryResources()`
  - Auxiliary resources are cleaned up before main workload deletion using `CleanupAuxiliaryResources()`
  - Resources tracked in `status.auxiliaryResourceStatuses` with proper state management
- **Webhook validation for auxiliary resources**: Added `validateAuxiliaryResources()` to template validation
  - Validates unique names, non-empty templates, and valid categories
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
