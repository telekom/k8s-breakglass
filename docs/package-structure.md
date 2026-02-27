# Package Structure — `pkg/breakglass/`

This document describes the sub-package layout of the core `pkg/breakglass/`
package after the god-package refactoring ([#416](https://github.com/telekom/k8s-breakglass/issues/416))
and the god-function decomposition ([#417](https://github.com/telekom/k8s-breakglass/issues/417)).

## Overview

```
pkg/breakglass/              Root — session controller, group checking, identity, scheme
│   session_request_helpers.go   Extracted helpers for handleRequestBreakglassSession
├── clusterconfig/           Cluster config checker & binding API
├── debug/                   Debug session API, reconciler, kubectl exec
├── escalation/              Escalation controller, manager, status updater
└── eventrecorder/           Kubernetes event recorder wrapper
```

## Import Graph

```
                     ┌──────────────┐
                     │    root      │
                     │ (breakglass) │
                     └──────┬───────┘
          ┌─────────────────┼─────────────────┐
          │                 │                  │
          ▼                 ▼                  ▼
  ┌───────────────┐ ┌─────────────┐ ┌──────────────────┐
  │ clusterconfig │ │    debug    │ │    escalation     │
  │               │ │             │ │                   │
  │ (no root dep) │ │ imports root│ │  imports root     │
  └───────────────┘ └─────────────┘ └──────────────────┘

  ┌───────────────┐
  │ eventrecorder │
  │               │
  │ (no root dep) │
  └───────────────┘
```

**Key constraint:** Root files (`package breakglass`) must **not** import any
sub-package that itself imports root.  The `EscalationLookup` interface in
`escalation_lookup.go` breaks the dependency between root and `escalation/`.

## Sub-packages

### `clusterconfig/`

| File | Description |
|------|-------------|
| `doc.go` | Package documentation |
| `checker.go` | `ClusterConfigChecker` — periodic reconciliation of `ClusterConfig` resources |
| `binding_api.go` | REST handlers for cluster-binding operations |

### `debug/`

| File | Description |
|------|-------------|
| `doc.go` | Package documentation |
| `interfaces.go` | Interfaces consumed by the debug sub-package |
| `debug_session_api.go` | Gin handlers for debug-session CRUD |
| `debug_session_api_constraints.go` | Constraint validation helpers |
| `debug_session_api_email_ops.go` | Email notification operations |
| `debug_session_api_resolution.go` | Template and cluster resolution logic |
| `debug_session_api_session_ops.go` | Session create/update/delete operations |
| `debug_session_api_templates.go` | Template listing and lookup |
| `debug_session_kubectl.go` | `kubectl exec` command builder |
| `debug_session_reconciler.go` | Controller-runtime reconciler for `DebugSession` resources |
| `debug_session_reconciler_lifecycle.go` | Reconciler lifecycle transitions |
| `debug_session_reconciler_rendering.go` | Pod template rendering logic |
| `debug_session_reconciler_workload.go` | Workload (DaemonSet/Deployment) management |
| `auxiliary_resource_manager.go` | Manages auxiliary resources for debug sessions |
| `template_renderer.go` | Go template rendering with Sprig functions |

### `escalation/`

| File | Description |
|------|-------------|
| `doc.go` | Package documentation |
| `escalation_controller.go` | `BreakglassEscalationController` — Gin REST handlers |
| `escalation_manager.go` | `EscalationManager` — escalation lookup and caching |
| `escalation_status_updater.go` | `EscalationStatusUpdater` — periodic status reconciliation |
| `escalation.go` | Shared helpers and constants |

### `eventrecorder/`

| File | Description |
|------|-------------|
| `doc.go` | Package documentation |
| `event_recorder.go` | `K8sEventRecorder` — thin wrapper around `client-go` event recording |

## The `EscalationLookup` Interface

Defined in the root package (`escalation_lookup.go`), this interface abstracts
the methods the session controller needs from `EscalationManager`:

```go
type EscalationLookup interface {
    GetClusterBreakglassEscalations(ctx, cluster) ([]BreakglassEscalation, error)
    GetClusterGroupBreakglassEscalations(ctx, cluster, groups) ([]BreakglassEscalation, error)
    GetResolver() GroupMemberResolver
    SetResolver(resolver GroupMemberResolver)
}
```

This lets `session_controller.go` reference escalation behaviour without
importing the `escalation/` sub-package, avoiding an import cycle.

## God-Function Decomposition (#417)

Three large controller functions were decomposed into focused helpers:

### `pkg/webhook/authorize_helpers.go`

Extracted from `handleAuthorize` in `controller.go` (706 → 46 lines).

| Symbol | Description |
|--------|-------------|
| `authorizeState` | Per-request state struct carrying SAR, phases, flags |
| `parseSARRequest` | Decode and validate the SubjectAccessReview body |
| `resolveClusterConfig` | Look up cluster configuration for the request |
| `logSARAction` | Emit structured log of SAR verb/resource/namespace |
| `loadSessionsAndGroups` | Fetch active sessions and user groups |
| `checkEarlyDebugSession` | Short-circuit allow for debug session pod exec |
| `evaluateDenyPolicies` | Evaluate deny-policy rules and global deny |
| `buildDenyPolicyReason` | Construct the human-readable deny reason string |
| `performRBACCheck` | Run the standard RBAC check via `canDoFn` using the user's groups |
| `resolveSessionAuthorization` | Merge escalation, IDP filtering, and session decisions |
| `buildFinalReason` | Assemble the final allowed/denied reason |
| `sendAuthorizationResponse` | Marshal and write the JSON response |

### `pkg/breakglass/session_request_helpers.go`

Extracted from `handleRequestBreakglassSession` in `session_controller.go` (~760 → ~140 lines).

| Symbol | Description |
|--------|-------------|
| `authenticatedIdentity` | Struct holding resolved email + username + error |
| `escalationResolutionResult` | Struct aggregating matched escalation and approvers |
| `sessionCreateParams` | Struct bundling spec, request, user info for session creation |
| `resolveAuthenticatedIdentity` | Extract email and username from gin context claims |
| `resolveUserGroups` | Fetch user's group memberships |
| `fetchMatchingEscalations` | Look up escalations for cluster + group |
| `collectApproversFromEscalations` | Walk escalations, collect approvers, find matched escalation |
| `resolveAndAddGroupMembers` | Expand group-based approvers to individual users |
| `checkDuplicateSession` | Return 409 if an active session already exists |
| `resolveUserIdentifierClaim` | Extract user identifier from JWT claims |
| `buildSessionSpec` | Construct the `BreakglassSessionSpec` |
| `createAndPersistSession` | Create the k8s resource and update escalation status |
| `sendSessionNotifications` | Send approval-request emails and update metrics |

### `cmd/main.go`

Extracted from `main()` into `run() error` plus 7 helpers and 2 structs.

| Symbol | Description |
|--------|-------------|
| `services` | Struct holding all runtime service references |
| `backgroundDeps` | Struct holding dependencies for background goroutines |
| `setupServices` | Wire all controllers, managers, and middleware |
| `createEventRecorder` | Build the Kubernetes event recorder |
| `createLeaderElectionLock` | Build the leader-election lease lock |
| `startBackgroundRoutines` | Launch goroutines for cleanup, certs, etc. |
| `startCertManagerIfNeeded` | Conditionally start the TLS cert file watcher |
| `awaitShutdownSignal` | Block on SIGINT/SIGTERM or fatal error |
| `shutdownServices` | Gracefully drain background goroutines |
