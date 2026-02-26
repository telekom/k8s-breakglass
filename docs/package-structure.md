# Package Structure — `pkg/breakglass/`

This document describes the sub-package layout of the core `pkg/breakglass/`
package after the god-package refactoring ([#416](https://github.com/telekom/k8s-breakglass/issues/416)).

## Overview

```
pkg/breakglass/              Root — session controller, group checking, identity, scheme
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
