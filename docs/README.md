# Documentation Index

Complete documentation for the breakglass privilege escalation system.

## Getting Started

- **[Quick Start](./quickstart.md)** - Get up and running in 5 minutes
- **[Installation](./installation.md)** - Complete step-by-step installation
- **[Building](./building.md)** - Build breakglass from source
- **[CLI Flags Reference](./cli-flags-reference.md)** - All configuration flags
- **[Troubleshooting](./troubleshooting.md)** - Common issues and solutions

## Configuration & Operations

- **[Scaling and Leader Election](./scaling-and-leader-election.md)** - Multi-replica deployments with leader election
- **[Webhook Setup](./webhook-setup.md)** - Configure authorization webhooks
- **[CLI Flags Reference](./cli-flags-reference.md)** - All controller flags and environment variables
- **[Configuration Reference](./configuration-reference.md)** - config.yaml settings and examples
- **[Metrics](./metrics.md)** - Prometheus metrics and monitoring

## Quick Reference

1. [Webhook Setup](./webhook-setup.md) - Configure authorization webhooks
2. [ClusterConfig](./cluster-config.md) - Connect tenant clusters
3. [BreakglassEscalation](./breakglass-escalation.md) - Define escalation policies
4. [Advanced Features](./advanced-features.md) - Request reasons, self-approval prevention, domain restrictions

## Resources

- **[ClusterConfig](./cluster-config.md)** - Manage tenant cluster connections
- **[BreakglassEscalation](./breakglass-escalation.md)** - Define privilege escalation policies
- **[BreakglassSession](./breakglass-session.md)** - Active escalation sessions
- **[DenyPolicy](./deny-policy.md)** - Explicit access restrictions
- **[Webhook Setup](./webhook-setup.md)** - Authorization webhook configuration
- **[API Reference](./api-reference.md)** - REST API endpoints and usage
- **[Metrics](./metrics.md)** - Prometheus metrics and monitoring
- **[Advanced Features](./advanced-features.md)** - Request/approval reasons, self-approval prevention, domain restrictions

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                    Hub Cluster                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Breakglass Controller (webhook + API + policy)      │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  ClusterConfig  BreakglassEscalation  DenyPolicy     │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
                           │
                           │ (webhook endpoint)
                           ▼
┌──────────────────────────────────────────────────────────────┐
│              Tenant Cluster (any of many)                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Kubernetes API Server + Authorization Webhook      │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

## Workflow

1. **Policy** - Admins create `BreakglassEscalation` policies
2. **Request** - Users request elevated access
3. **Approval** - Approvers review and approve/deny
4. **Active** - Approved sessions grant temporary privileges
5. **Webhook** - Kubernetes validates requests against active sessions
6. **Expiry** - Sessions auto-expire after set duration

## Common Use Cases

- **Production Incidents** - Emergency cluster-admin access with approval
- **Development** - Self-service namespace-admin for debugging
- **Contractors** - Limited-time access with manager approval
- **Compliance** - All escalations logged and auditable

## Key Features

- Time-bounded access (expires automatically)
- Mandatory approvals for sensitive escalations
- Explicit deny policies override all permissions
- Real-time webhook-based authorization
- Complete audit trail for compliance
- Multi-cluster support
