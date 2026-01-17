# Documentation Index

Complete documentation for the breakglass privilege escalation system.

## Getting Started

- **[Quick Start](./quickstart.md)** - Get up and running in 5 minutes
- **[End-to-End Example](./end-to-end-example.md)** - Complete production deployment walkthrough
- **[Installation](./installation.md)** - Complete step-by-step installation
- **[Use Cases](./use-cases.md)** - Real-world use cases with configuration examples
- **[Building](./building.md)** - Build breakglass from source
- **[Troubleshooting](./troubleshooting.md)** - Common issues and solutions

## Configuration & Operations

- **[Configuration Reference](./configuration-reference.md)** - config.yaml settings and examples
- **[CLI Flags Reference](./cli-flags-reference.md)** - All controller flags and environment variables
- **[Scaling and Leader Election](./scaling-and-leader-election.md)** - Multi-replica deployments with leader election
- **[Webhook Setup](./webhook-setup.md)** - Configure authorization webhooks
- **[Metrics](./metrics.md)** - Prometheus metrics and monitoring
- **[Logging and Debugging](./logging-and-debugging.md)** - Frontend and backend logging infrastructure, debugging tips

## Identity & Authentication

- **[Identity Provider](./identity-provider.md)** - OIDC configuration and multi-IDP setup
- **[Advanced Features - Multi-IDP Guide](./advanced-features.md#multi-idp-configuration-guide)** - Multiple identity provider configuration and best practices

## Email Notifications

- **[Mail Provider](./mail-provider.md)** - SMTP configuration for email notifications
- **[Email Templates](./email-templates.md)** - Customize and override email notification templates

## Quick Reference

1. [Webhook Setup](./webhook-setup.md) - Configure authorization webhooks
2. [ClusterConfig](./cluster-config.md) - Connect tenant clusters
3. [BreakglassEscalation](./breakglass-escalation.md) - Define escalation policies
4. [Advanced Features](./advanced-features.md) - Request reasons, self-approval prevention, domain restrictions

## Resources

- **[ClusterConfig](./cluster-config.md)** - Manage tenant cluster connections
- **[BreakglassEscalation](./breakglass-escalation.md)** - Define privilege escalation policies
- **[BreakglassSession](./breakglass-session.md)** - Active escalation sessions
- **[Debug Session](./debug-session.md)** - Debug pod deployments and kubectl debug access
- **[DenyPolicy](./deny-policy.md)** - Explicit access restrictions
- **[AuditConfig](./audit-config.md)** - Configure audit sinks (Kafka, webhooks, logs)
- **[IdentityProvider](./identity-provider.md)** - OIDC identity provider configuration
- **[MailProvider](./mail-provider.md)** - SMTP mail provider configuration
- **[Webhook Setup](./webhook-setup.md)** - Authorization webhook configuration
- **[API Reference](./api-reference.md)** - REST API endpoints and usage
- **[Metrics](./metrics.md)** - Prometheus metrics and monitoring
- **[Advanced Features](./advanced-features.md)** - Request/approval reasons, self-approval prevention, domain restrictions

## Security & Policy

- **[Security Best Practices](./security-best-practices.md)** - Rate limiting, input sanitization, network security
- **Frontend input sanitization** - Request reason sanitization and duration parsing are centralized in shared UI utilities for consistent validation.
- **[DenyPolicy](./deny-policy.md)** - Explicit access restrictions and pod security rules
- **[Pod Security Evaluation](./deny-policy.md#podsecurityrules)** - Risk-based exec/attach/portforward controls
- **[BreakglassEscalation - Security Overrides](./breakglass-escalation.md#podsecurityoverrides)** - Per-escalation pod security exemptions

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
