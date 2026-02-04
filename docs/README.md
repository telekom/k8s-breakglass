# Documentation Index

Complete documentation for the breakglass privilege escalation system.

## Getting Started

- **[Quick Start](./quickstart.md)** - Get up and running in 5 minutes
- **[End-to-End Example](./end-to-end-example.md)** - Complete production deployment walkthrough
- **[Installation](./installation.md)** - Complete step-by-step installation
- **[Use Cases](./use-cases.md)** - Real-world use cases with configuration examples
- **[Building](./building.md)** - Build breakglass from source
- **[CLI Tool (bgctl)](./cli.md)** - Command-line interface for terminal access and automation
- **[Troubleshooting](./troubleshooting.md)** - Common issues and solutions

## Deployment & Operations

- **[Deployment Targets](./deployment-targets.md)** - Kustomize targets (base, debug, dev) and manifest generation
- **[Production Deployment Checklist](./production-deployment-checklist.md)** - Pre-production readiness verification
- **[Upgrade Guide](./upgrade-guide.md)** - Version upgrades, migration, and rollback procedures
- **[Configuration Reference](./configuration-reference.md)** - config.yaml settings and examples
- **[CLI Flags Reference](./cli-flags-reference.md)** - All controller flags and environment variables
- **[Ingress Configuration](./ingress-configuration.md)** - CORS, security headers, and reverse proxy setup
- **[Scaling and Leader Election](./scaling-and-leader-election.md)** - Multi-replica deployments with leader election
- **[Webhook Setup](./webhook-setup.md)** - Configure authorization webhooks
- **[Metrics](./metrics.md)** - Prometheus metrics and monitoring
- **[Logging and Debugging](./logging-and-debugging.md)** - Frontend and backend logging infrastructure, debugging tips
- **[CI Logs and Artifacts](./ci-logs.md)** - Retrieve CI logs and artifacts with gh CLI

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
- **[Debug Session Cluster Bindings](./debug-session-cluster-binding.md)** - Delegate template access to teams and clusters
- **[Extra Deploy Variables](./extra-deploy-variables.md)** - User-provided variables for customizable templates
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

## Development & Maintenance

- **[Technical Debt](./TECHNICAL_DEBT.md)** - Known TODOs, future enhancements, and maintenance tracking
- **[Release Process](./release-process.md)** - Release signing, provenance, and checklist

## Contributing

- **[Contributing Guide](../CONTRIBUTING.md)** - Contribution requirements, test policy, and review process

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
- Scheduled sessions with deferred activation
- Debug sessions and debug pod templates
- Multi-IDP support with optional group sync
- CLI automation via `bgctl`
- Request modals reset to a clean state when closed for consistent UX

## Deployment Modes

Breakglass supports multiple deployment patterns via component enable flags. See the
[Installation](./installation.md) and [CLI Flags Reference](./cli-flags-reference.md) for full examples.

- **Monolithic (default)**: frontend + API + SAR webhook + cleanup + validating webhooks
- **Webhook-only**: validating webhooks only (CRD validation)
- **API-only**: frontend + API + SAR webhook (no validating webhooks)
- **Frontend-only**: web UI only
- **Cleanup-only**: background cleanup routine only
