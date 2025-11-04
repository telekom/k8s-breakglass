<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Documentation Index

This directory contains comprehensive documentation for the breakglass system.

## Quick Start

1. **[Webhook Setup](./webhook-setup.md)** - Configure Kubernetes authorization webhooks for your clusters
2. **[ClusterConfig](./cluster-config.md)** - Set up cluster connections and configuration
3. **[BreakglassEscalation](./breakglass-escalation.md)** - Create escalation policies and approval workflows

## Custom Resources

- **[ClusterConfig](./cluster-config.md)** - Configure and manage tenant clusters for breakglass integration
- **[BreakglassEscalation](./breakglass-escalation.md)** - Define who can request privileges, for which clusters, and who can approve
- **[BreakglassSession](./breakglass-session.md)** - Active or requested privilege escalation sessions
- **[DenyPolicy](./deny-policy.md)** - Explicit access restrictions that override other permissions

## Integration

- **[Webhook Setup](./webhook-setup.md)** - Complete guide for setting up Kubernetes authorization webhooks
- **[API Reference](./api-reference.md)** - REST API documentation for external integrations

## Architecture

The breakglass system consists of several key components:

### Hub Cluster

- **Breakglass Controller** - Manages custom resources and provides REST API
- **Frontend Application** - Web UI for users and approvers
- **ClusterConfig Resources** - Configuration for managed tenant clusters
- **BreakglassEscalation Resources** - Policy definitions for privilege escalation

### Tenant Clusters

- **Authorization Webhook** - Intercepts Kubernetes authorization requests
- **Webhook Configuration** - Points to breakglass controller for authorization decisions

### Flow Overview

1. **Policy Definition** - Administrators create `BreakglassEscalation` policies
2. **Cluster Configuration** - `ClusterConfig` resources define tenant cluster connections
3. **Session Request** - Users request elevated privileges through the frontend or API
4. **Approval Process** - Designated approvers review and approve/deny requests
5. **Active Session** - Approved sessions grant temporary elevated privileges
6. **Authorization** - Kubernetes webhook validates requests against active sessions
7. **Audit & Cleanup** - All activities are logged and sessions auto-expire

## Security Model

- **Principle of Least Privilege** - Users can only escalate to predefined groups
- **Time-Bounded Access** - All sessions have expiration times
- **Approval Required** - Sensitive escalations require explicit approval
- **Audit Logging** - All activities are logged for compliance
- **Deny Policies** - Explicit restrictions that cannot be overridden
- **Real-time Enforcement** - Authorization decisions made at request time

## Common Use Cases

### Emergency Production Access

- Site reliability engineers need temporary cluster-admin access during incidents
- Security team approves emergency requests outside business hours
- Sessions automatically expire after incident resolution

### Development Self-Service

- Developers can self-approve namespace-admin access in non-production environments
- Time-bounded access for debugging and troubleshooting
- Automatic approval for trusted environments

### Compliance and Auditing

- All privilege escalations are logged with justification
- Deny policies enforce regulatory requirements
- Regular access reviews through session history

### External Contractor Access

- Limited-time access for external contractors
- Require approval from contract managers
- Restrict to specific clusters and time windows

## Getting Help

- Check the specific resource documentation for detailed examples
- Review the [API Reference](./api-reference.md) for integration details  
- See the main [README.md](../README.md) for basic setup and configuration
- Look at sample configurations in the [config/samples/](../config/samples/) directory
