# Kubernetes Breakglass

[![](https://img.shields.io/badge/license-Apache%20License%202.0-blue)](https://img.shields.io/badge/license-Apache%20License%202.0-blue)
[![REUSE Compliance Check](https://github.com/telekom/k8s-breakglass/actions/workflows/reuse-compliance.yml/badge.svg)](https://github.com/telekom/k8s-breakglass/actions/workflows/reuse-compliance.yml)
[![OpenSSF Scorecard Score](https://api.scorecard.dev/projects/github.com/telekom/k8s-breakglass/badge)](https://scorecard.dev/viewer/?uri=github.com/telekom/k8s-breakglass)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11553/badge)](https://www.bestpractices.dev/projects/11553)
[![codecov](https://codecov.io/github/telekom/k8s-breakglass/graph/badge.svg?token=OJLpw2PNDW)](https://codecov.io/github/telekom/k8s-breakglass)

**Kubernetes Breakglass** is a secure, auditable privilege escalation system for Kubernetes clusters. It enables users to request temporary elevated access through a structured approval workflow, with real-time webhook integration for immediate Kubernetes RBAC enforcement.

## 🎯 Key Features

- **Request-Approval Workflow** - Users request access, approvers review and grant temporary privileges
- **Real-time Authorization Webhook** - Integrated with Kubernetes' authorization system for immediate enforcement
- **Time-Bounded Access** - Sessions expire automatically after configured duration
- **Audit Trail** - Full history of requests, approvals, and access events
- **Audit Sinks** - Kafka/webhook/log/Kubernetes audit outputs via `AuditConfig`
- **Flexible Authorization** - Define escalations, approvers, and access restrictions using Kubernetes CRDs
- **Multi-Cluster Support** - Centralized hub manages access across multiple spoke clusters
- **OIDC/JWT Authentication** - Integrates with identity providers like Keycloak and Azure AD
- **Web UI, CLI & REST API** - User-friendly web interface, `bgctl` command-line tool, and programmatic access
- **Command-Line Interface (`bgctl`)** - Terminal-based access for automation and scripting
- **Debug Sessions** - Time-bounded debug pods and kubectl-debug workflows
- **Automatic Cluster Cache Invalidation** - Watches ClusterConfig and kubeconfig Secret changes to refresh connectivity instantly
- **Rich Prometheus Signals** - API endpoints expose dedicated request/error/duration metrics for fine-grained SLOs

## Architecture

**Components:**

- **Backend Service** - Go REST API server with Kubernetes webhook support
- **Frontend** - TypeScript/Vue web application for request management
- **CLI Tool (`bgctl`)** - Command-line interface for automation and terminal access
- **Custom Resources** - Configuration and persistence via Kubernetes CRDs:
  - `BreakglassEscalation` - Define available privilege escalations
  - `BreakglassSession` - Track active sessions
  - `ClusterConfig` - Configure managed clusters
  - `DenyPolicy` - Restrict access by policy
  - `AuditConfig` - Configure audit sinks (Kafka, webhook, log, Kubernetes)
  - `IdentityProvider` - OIDC provider configuration and group sync
  - `MailProvider` - Email notification configuration
  - `DebugSession` - Debug session lifecycle
  - `DebugSessionTemplate` - Debug session templates
  - `DebugPodTemplate` - Debug pod templates

**Design:** Hub-and-spoke topology where a central breakglass service manages temporary access for multiple Kubernetes clusters.

## 📚 Documentation

Complete documentation is available in the [docs/](./docs/) directory:

**Getting Started:**

- **[Quick Start](./docs/quickstart.md)** - Get running in 5 minutes
- **[Installation](./docs/installation.md)** - Complete step-by-step installation guide
- **[Building](./docs/building.md)** - Build from source and run tests

**Resources & Configuration:**

- **[IdentityProvider](./docs/identity-provider.md)** - **MANDATORY** - Configure OIDC authentication for users
- **[BreakglassEscalation](./docs/breakglass-escalation.md)** - Define available privilege escalations
- **[BreakglassSession](./docs/breakglass-session.md)** - Session lifecycle and state management
- **[ClusterConfig](./docs/cluster-config.md)** - Configure managed clusters
- **[DenyPolicy](./docs/deny-policy.md)** - Create access restrictions and policies
- **[AuditConfig](./docs/audit-config.md)** - Configure audit sinks (Kafka, webhooks, logs)
- **[MailProvider](./docs/mail-provider.md)** - Email notification configuration
- **[Debug Session](./docs/debug-session.md)** - Debug sessions and templates

**Integration & Advanced Topics:**

- **[Webhook Setup](./docs/webhook-setup.md)** - Integrate with Kubernetes authorization
- **[CLI Tool (bgctl)](./docs/cli.md)** - Command-line interface for terminal access and automation
- **[API Reference](./docs/api-reference.md)** - REST API endpoints and examples
- **[Metrics](./docs/metrics.md)** - Prometheus metrics, alerting, and dashboards
- **[Advanced Features](./docs/advanced-features.md)** - Request reasons, approval reasons, self-approval prevention, domain restrictions
- **[Troubleshooting](./docs/troubleshooting.md)** - Common issues and solutions

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for contribution requirements, testing policy, and review expectations.

## 📦 Example Assets

- **[DenyPolicy examples](./config/deny-policy-examples.yaml)** - Ready-to-use templates covering exfiltration, operational safety, and compliance controls

## ⚙️ Configuration

The application is configured via a `config.yaml` file. See [`config.example.yaml`](./config.example.yaml) for a complete example.

**Core Configuration:**

```yaml
server:
  listenAddress: :8080
  tlsCertFile: /etc/tls/cert.crt      # optional
  tlsKeyFile: /etc/tls/key.key        # optional, for HTTPS

frontend:
  baseURL: https://breakglass.example.com
  brandingName: "My Breakglass"       # optional
  uiFlavour: "oss"                    # optional: "oss", "telekom", or "neutral"

kubernetes:
  context: ""                         # kubectl config context (empty = default)
  oidcPrefixes:                       # Prefixes to strip from OIDC groups
    - "keycloak:"
    - "oidc:"
```

**Notes:**

- **OIDC/IDP authentication** is managed via **IdentityProvider CRDs**. See [Identity Provider documentation](docs/identity-provider.md) for details.
- **Email notifications** are managed via **MailProvider CRDs**. See [Mail Provider documentation](docs/mail-provider.md) for details.
- Email notifications can be disabled with `--disable-email` when MailProvider is not configured.

### OIDC Group Prefix Handling

When users authenticate via OIDC providers like Keycloak, groups often include provider-specific prefixes (e.g., `keycloak:admin`, `oidc:developers`). Kubernetes RBAC typically uses clean group names (e.g., `admin`, `developers`).

The `oidcPrefixes` configuration automatically strips these prefixes when matching user groups to escalation rules.

**Example Flow:**

| Step | Value |
|------|-------|
| 1. User's OIDC groups | `["keycloak:admin", "keycloak:developers"]` |
| 2. After prefix stripping | `["admin", "developers"]` |
| 3. Matched against escalations | Uses clean names like `admin` |

This ensures escalation policies reference clean group names, independent of the OIDC provider.

## 🚀 Deployment

### Quick Start

Get breakglass running in 5 minutes with the dev deployment:

```bash
# Deploy to local kind cluster with Keycloak and MailHog
make docker-build-dev                   # build dev image
kind create cluster                     # create local kind cluster
kind load docker-image breakglass:dev   # load dev image into kind cluster
make install                            # install CRDs
make deploy_dev                         # deploy breakglass and dependencies

# Access the application
# Breakglass UI:  https://breakglass-dev:30081
# Keycloak:       https://breakglass-dev:30083
# MailHog:        http://breakglass-dev:30084
```

For production deployment, see the [Installation Guide](./docs/installation.md).

### Production Deployment

```bash
# Edit configuration
cp config.example.yaml config/default/config.yaml
# ... customize settings ...

# Deploy CRDs, RBAC, and application
make deploy
```

See [Installation Guide](./docs/installation.md) for detailed setup steps.

### Building from Source

**OSS Flavour (Recommended):**

```bash
# Build backend and OSS UI
docker build -t breakglass:latest .

# Or build just the backend
go build -o bin/breakglass ./cmd/...
```

**UI Customization:**

The frontend uses the [telekom/scale](https://github.com/telekom/scale) framework. See its [theming documentation](https://telekom.github.io/scale/?path=/docs/guidelines-customization-and-themes--page) for customization options.

#### ⚠️ Telekom UI Flavour

The Telekom branded UI (`UI_FLAVOUR=telekom`) is proprietary to Deutsche Telekom and **must NOT be used outside Deutsche Telekom entities**.

- Contains proprietary Deutsche Telekom branding and customizations
- Unauthorized use violates Deutsche Telekom's intellectual property rights
- All non-Telekom organizations must use the OSS flavour (default)
- The OSS flavour is fully functional and appropriate for all organizations

## 🔗 Webhook Integration

The authorization webhook enables real-time enforcement of breakglass sessions. When a user attempts an action on a managed cluster, the webhook is called to determine if they have an active session granting the requested access.

**Setup Overview:**

1. Configure the cluster's API server to use the breakglass webhook as an authorization plugin
2. Create webhook kubeconfig pointing to the breakglass service
3. Create `ClusterConfig` resource defining the cluster relationship

See [Webhook Setup Guide](./docs/webhook-setup.md) for complete configuration instructions.

**API Server Configuration Example:**

```yaml
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
  - type: Node
    name: node
  - type: RBAC
    name: rbac
  - type: Webhook
    name: breakglass
    webhook:
      unauthorizedTTL: 30s
      timeout: 3s
      failurePolicy: Deny
      connectionInfo:
        type: KubeConfigFile
        kubeConfigFile: /etc/kubernetes/breakglass-authz.kubeconfig
```

## 📖 Custom Resources

### BreakglassEscalation

Defines available privilege escalations for users. Specifies target groups, approvers, and constraints.

- **Example:** "Allow developers to request temporary cluster-admin access for 2 hours"
- **Approvers:** Can be individuals or groups
- **Constraints:** Max duration, request reasons, self-approval policy

See [BreakglassEscalation Documentation](./docs/breakglass-escalation.md) for details.

### BreakglassSession

Represents an active or historical privilege escalation request. Tracks state through the approval workflow.

- **Lifecycle:** Pending → Approved/Rejected → Expired/Withdrawn
- **Audit Trail:** Request time, approver, reason, expiration
- **Managed by:** Breakglass API (users don't create directly)

See [BreakglassSession Documentation](./docs/breakglass-session.md) for details.

### ClusterConfig

Configures a managed cluster's relationship to the breakglass hub.

- **Purpose:** Define cluster identity and webhook endpoint
- **Usage:** Connect managed clusters to the central breakglass service

See [ClusterConfig Documentation](./docs/cluster-config.md) for details.

### DenyPolicy

Restrict access across clusters and namespaces based on resource attributes.

- **Example:** "Deny access to secrets namespace"
- **Scope:** Cluster-wide or tenant-scoped
- **Precedence:** Evaluated before escalations

See [DenyPolicy Documentation](./docs/deny-policy.md) for details.

## Code of Conduct

This project has adopted the [Contributor Covenant](https://www.contributor-covenant.org/) in version 2.1 as our code of conduct. Please see the details in our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). All contributors must abide by the code of conduct.

By participating in this project, you agree to abide by its [Code of Conduct](./CODE_OF_CONDUCT.md) at all times.

## License

Copyright (c) Deutsche Telekom AG

All content in this repository is licensed under at least one of the licenses found in [./LICENSES](./LICENSES); you may not use this file, or any other file in this repository, except in compliance with the Licenses.
You may obtain a copy of the Licenses by reviewing the files found in the [./LICENSES](./LICENSES) folder.

Unless required by applicable law or agreed to in writing, software distributed under the Licenses is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See in the [./LICENSES](./LICENSES) folder for the specific language governing permissions and limitations under the Licenses.

This project follows the [REUSE standard for software licensing](https://reuse.software/). Each file contains copyright and license information, and license texts can be found in the [./LICENSES](./LICENSES) folder. For more information, visit [https://reuse.software/](https://reuse.software/).

You can find a guide for developers at [https://telekom.github.io/reuse-template/](https://telekom.github.io/reuse-template/).
