# Breakglass Controller Samples

This directory contains sample YAML manifests for all Custom Resource Definitions (CRDs) provided by the Breakglass Controller.

## Validation

All samples in this directory are validated on every build to ensure they conform to the CRD schemas. To run validation manually:

```bash
make validate-samples
```

## Sample Categories

### Core Resources

| File | Description |
|------|-------------|
| `breakglass.t-cass.telekom.com_v1alpha1_breakglassescalation.yaml` | Basic escalation configurations |
| `breakglass_v1alpha1_breakglassescalation_advanced.yaml` | Advanced escalation features (multi-IDP, pod security overrides) |
| `breakglass_session_comprehensive.yaml` | Session examples including scheduled sessions |
| `telekom_v1alpha1_breakglasssession.yaml` | Basic session example |

### Cluster Configuration

| File | Description |
|------|-------------|
| `breakglass_v1alpha1_clusterconfig_kubeconfig.yaml` | Kubeconfig-based cluster authentication |
| `breakglass_v1alpha1_clusterconfig_oidc.yaml` | OIDC-based cluster authentication with token exchange |
| `breakglass_v1alpha1_clusterconfig_oidc_from_idp.yaml` | OIDC inherited from IdentityProvider |

### Identity Providers

| File | Description |
|------|-------------|
| `breakglass_v1alpha1_identityprovider_keycloak.yaml` | Keycloak with group synchronization |
| `breakglass_v1alpha1_identityprovider_oidc.yaml` | Pure OIDC without group sync |

### Mail Providers

| File | Description |
|------|-------------|
| `breakglass_v1alpha1_mailprovider.yaml` | SMTP configurations (default, critical alerts, dev) |

### Deny Policies

| File | Description |
|------|-------------|
| `breakglass_v1alpha1_denypolicy_comprehensive.yaml` | Comprehensive deny policy examples |
| `breakglass_v1alpha1_denypolicy_podsecurity.yaml` | Pod security risk evaluation |
| `breakglass_v1alpha1_denypolicy_namespace_selectors.yaml` | Namespace label-based selectors |

### Audit Configuration

| File | Description |
|------|-------------|
| `audit_config_kafka.yaml` | Kafka sink with TLS/SASL, webhook, and multi-sink examples |
| `audit_config_namespace_selectors.yaml` | Namespace-based filtering with label selectors |

### Debug Sessions

| File | Description |
|------|-------------|
| `debug_session_templates.yaml` | DebugSessionTemplate examples (workload, kubectl-debug, hybrid modes) |
| `debug_session_template_namespace_selectors.yaml` | Templates with namespace filtering |
| `debug_pod_templates.yaml` | DebugPodTemplate examples |
| `debug-pod-template-minimal.yaml` | Minimal debug pod |
| `debug-pod-template-network.yaml` | Network debugging tools |
| `debug-pod-template-log-inspector.yaml` | Log inspection tools |
| `debug_sessions.yaml` | DebugSession examples |

## Feature Coverage

These samples demonstrate the following key features:

### BreakglassEscalation
- Basic escalation configuration
- Multi-IDP split control (different IDPs for requests vs approvals)
- Pod security overrides for trusted groups
- Notification exclusions
- Custom mail providers per escalation
- Approval timeouts
- Block self-approval

### ClusterConfig
- Kubeconfig-based authentication
- OIDC client credentials flow
- OIDC token exchange
- OIDC inherited from IdentityProvider
- Multi-IDP restrictions per cluster

### IdentityProvider
- OIDC authentication
- Keycloak group synchronization
- Multi-provider support

### DenyPolicy
- Basic deny rules (verbs, resources, namespaces)
- Pod security risk evaluation with thresholds
- Namespace label selectors
- Cluster/tenant scoping
- Session-specific policies

### AuditConfig
- Kafka sink with TLS and SASL
- Webhook sink for SIEM integration
- Kubernetes Events sink
- Structured log sink
- Event filtering and sampling
- Namespace-based filtering

### DebugSessionTemplate
- Workload mode (DaemonSet/Deployment)
- Kubectl-debug mode (ephemeral containers)
- Hybrid mode
- Auto-approval configuration
- Namespace restrictions

### BreakglassSession
- Basic session requests
- Scheduled sessions (future activation)
- IDP tracking
- Deny policy attachments

## Usage

Apply samples to a cluster with:

```bash
kubectl apply -f config/samples/<sample-file>.yaml
```

**Note:** Most samples require supporting resources like Secrets. For examples, we prefer `stringData` with placeholder values to avoid base64 encoding mistakes.

These samples are for documentation/manual usage and schema validation; the E2E harness uses `config/dev/` resources and does not apply `config/samples/`.

## Contributing

When adding or modifying samples:

1. Ensure the sample validates: `make validate-samples`
2. Add comments explaining the configuration
3. Include example Secrets with placeholder values where needed
4. Update this README if adding new sample files
