# MailProvider

The **MailProvider** Custom Resource Definition (CRD) allows you to configure multiple SMTP mail providers for sending breakglass notification emails. This provides flexibility in mail delivery, allows per-cluster or per-escalation provider selection, and enables high availability through provider failover.

## Overview

MailProvider replaces the legacy `mail` configuration from `config.yaml` with a CRD-based approach that provides:

- **Multiple Providers**: Configure multiple SMTP servers and select per-escalation or per-cluster
- **Automatic Reconciliation**: Changes to MailProvider CRs are automatically reloaded without restart
- **Health Checking**: Built-in SMTP connection and authentication health checks with status reporting
- **Provider-Aware Metrics**: Prometheus metrics track email operations per provider
- **Secret-Based Credentials**: SMTP passwords stored securely in Kubernetes Secrets

## Architecture

```
┌─────────────────┐
│ BreakglassEsc   │─┐
│ mailProvider:   │ │
│   "urgent-mail" │ │  Priority Selection
└─────────────────┘ │  1. Escalation provider
                    ├─→ 2. Cluster provider
┌─────────────────┐ │  3. Default provider
│ ClusterConfig   │ │
│ mailProvider:   │ │
│   "cluster-mail"│─┘
└─────────────────┘
         │
         ├─────────────────┐
         ↓                 ↓
┌──────────────────┐  ┌──────────────────┐
│ MailProvider     │  │ MailProvider     │
│ name: urgent     │  │ name: default    │
│ default: false   │  │ default: true    │
└──────────────────┘  └──────────────────┘
```

## Specification

### MailProviderSpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `displayName` | string | No | Human-readable name for this provider |
| `default` | bool | No | Mark as default provider (only one should be true) |
| `disabled` | bool | No | Temporarily disable provider without deleting |
| `smtp` | SMTPConfig | Yes | SMTP server configuration |
| `sender` | SenderConfig | Yes | Email sender information |
| `retry` | RetryConfig | No | Retry and queue configuration |

### SMTPConfig

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `host` | string | Yes | SMTP server hostname (1-253 chars) |
| `port` | int | Yes | SMTP port (1-65535), common: 587, 465, 25 |
| `username` | string | No | SMTP authentication username |
| `passwordRef` | SecretKeyReference | No | Reference to secret containing password |
| `insecureSkipVerify` | bool | No | Skip TLS cert verification (testing only!) |
| `certificateAuthority` | string | No | PEM-encoded CA certificate for TLS |

**Validation Rules:**
- If `username` is set, `passwordRef` must be provided
- If `passwordRef` is set, `username` must be provided
- Port must be between 1 and 65535
- Host must be 1-253 characters

### SenderConfig

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `address` | string | Yes | Email address (3-254 chars, valid format) |
| `name` | string | No | Display name (max 100 chars) |

**Validation Rules:**
- Address must match email regex pattern
- Address length: 3-254 characters

### RetryConfig

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `count` | int | No | 3 | Number of retry attempts (0-10) |
| `initialBackoffMs` | int | No | 100 | Initial backoff in milliseconds (10-60000) |
| `queueSize` | int | No | 1000 | Max pending emails in queue (10-10000) |

## Status

### MailProviderStatus

| Field | Type | Description |
|-------|------|-------------|
| `conditions` | []Condition | Standard Kubernetes conditions |
| `lastHealthCheck` | Time | Timestamp of last successful health check |
| `lastSendAttempt` | Time | Timestamp of last email send attempt |
| `lastSendError` | string | Error message from last failed send |

### Conditions

| Type | Description |
|------|-------------|
| `Ready` | MailProvider is configured and ready to use |
| `Healthy` | Last health check succeeded (SMTP connection + auth) |
| `PasswordLoaded` | Password successfully loaded from secret |

## Examples

### Basic Configuration

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: MailProvider
metadata:
  name: default-smtp
spec:
  displayName: "Production SMTP"
  default: true
  smtp:
    host: smtp.example.com
    port: 587
    username: breakglass@example.com
    passwordRef:
      name: smtp-secret
      key: password
  sender:
    address: noreply@example.com
    name: "Breakglass Notifications"
---
apiVersion: v1
kind: Secret
metadata:
  name: smtp-secret
type: Opaque
stringData:
  password: "your-secure-password"
```

### Multiple Providers

```yaml
# Default provider for most emails
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: MailProvider
metadata:
  name: standard-mail
spec:
  displayName: "Standard SMTP"
  default: true
  smtp:
    host: smtp.example.com
    port: 587
    username: standard@example.com
    passwordRef:
      name: standard-smtp-secret
      key: password
  sender:
    address: noreply@example.com
    name: "Breakglass"
  retry:
    count: 3
    initialBackoffMs: 100
---
# High-priority provider for urgent escalations
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: MailProvider
metadata:
  name: urgent-mail
spec:
  displayName: "Urgent Priority SMTP"
  default: false
  smtp:
    host: urgent-smtp.example.com
    port: 465
    username: urgent@example.com
    passwordRef:
      name: urgent-smtp-secret
      key: password
  sender:
    address: urgent@example.com
    name: "URGENT - Breakglass"
  retry:
    count: 5
    initialBackoffMs: 50
```

### Gmail Configuration

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: MailProvider
metadata:
  name: gmail-provider
spec:
  displayName: "Gmail SMTP"
  default: true
  smtp:
    host: smtp.gmail.com
    port: 587
    username: your-email@gmail.com
    passwordRef:
      name: gmail-secret
      key: app-password  # Use App Password, not account password
  sender:
    address: your-email@gmail.com
    name: "Breakglass System"
---
apiVersion: v1
kind: Secret
metadata:
  name: gmail-secret
type: Opaque
stringData:
  app-password: "xxxx xxxx xxxx xxxx"  # 16-character app password
```

### Office 365 Configuration

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: MailProvider
metadata:
  name: o365-provider
spec:
  displayName: "Office 365 SMTP"
  default: true
  smtp:
    host: smtp.office365.com
    port: 587
    username: breakglass@yourdomain.com
    passwordRef:
      name: o365-secret
      key: password
  sender:
    address: breakglass@yourdomain.com
    name: "Breakglass Notifications"
```

### Unauthenticated SMTP (Internal Relay)

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: MailProvider
metadata:
  name: internal-relay
spec:
  displayName: "Internal SMTP Relay"
  default: true
  smtp:
    host: smtp-relay.internal
    port: 25
    # No username/password for internal relay
  sender:
    address: noreply@internal.example.com
    name: "Internal Breakglass"
```

## Provider Selection

### Selection Priority

When sending emails, the system selects a MailProvider in this order:

1. **Escalation-specific**: `BreakglassEscalation.spec.mailProvider`
2. **Cluster-specific**: `ClusterConfig.spec.mailProvider`
3. **Default provider**: MailProvider with `spec.default: true`

### Usage in BreakglassEscalation

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: production-escalation
spec:
  mailProvider: urgent-mail  # Use specific provider for this escalation
  notificationMails:
    - oncall@example.com
  # ... other escalation config
```

### Usage in ClusterConfig

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: production-cluster
spec:
  mailProvider: standard-mail  # Default provider for this cluster
  # ... other cluster config
```

## Health Checking

The MailProvider reconciler automatically performs health checks:

- **Frequency**: Every 5 minutes (healthy) or 30 seconds (unhealthy)
- **Checks**:
  1. Load password from secret
  2. Connect to SMTP server
  3. Perform STARTTLS negotiation
  4. Authenticate with credentials
- **Timeout**: 10 seconds per health check

View health status:

```bash
kubectl get mailprovider
# NAME            HOST              PORT   DEFAULT   READY   AGE
# default-smtp    smtp.example.com  587    true      True    5m
# urgent-mail     urgent.smtp.com   465    false     True    5m

kubectl describe mailprovider default-smtp
# Status:
#   Conditions:
#     Type: Ready
#     Status: True
#     Type: Healthy
#     Status: True
#   LastHealthCheck: 2024-03-15T10:30:00Z
```

## Metrics

MailProvider exports Prometheus metrics:

```promql
# Provider configuration status
breakglass_mailprovider_configured{provider="default-smtp",status="enabled"} 1

# Health check results
breakglass_mailprovider_health_check_total{provider="default-smtp",result="success"} 120

# Health check duration
breakglass_mailprovider_health_check_duration_seconds{provider="default-smtp"}

# Provider status
breakglass_mailprovider_status{provider="default-smtp"} 1  # 1=Healthy, 0=Unhealthy, -1=Disabled

# Email send statistics
breakglass_mailprovider_emails_sent_total{provider="default-smtp"} 45
breakglass_mailprovider_emails_failed_total{provider="default-smtp",reason="connection_timeout"} 2
```

## Migration from config.yaml

### Before (config.yaml)

```yaml
mail:
  host: smtp.example.com
  port: 587
  username: breakglass@example.com
  password: secret-password
  sender:
    address: noreply@example.com
    name: "Breakglass"
  retry:
    count: 3
    initialBackoffMs: 100
```

### After (MailProvider CRD)

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: MailProvider
metadata:
  name: default-smtp
spec:
  default: true
  smtp:
    host: smtp.example.com
    port: 587
    username: breakglass@example.com
    passwordRef:
      name: smtp-credentials
      key: password
  sender:
    address: noreply@example.com
    name: "Breakglass"
  retry:
    count: 3
    initialBackoffMs: 100
---
apiVersion: v1
kind: Secret
metadata:
  name: smtp-credentials
type: Opaque
stringData:
  password: secret-password
```

## Troubleshooting

### Provider Not Ready

```bash
kubectl describe mailprovider my-provider
# Check Conditions for error details
```

Common issues:
- **PasswordLoaded=False**: Secret not found or missing key
- **Healthy=False**: SMTP connection failed, check host/port/credentials
- **Ready=False**: Validation failed, check spec configuration

### Test SMTP Connection

```bash
# Check logs for health check details
kubectl logs -n breakglass-system deployment/breakglass-controller-manager | grep mailprovider

# Manually test SMTP from pod
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -- bash
telnet smtp.example.com 587
```

### Webhook Validation Errors

Validation warnings/errors during create/update:

```bash
# Example error
Error from server: admission webhook "mailprovider.validation..." denied the request:
spec.smtp.passwordRef: Required value: passwordRef must be specified when username is provided
```

Fix: Ensure username and passwordRef are both set or both empty.

### Check Provider Selection

```bash
# View which provider an escalation uses
kubectl get breakglassescalation my-escalation -o jsonpath='{.spec.mailProvider}'

# View cluster default
kubectl get clusterconfig my-cluster -o jsonpath='{.spec.mailProvider}'

# View which provider is marked as default
kubectl get mailprovider -o json | jq '.items[] | select(.spec.default==true) | .metadata.name'
```

## Security Considerations

1. **Secret Storage**: Always store SMTP passwords in Kubernetes Secrets, never in the CR
2. **RBAC**: Limit access to MailProvider CRs and SMTP credential secrets
3. **TLS**: Use port 587 (STARTTLS) or 465 (TLS), avoid port 25 (plaintext)
4. **insecureSkipVerify**: Only use for internal testing, never in production
5. **App Passwords**: For Gmail/O365, use app-specific passwords, not account passwords

## Best Practices

1. **Always mark one provider as default**: Ensures fallback when no specific provider selected
2. **Use descriptive names**: `displayName` helps operators understand provider purpose
3. **Monitor metrics**: Set up alerts on `breakglass_mailprovider_emails_failed_total`
4. **Test before production**: Create test MailProvider and verify health checks pass
5. **Rotate credentials**: Update secrets regularly and watch for health check failures
6. **Use multiple providers**: Configure backup providers for high availability

## Related Documentation

- [BreakglassEscalation](./breakglass-escalation.md)
- [ClusterConfig](./cluster-config.md)
- [Email Templates](./email-templates.md)
- [Metrics](./metrics.md)
