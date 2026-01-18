# Production Deployment Checklist

This checklist helps ensure a secure and reliable production deployment of the breakglass controller.

## Pre-Deployment Requirements

### Infrastructure

- [ ] Kubernetes cluster version 1.27+ (tested with up to 1.32)
- [ ] cert-manager installed (for webhook TLS certificates)
- [ ] Ingress controller configured (nginx, traefik, or similar)
- [ ] TLS certificates for external access (production CA, not self-signed)
- [ ] DNS configured for breakglass service endpoint
- [ ] Storage for audit logs (optional, if using persistent audit)

### Authentication & Identity

- [ ] **IdentityProvider CRD configured** (MANDATORY)
  - [ ] OIDC authority URL verified accessible from cluster
  - [ ] Client ID and secrets configured in Kubernetes Secret
  - [ ] Group claim mapping verified in OIDC provider
  - [ ] Certificate authority configured if using private CA
- [ ] Test user authentication flow before production traffic

### Cluster Connectivity

- [ ] **ClusterConfig resources created** for each target cluster
  - [ ] Kubeconfig secrets created with minimal required permissions
  - [ ] Service account tokens rotated and have proper RBAC
  - [ ] Network connectivity verified to target cluster API servers
- [ ] Test authorization webhook connectivity

### Email Notifications

- [ ] **MailProvider CRD configured** (optional but recommended)
  - [ ] SMTP server accessible from cluster
  - [ ] TLS/STARTTLS configured for mail transport
  - [ ] Sender address configured and verified
  - [ ] Test email delivery to verify configuration

---

## Security Checklist

### Network Security

- [ ] Breakglass API only accessible via HTTPS (TLS 1.2+)
- [ ] Network policies restrict pod-to-pod communication
- [ ] Ingress rate limiting enabled
- [ ] CORS origins properly configured (`--frontend-base-url`)
- [ ] Webhook endpoint secured with client certificate or network policy

### RBAC & Permissions

- [ ] Service account has minimal required RBAC permissions
- [ ] No cluster-admin bindings for breakglass service account
- [ ] Target cluster service accounts have only required permissions
- [ ] Review and approve all escalation policies before enabling

### Secrets Management

- [ ] All secrets stored in Kubernetes Secrets (not ConfigMaps)
- [ ] Secrets encrypted at rest (Kubernetes EncryptionConfiguration)
- [ ] Secret rotation plan documented
- [ ] No secrets in container environment variables (use secretRef)

### Audit & Compliance

- [ ] Audit logging enabled (`--enable-audit` flag)
- [ ] Audit logs shipped to SIEM/log aggregation
- [ ] Retention period configured for BreakglassSession resources
- [ ] DenyPolicy resources reviewed and tested

---

## Configuration Checklist

### Required Flags

```bash
# Minimum required flags for production
--leader-elect=true                    # Enable leader election for HA
--metrics-bind-address=:8443           # Prometheus metrics endpoint
--health-probe-bind-address=:8081      # Health/readiness probes
--frontend-base-url=https://breakglass.example.com  # External URL
```

### Recommended Flags

```bash
# Production-recommended flags
--enable-audit=true                    # Enable audit event logging
--debug-sessions-enabled=true          # Enable debug session feature
--zap-log-level=info                   # Production log level
--zap-encoder=json                     # Structured JSON logs
```

### Environment Variables

| Variable | Production Value | Description |
|----------|------------------|-------------|
| `CLEANUP_INTERVAL` | `5m` (default) | Session cleanup frequency |
| `DEBUG_SESSION_RETENTION_PERIOD` | `168h` (7 days) | Audit retention |
| `GOMAXPROCS` | Match CPU limits | Optimize for container |

---

## High Availability Checklist

### Deployment Configuration

- [ ] **Replicas**: Minimum 2 replicas for HA
- [ ] **Leader Election**: Enabled (`--leader-elect=true`)
- [ ] **Pod Disruption Budget**: Configured to ensure availability
- [ ] **Pod Anti-Affinity**: Spread across nodes/zones
- [ ] **Resource Requests/Limits**: Properly sized

### Example PDB

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: breakglass-pdb
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: breakglass
```

### Example Anti-Affinity

```yaml
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchLabels:
            app: breakglass
        topologyKey: kubernetes.io/hostname
```

---

## Monitoring & Alerting

### Prometheus Metrics

- [ ] Metrics endpoint accessible (`/api/metrics` or separate port)
- [ ] ServiceMonitor or PodMonitor configured for Prometheus
- [ ] Key metrics dashboards created:
  - Session request/approval rates
  - Authorization latency (p50, p95, p99)
  - Error rates by type
  - Active session count

### Recommended Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| BreakglassHighErrorRate | Error rate > 5% for 5m | Warning |
| BreakglassWebhookLatencyHigh | p99 latency > 500ms | Warning |
| BreakglassSessionCleanupFailing | Cleanup errors for 15m | Warning |
| BreakglassNoLeader | No leader for 2m | Critical |
| BreakglassDown | No healthy replicas | Critical |

### Health Checks

- [ ] Liveness probe configured (`/healthz`)
- [ ] Readiness probe configured (`/readyz`)
- [ ] Probe timeouts appropriate for load

---

## Backup & Recovery

### What to Backup

- [ ] BreakglassEscalation resources (policies)
- [ ] ClusterConfig resources (cluster connectivity)
- [ ] IdentityProvider resources (authentication config)
- [ ] MailProvider resources (email config)
- [ ] DenyPolicy resources (access restrictions)
- [ ] Kubernetes Secrets referenced by above

### Recovery Procedure

1. Restore CRDs from backup
2. Restore Secrets from secure backup
3. Deploy breakglass controller
4. Verify IdentityProvider status is Ready
5. Test authentication flow
6. Test authorization webhook

---

## Go-Live Verification

### Functional Testing

- [ ] User can log in via configured IDP
- [ ] User can request breakglass session
- [ ] Approver receives notification (email if configured)
- [ ] Approver can approve/reject session
- [ ] Approved user can access target cluster resources
- [ ] Session expires correctly after duration
- [ ] Webhook denies access after expiration

### Performance Testing

- [ ] Authorization webhook latency < 100ms (p95)
- [ ] API response times < 200ms (p95)
- [ ] System handles expected concurrent users
- [ ] No memory leaks under sustained load

### Security Testing

- [ ] Invalid tokens are rejected
- [ ] Expired sessions deny access
- [ ] DenyPolicies block restricted resources
- [ ] Rate limiting prevents abuse
- [ ] Audit logs capture all access decisions

---

## Post-Deployment

### Documentation

- [ ] Runbook for common operational tasks
- [ ] Escalation contacts documented
- [ ] User guide distributed to users
- [ ] Approver training completed

### Monitoring

- [ ] Dashboards accessible to operations team
- [ ] Alert routing configured (PagerDuty, Slack, etc.)
- [ ] On-call rotation includes breakglass expertise

### Maintenance Plan

- [ ] Upgrade schedule defined
- [ ] Secret rotation schedule
- [ ] Certificate renewal process
- [ ] Disaster recovery tested

---

## Quick Verification Commands

```bash
# Check controller health
kubectl get pods -l app=breakglass -n breakglass-system

# Verify CRDs installed
kubectl get crd | grep breakglass

# Check IdentityProvider status
kubectl get identityproviders -o wide

# Check ClusterConfig status
kubectl get clusterconfigs -o wide

# View recent sessions
kubectl get breakglasssessions -A --sort-by=.metadata.creationTimestamp

# Check metrics endpoint
kubectl port-forward svc/breakglass -n breakglass-system 8443:8443
curl -k https://localhost:8443/metrics

# Test authorization webhook (from target cluster)
kubectl auth can-i get pods --as=test@example.com -v=6
```

---

## Related Documentation

- [Installation Guide](./installation.md)
- [Configuration Reference](./configuration-reference.md)
- [CLI Flags Reference](./cli-flags-reference.md)
- [Webhook Setup](./webhook-setup.md)
- [Metrics](./metrics.md)
- [Security Best Practices](./security-best-practices.md)
- [Troubleshooting](./troubleshooting.md)
