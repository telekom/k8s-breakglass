# Deployment Manifest Build Verification

## Build Status

✅ **Default Configuration** (`config/default`)

```bash
kustomize build config/default
```

- Status: **SUCCESS**
- Resources: 25 total

✅ **Dev Configuration** (`config/dev`)

```bash
kustomize build config/dev
```

- Status: **SUCCESS**
- Resources: 40+ total (includes test resources)

✅ **Webhook Configuration** (`config/webhook`)

```bash
kustomize build config/webhook
```

- Status: **SUCCESS**
- Resources: 2 (Service + ValidatingWebhookConfiguration)

## Resource Verification

### Default Build Output

| Resource Type | Count | Notes |
|---|---|---|
| CustomResourceDefinition | 4 | BreakglassEscalation, BreakglassSession, ClusterConfig, IdentityProvider |
| ClusterRole | 6 | RBAC roles for webhooks, escalations, sessions, configs |
| ClusterRoleBinding | 6 | Bindings for cluster-scoped permissions |
| Role | 1 | Namespace-scoped role for webhook certificate management |
| RoleBinding | 1 | Binding for namespace-scoped permissions |
| Service | 2 | HTTP service + Webhook service |
| ServiceAccount | 1 | Service account for deployment |
| Deployment | 1 | Manager with hardening + webhook port/volumes |
| ConfigMap | 1 | Configuration data |
| Ingress | 1 | HTTP ingress routing |
| ValidatingWebhookConfiguration | 1 | Admission webhook rules |
| Namespace | 1 | breakglass-system |

## Deployment Configuration Details

### Security Hardening (Base Deployment)

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault

containers:
  - securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: [ALL]
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 500m
        memory: 512Mi
```

### Ports

- **HTTP**: 8081 (main service)
- **Webhook**: 9443 (webhook service) - Added via patch

### Volume Mounts

```yaml
volumeMounts:
  - mountPath: /config/
    name: config
    readOnly: true
  - mountPath: /tmp/k8s-webhook-server/serving-certs
    name: webhook-certs
    readOnly: true
```

### Volumes

```yaml
volumes:
  - name: config
    configMap:
      name: breakglass-config
  - name: webhook-certs
    secret:
      secretName: webhook-certs
      optional: true
```

## Webhook Resources

### ValidatingWebhookConfiguration

Registered webhooks:

- `vbreakglassescalation.kb.io` - BreakglassEscalation validation
- `vbreakglasssession.kb.io` - BreakglassSession validation
- `vclusterconfig.kb.io` - ClusterConfig validation

Service: `webhook-service` in `system` namespace
Port: 443 → 9443

### Webhook Service

```yaml
kind: Service
metadata:
  name: webhook-service
spec:
  ports:
    - name: webhook
      port: 443
      targetPort: 9443
  selector:
    app: breakglass
  type: ClusterIP
```

## RBAC Configuration

### Webhook Certificate Rotator (Namespace-Scoped)
- **Role**: `breakglass-webhook-cert-rotator-role`
  - Permissions: Manage secrets in namespace
- **RoleBinding**: `breakglass-webhook-cert-rotator-role-binding`
  - Binds role to manager ServiceAccount

### Webhook Certificate Rotator (Cluster-Scoped)
- **ClusterRole**: `breakglass-webhook-cert-rotator-cluster-role`
  - Permissions: Patch ValidatingWebhookConfiguration
- **ClusterRoleBinding**: `breakglass-webhook-cert-rotator-cluster-role-binding`
  - Binds role to manager ServiceAccount

## Files Modified

1. `config/deployment/app.yaml` - Base deployment with hardening
2. `config/webhook/service.yaml` - Webhook service
3. `config/webhook/manifests.yaml` - ValidatingWebhookConfiguration
4. `config/webhook/deployment-patch.yaml` - Webhook port/volume patch
5. `config/webhook/kustomization.yaml` - Webhook kustomization
6. `config/default/kustomization.yaml` - Updated with JSON patch for deployment
7. `config/dev/kustomization.yaml` - Dev config with webhook resources
8. `config/dev/resources/webhook-dev-ca-patch.yaml` - Dev CA annotation patch

## Build Commands

```bash
# Build default (production) configuration
kustomize build config/default > deployment.yaml

# Build dev configuration
kustomize build config/dev > dev-deployment.yaml

# Build webhook configuration only
kustomize build config/webhook > webhook.yaml

# Apply to cluster
kubectl apply -k config/default
```

## Notes

- Webhook deployment is optional via `ENABLE_WEBHOOK_MANAGER` environment variable
- Certificate rotation is automatic (controlled by `ENABLE_CERT_ROTATION`)
- Custom webhook secret name supported via `WEBHOOK_SECRET_NAME` environment variable
- All security hardening applied by default (not webhook-specific)
- Webhook configuration organized in dedicated `config/webhook/` directory
