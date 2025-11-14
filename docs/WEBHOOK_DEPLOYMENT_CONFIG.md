# Webhook Deployment Configuration

## Overview

All webhook-related Kubernetes manifests are organized in `config/webhook/` directory using Kustomize. The main deployment includes security hardening, while webhook-specific configurations are applied as patches.

## File Structure

```yaml
config/webhook/
├── manifests.yaml          # ValidatingWebhookConfiguration
├── service.yaml            # Webhook service (port 443 -> 9443)
├── deployment-patch.yaml   # Kustomize patch for webhook port and certs
├── kustomization.yaml      # Webhook kustomization definition
├── dev-ca-patch.yaml       # Dev environment CA annotation patch
└── overlays/
    └── dev/
        └── kustomization.yaml  # Dev webhook overlay
```

## Components

### 1. ValidatingWebhookConfiguration

File: `manifests.yaml`

- Defines admission webhooks for:
  - BreakglassEscalation
  - BreakglassSession
  - ClusterConfig
- References `webhook-service` for client config
- Uses cert-controller annotation for automatic CA injection

### 2. Webhook Service

File: `service.yaml`

- Service name: `webhook-service`
- Namespace: `system`
- Port: 443 (external) -> 9443 (target port)
- Selector: `app: breakglass`

### 3. Deployment Patch

File: `deployment-patch.yaml`

Adds to the base deployment:

- **Webhook port**: Container port 9443
- **Certificate volume mount**: `/tmp/k8s-webhook-server/serving-certs`
- **Secret volume**: `webhook-certs` (optional)

### 4. Base Deployment Security

File: `config/deployment/app.yaml`

Includes hardening (NOT webhook-specific):

- **Pod security context**:
  - `runAsNonRoot: true`
  - `runAsUser: 65532`
  - `fsGroup: 65532`
  - `seccompProfile: RuntimeDefault`
- **Container security context**:
  - `allowPrivilegeEscalation: false`
  - `readOnlyRootFilesystem: true`
  - Drop all capabilities
- **Resource limits**:
  - Requests: 100m CPU, 128Mi memory
  - Limits: 500m CPU, 512Mi memory

## Integration

### Default Configuration

File: `config/default/kustomization.yaml`

```yaml
resources:
- ../crd
- ../rbac
- ../deployment
- ../webhook

patchesStrategicMerge:
  - ../webhook/deployment-patch.yaml
```

### Dev Configuration

File: `config/dev/kustomization.yaml`

```yaml
resources:
- ../crd
- ../rbac
- ../deployment
- ../webhook
- ./resources/...

patches:
- target:
    group: admissionregistration.k8s.io
    version: v1
    kind: ValidatingWebhookConfiguration
  path: ./resources/webhook-dev-ca-patch.yaml
```

## Certificate Management

### Automatic CA Injection

The ValidatingWebhookConfiguration includes annotation:

```yaml
annotations:
  cert-controller.breakglass.io/inject-ca-from: breakglass-system/webhook-certs
```

This enables cert-controller to automatically inject the CA certificate from the `webhook-certs` secret.

### Secret Requirements

- Secret name: `webhook-certs`
- Namespace: `breakglass-system` (or `breakglass-dev-system` for dev)
- Keys: `tls.crt`, `tls.key`, `ca.crt`

## Environment Variables

- `ENABLE_WEBHOOK_MANAGER`: Controls webhook registration (default: `true`)
- `ENABLE_CERT_ROTATION`: Controls certificate rotation (default: `true`)
- `WEBHOOK_SECRET_NAME`: Custom secret name for certificates (default: `webhook-certs`)

See `docs/MANAGER_STARTUP_LOGIC.md` for details.

## Building

### Default (production)

```bash
kustomize build config/default
```

### Dev (with test resources)

```bash
kustomize build config/dev
```

### Webhook only

```bash
kustomize build config/webhook
```
