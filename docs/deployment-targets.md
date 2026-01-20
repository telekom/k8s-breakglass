# Deployment Targets

This document describes the kustomize deployment targets available for Breakglass.

## Overview

Breakglass uses [kustomize](https://kustomize.io/) to manage Kubernetes manifests. All deployment targets share a common base configuration and add target-specific patches.

```
config/
├── base/           # Shared base (crd, rbac, deployment, webhook)
├── debug/          # Base + debug logging
├── dev/            # Base + keycloak, mailhog, kafka for e2e testing
├── crd/            # CRD definitions (auto-generated)
├── rbac/           # RBAC resources (auto-generated role.yaml)
├── deployment/     # Core deployment resources
└── webhook/        # Webhook configuration
```

## Targets

### `config/base` - Production Deployment

The standard production deployment with all features enabled.

**Usage:**
```bash
make deploy
# Or manually:
kustomize build config/base | kubectl apply -f -
```

**Includes:**
- CRDs for all Breakglass resources
- RBAC configuration (ServiceAccount, ClusterRole, ClusterRoleBinding)
- Deployment with all component flags enabled
- Webhook configuration (ValidatingWebhookConfiguration, Certificate, Service)
- ConfigMap with application configuration

**Configuration:**
- Namespace: `breakglass-system`
- Name prefix: `breakglass-`
- All webhooks enabled
- Production-ready resource limits

### `config/debug` - Debug Deployment

Production deployment with debug logging enabled. Useful for troubleshooting.

**Usage:**
```bash
make deploy_debug
# Or manually:
kustomize build config/debug | kubectl apply -f -
```

**Adds to base:**
- `--debug` flag for verbose logging

**When to use:**
- Troubleshooting authorization issues
- Debugging webhook behavior
- Investigating session lifecycle problems

### `config/dev` - Development/E2E Environment

Full development environment with all dependencies for local testing and CI.

**Usage:**
```bash
make deploy_dev
# Or manually:
kustomize build config/dev | kubectl apply -f -
```

**Adds to base:**
- Keycloak for OIDC authentication
- MailHog for email testing
- Kafka for audit log testing
- Audit webhook receiver for testing
- Pre-configured test users and RBAC
- Faster intervals for testing (10s instead of 10m)
- Increased resource limits for test workloads

**When to use:**
- Local development with Kind cluster
- Running E2E tests
- CI/CD pipelines

## Makefile Targets

| Make Target | Kustomize Target | Description |
|-------------|------------------|-------------|
| `make deploy` | `config/base` | Production deployment |
| `make undeploy` | `config/base` | Remove production deployment |
| `make deploy_debug` | `config/debug` | Debug deployment |
| `make undeploy_debug` | `config/debug` | Remove debug deployment |
| `make deploy_dev` | `config/dev` | Dev/E2E environment |
| `make undeploy_dev` | `config/dev` | Remove dev environment |
| `make install` | `config/crd` | Install CRDs only |
| `make uninstall` | `config/crd` | Remove CRDs only |

## Pre-built Manifests

Pre-built manifest files are published with each release for users who prefer not to use kustomize:

- **GitHub Releases**: Each release includes `manifests.yaml` containing all resources
- **Installation**: `kubectl apply -f https://github.com/telekom/k8s-breakglass/releases/download/v1.0.0/manifests.yaml`

See the [Releases page](https://github.com/telekom/k8s-breakglass/releases) for available versions.

## Customization

### Using Kustomize Overlays

Create a custom overlay to modify the base configuration:

```yaml
# my-overlay/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- github.com/telekom/k8s-breakglass/config/base?ref=v1.0.0

namespace: my-custom-namespace

patches:
  - target:
      group: apps
      version: v1
      kind: Deployment
      name: manager
    patch: |-
      - op: replace
        path: /spec/replicas
        value: 3
```

### Image Customization

Override the container image:

```yaml
images:
  - name: breakglass
    newName: my-registry.example.com/breakglass
    newTag: v1.0.0
```

### Configuration

Each target includes a `config.yaml` file in `configMapGenerator`. To customize:

1. Create your own `config.yaml` based on `config.example.yaml`
2. Use kustomize's `configMapGenerator` with `behavior: replace`

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        config/base                               │
│  ┌─────────┐ ┌─────────┐ ┌─────────────┐ ┌─────────┐            │
│  │  crd/   │ │  rbac/  │ │ deployment/ │ │ webhook/│            │
│  └─────────┘ └─────────┘ └─────────────┘ └─────────┘            │
│                                                                  │
│  + namePrefix: breakglass-                                       │
│  + namespace: breakglass-system                                  │
│  + webhook port/volume patches                                   │
└─────────────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
    ┌─────────────┐     ┌─────────────┐      ┌─────────────┐
    │config/debug │     │ config/dev  │      │ (your       │
    │             │     │             │      │  overlay)   │
    │ + --debug   │     │ + --debug   │      │             │
    │             │     │ + keycloak  │      │ + custom    │
    │             │     │ + mailhog   │      │   patches   │
    │             │     │ + kafka     │      │             │
    └─────────────┘     └─────────────┘      └─────────────┘
```

## Validation

To validate a target builds correctly without applying:

```bash
# Dry-run build
kustomize build config/base > /dev/null && echo "OK"

# Preview generated manifests
kustomize build config/base | less

# Validate with kubectl
kustomize build config/base | kubectl apply --dry-run=server -f -
```

## CI Manifest Comparison

The CI pipeline automatically:
1. Builds all kustomize targets on every PR
2. Compares generated manifests against the last release
3. Posts a comment on the PR highlighting any changes

This ensures manifest changes are reviewed before merging.
