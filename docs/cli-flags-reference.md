# CLI Flags Reference

Complete reference for all command-line flags available in the breakglass controller.

**Implementation:** `cmd/main.go`

## Overview

The breakglass controller supports 40+ configuration flags that can be set via:
1. **Command-line arguments**: `breakglass-controller --flag-name=value`
2. **Environment variables**: `FLAG_NAME=value breakglass-controller`

All flags have sensible defaults and are optional.

## Quick Start

### Single Instance Deployment

```bash
breakglass-controller \
  --enable-leader-election=false \
  --enable-frontend=true \
  --enable-api=true \
  --enable-cleanup=true \
  --enable-webhooks=true
```

### Multi-Replica Deployment

```bash
breakglass-controller \
  --enable-leader-election=true \
  --enable-frontend=true \
  --enable-api=true \
  --enable-cleanup=true \
  --enable-webhooks=true
```

### Webhook-Only Instance

```bash
breakglass-controller \
  --enable-frontend=false \
  --enable-api=false \
  --enable-cleanup=false \
  --enable-webhooks=true
```

## Flag Categories

### Debug and Logging

#### `--debug`

Enable debug level logging (verbose output)

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `false` |
| **Environment** | `DEBUG` |
| **Example** | `--debug` |

```bash
breakglass-controller --debug
```

When enabled:
- Logs are output in development format (more readable)
- Additional diagnostic information included
- Performance may be impacted (not for production)

---

### Webhook Server Configuration

#### `--webhook-bind-address`

The address the webhook server binds to (host:port)

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `0.0.0.0:9443` |
| **Environment** | `WEBHOOK_BIND_ADDRESS` |
| **Example** | `--webhook-bind-address=:9443` |

```bash
# Listen on all interfaces
breakglass-controller --webhook-bind-address=0.0.0.0:9443

# Listen on localhost only
breakglass-controller --webhook-bind-address=127.0.0.1:9443
```

#### `--webhook-cert-path`

Directory containing the webhook server certificate

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `/tmp/k8s-webhook-server/serving-certs` |
| **Environment** | `WEBHOOK_CERT_PATH` |
| **Example** | `--webhook-cert-path=/etc/webhook/certs` |

```bash
breakglass-controller --webhook-cert-path=/etc/webhook/certs
```

#### `--webhook-cert-name`

Name of the webhook certificate file in the cert directory

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `tls.crt` |
| **Environment** | `WEBHOOK_CERT_NAME` |
| **Example** | `--webhook-cert-name=cert.pem` |

#### `--webhook-cert-key`

Name of the webhook key file in the cert directory

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `tls.key` |
| **Environment** | `WEBHOOK_CERT_KEY` |
| **Example** | `--webhook-cert-key=key.pem` |

---

### Metrics Server Configuration

#### `--metrics-bind-address`

The address the metrics endpoint binds to (host:port)

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `0.0.0.0:8081` |
| **Environment** | `METRICS_BIND_ADDRESS` |
| **Example** | `--metrics-bind-address=:8081` |

```bash
# Enable metrics
breakglass-controller --metrics-bind-address=:8081

# Disable metrics
breakglass-controller --metrics-bind-address=0
```

#### `--metrics-secure`

If set, metrics endpoint is served securely via HTTPS

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `false` |
| **Environment** | `METRICS_SECURE` |
| **Example** | `--metrics-secure` |

```bash
breakglass-controller --metrics-secure --metrics-cert-path=/etc/metrics/certs
```

#### `--metrics-cert-path`

Directory containing metrics server certificate (when `--metrics-secure` is enabled)

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (empty) |
| **Environment** | `METRICS_CERT_PATH` |
| **Example** | `--metrics-cert-path=/etc/metrics/certs` |

#### `--metrics-cert-name`

Name of metrics certificate file

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `tls.crt` |
| **Environment** | `METRICS_CERT_NAME` |

#### `--metrics-cert-key`

Name of metrics key file

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `tls.key` |
| **Environment** | `METRICS_CERT_KEY` |

---

### Webhook Metrics Server Configuration

#### `--webhooks-metrics-bind-address`

The address the webhook metrics endpoint binds to (separate from reconciler metrics)

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (empty - uses reconciler metrics) |
| **Environment** | `WEBHOOKS_METRICS_BIND_ADDRESS` |
| **Example** | `--webhooks-metrics-bind-address=:8083` |

```bash
# Separate metrics server for webhooks
breakglass-controller \
  --metrics-bind-address=:8081 \
  --webhooks-metrics-bind-address=:8083
```

If empty, webhook metrics will use the reconciler metrics address.

#### `--webhooks-metrics-secure`

If set, webhook metrics endpoint is served securely via HTTPS

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `false` |
| **Environment** | `WEBHOOKS_METRICS_SECURE` |

#### `--webhooks-metrics-cert-path`

Directory containing webhook metrics certificate

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (empty) |
| **Environment** | `WEBHOOKS_METRICS_CERT_PATH` |

#### `--webhooks-metrics-cert-name`

Name of webhook metrics certificate file

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `tls.crt` |
| **Environment** | `WEBHOOKS_METRICS_CERT_NAME` |

#### `--webhooks-metrics-cert-key`

Name of webhook metrics key file

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `tls.key` |
| **Environment** | `WEBHOOKS_METRICS_CERT_KEY` |

---

### Health Probe Configuration

#### `--health-probe-bind-address`

The address the health probe endpoint binds to (for liveness and readiness checks)

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `:8082` |
| **Environment** | `PROBE_BIND_ADDRESS` |
| **Example** | `--health-probe-bind-address=:8082` |

```bash
breakglass-controller --health-probe-bind-address=:8082
```

Used by Kubernetes probes:
```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8082

readinessProbe:
  httpGet:
    path: /readyz
    port: 8082
```

---

### Leader Election Configuration

#### `--enable-leader-election`

Enable leader election for running multiple instances

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `true` |
| **Environment** | `ENABLE_LEADER_ELECTION` |
| **Example** | `--enable-leader-election=false` |

```bash
# Enable (default - recommended for HA)
breakglass-controller --enable-leader-election=true

# Disable (for single instance or testing)
breakglass-controller --enable-leader-election=false
```

When **enabled** (multi-replica):
- Only one replica becomes leader
- Background loops (cleanup, status updater) run only on leader
- Automatic failover when leader crashes

When **disabled** (single instance):
- All replicas act as leaders
- All background loops run on all replicas (causes duplicate work in multi-replica)
- Useful for testing or single-instance deployments

See [Scaling and Leader Election](./scaling-and-leader-election.md) for detailed information.

#### `--leader-elect-namespace`

The namespace where the leader election lease will be created

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (pod's namespace) |
| **Environment** | `LEADER_ELECT_NAMESPACE` |
| **Example** | `--leader-elect-namespace=breakglass-system` |

```bash
# Use specific namespace
breakglass-controller --leader-elect-namespace=breakglass-system

# Use pod's namespace (default)
breakglass-controller --leader-elect-namespace=
```

#### `--leader-elect-id`

The ID used for leader election

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `breakglass.telekom.io` |
| **Environment** | `LEADER_ELECT_ID` |
| **Example** | `--leader-elect-id=breakglass.example.com` |

```bash
breakglass-controller --leader-elect-id=breakglass.example.com
```

This ID is used as the Lease name in Kubernetes and must be unique across deployments.

---

### HTTP/2 Configuration

#### `--enable-http2`

Enable HTTP/2 for metrics and webhook servers

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `false` |
| **Environment** | `ENABLE_HTTP2` |
| **Example** | `--enable-http2` |

```bash
breakglass-controller --enable-http2
```

⚠️ **Security Note**: HTTP/2 has known vulnerabilities (CVE-2023-44487, CVE-2024-3156). Leave disabled unless required.

When disabled (default):
- HTTP/1.1 only
- More secure configuration

When enabled:
- HTTP/2 support added
- Requires careful security review

---

### Webhook Component Configuration

#### `--enable-webhooks`

Enable webhook manager for validating webhooks

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `true` |
| **Environment** | `ENABLE_WEBHOOKS` |
| **Example** | `--enable-webhooks=false` |

```bash
# Enable webhooks (default)
breakglass-controller --enable-webhooks=true

# Disable webhooks (for API-only deployments)
breakglass-controller --enable-webhooks=false
```

When **enabled**:
- ValidatingWebhookConfigurations registered
- CRD validation webhooks active
- Webhook server runs on `--webhook-bind-address`

When **disabled**:
- No validating webhooks
- CRD creation/updates not validated
- Useful when deploying API-only instances

#### `--enable-validating-webhooks`

Enable specific validating webhooks for breakglass CRDs

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `true` |
| **Environment** | `ENABLE_VALIDATING_WEBHOOKS` |
| **Example** | `--enable-validating-webhooks=false` |

This flag controls which validating webhooks are registered:
- BreakglassSession validation
- BreakglassEscalation validation
- ClusterConfig validation
- IdentityProvider validation

---

### Pod and Network Configuration

#### `--pod-namespace`

The namespace where the pod is running (used for event recording)

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `default` |
| **Environment** | `POD_NAMESPACE` |
| **Example** | `--pod-namespace=breakglass-system` |

```bash
breakglass-controller --pod-namespace=breakglass-system
```

Used for:
- Event source namespace
- Default lease namespace (if `--leader-elect-namespace` not specified)

---

### Component Enable Flags

These flags control which components are enabled. Use them to split the controller into multiple instances.

#### `--enable-frontend`

Enable the frontend API endpoints (web UI)

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `true` |
| **Environment** | `ENABLE_FRONTEND` |
| **Example** | `--enable-frontend=false` |

```bash
# Enable frontend (default)
breakglass-controller --enable-frontend=true

# Disable (for webhook-only instances)
breakglass-controller --enable-frontend=false
```

When **enabled**:
- Web UI available at `http://localhost:8080`
- Static assets served
- Frontend API endpoints available

When **disabled**:
- Web UI not available
- Useful for webhook-only or background-task-only instances

#### `--enable-api`

Enable the REST API controller

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `true` |
| **Environment** | `ENABLE_API` |
| **Example** | `--enable-api=false` |

```bash
# Enable API (default)
breakglass-controller --enable-api=true

# Disable (for webhook-only instances)
breakglass-controller --enable-api=false
```

When **enabled**:
- REST API endpoints available
- SAR (SubjectAccessReview) webhook available
- BreakglassSession/Escalation endpoints available

When **disabled**:
- API endpoints not available
- Useful for webhook-only instances

#### `--enable-cleanup`

Enable the background cleanup routine

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `true` |
| **Environment** | `ENABLE_CLEANUP` |
| **Example** | `--enable-cleanup=false` |

```bash
# Enable (default)
breakglass-controller --enable-cleanup=true

# Disable (for API/webhook-only instances)
breakglass-controller --enable-cleanup=false
```

When **enabled**:
- Cleanup routine runs periodically (5 minute interval)
- Expired sessions marked for deletion
- Only runs on leader (if leader election enabled)

When **disabled**:
- No automatic session cleanup
- Manual cleanup required
- Useful for API/webhook-only instances

---

### Interval Configuration

#### `--cluster-config-check-interval`

Interval for checking cluster configuration validity

| Property | Value |
|----------|-------|
| **Type** | `duration` |
| **Default** | `10m` |
| **Environment** | `CLUSTER_CONFIG_CHECK_INTERVAL` |
| **Example** | `--cluster-config-check-interval=5m` |

```bash
# Check every 10 minutes (default)
breakglass-controller --cluster-config-check-interval=10m

# Check every 5 minutes
breakglass-controller --cluster-config-check-interval=5m

# Check every 30 seconds
breakglass-controller --cluster-config-check-interval=30s
```

Valid duration formats: `30s`, `5m`, `1h`

The ClusterConfigChecker:
- Validates ClusterConfig resources periodically
- Verifies kubeconfig secrets are accessible
- Runs only on leader (if leader election enabled)

#### `--escalation-status-update-interval`

Interval for updating escalation status from identity provider

| Property | Value |
|----------|-------|
| **Type** | `duration` |
| **Default** | `10m` |
| **Environment** | `ESCALATION_STATUS_UPDATE_INTERVAL` |
| **Example** | `--escalation-status-update-interval=5m` |

```bash
# Update every 10 minutes (default)
breakglass-controller --escalation-status-update-interval=10m

# Update every 5 minutes
breakglass-controller --escalation-status-update-interval=5m
```

Valid duration formats: `30s`, `5m`, `1h`

The EscalationStatusUpdater:
- Syncs group membership from Keycloak
- Updates BreakglassEscalation.Status periodically
- Runs only on leader (if leader election enabled)

---

### Configuration File Paths

#### `--config-path`

Path to the breakglass configuration file

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `./config.yaml` |
| **Environment** | `BREAKGLASS_CONFIG_PATH` |
| **Example** | `--config-path=/etc/breakglass/config.yaml` |

```bash
# Custom config location
breakglass-controller --config-path=/etc/breakglass/config.yaml
```

This file contains:
- Server settings
- OIDC/authentication config
- Frontend configuration
- Email settings
- Kubernetes settings

See [Installation Guide](./installation.md) for config file format.

#### `--breakglass-namespace`

The Kubernetes namespace containing breakglass resources (IdentityProvider secrets)

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (cluster-wide lookup) |
| **Environment** | `BREAKGLASS_NAMESPACE` |
| **Example** | `--breakglass-namespace=breakglass-system` |

```bash
breakglass-controller --breakglass-namespace=breakglass-system
```

Used for:
- Finding IdentityProvider resources
- Locating secret references

#### `--disable-email`

Disable email notifications for breakglass session requests

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `false` |
| **Environment** | `BREAKGLASS_DISABLE_EMAIL` |
| **Example** | `--disable-email` |

```bash
# Disable email (useful for testing)
breakglass-controller --disable-email

# Enable email (default, requires config)
# (no flag needed, email enabled by default)
```

When **disabled**:
- No email notifications sent
- Useful for development/testing
- Approvers won't be notified of requests

When **enabled** (default):
- Email notifications sent based on config.yaml
- Requires SMTP configuration
- Approvers notified of requests

---

## Environment Variables

All flags can be set via environment variables. The naming convention is:

- Replace hyphens (`-`) with underscores (`_`)
- Convert to uppercase
- Add prefix if needed

**Examples:**

```bash
# Flag: --enable-leader-election
export ENABLE_LEADER_ELECTION=true

# Flag: --webhook-bind-address
export WEBHOOK_BIND_ADDRESS=0.0.0.0:9443

# Flag: --cluster-config-check-interval
export CLUSTER_CONFIG_CHECK_INTERVAL=5m

# Start controller with all env vars
breakglass-controller
```

Priority order (highest to lowest):
1. Command-line flag
2. Environment variable
3. Default value

---

## Deployment Examples

### Docker Container

```bash
docker run \
  -e ENABLE_LEADER_ELECTION=true \
  -e WEBHOOK_BIND_ADDRESS=0.0.0.0:9443 \
  -e METRICS_BIND_ADDRESS=0.0.0.0:8081 \
  -e POD_NAMESPACE=breakglass-system \
  -v /etc/breakglass:/etc/breakglass:ro \
  breakglass:latest
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: breakglass-controller
  namespace: breakglass-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: breakglass-controller
  template:
    metadata:
      labels:
        app: breakglass-controller
    spec:
      containers:
      - name: controller
        image: breakglass:latest
        args:
          - --enable-leader-election=true
          - --enable-frontend=true
          - --enable-api=true
          - --enable-cleanup=true
          - --enable-webhooks=true
          - --webhook-bind-address=0.0.0.0:9443
          - --metrics-bind-address=0.0.0.0:8081
          - --health-probe-bind-address=:8082
          - --config-path=/etc/breakglass/config.yaml
          - --pod-namespace=breakglass-system
          - --cluster-config-check-interval=10m
          - --escalation-status-update-interval=10m
        
        env:
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        
        ports:
        - name: webhook
          containerPort: 9443
          protocol: TCP
        - name: metrics
          containerPort: 8081
          protocol: TCP
        - name: healthz
          containerPort: 8082
          protocol: TCP
        
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8082
          initialDelaySeconds: 15
          periodSeconds: 20
        
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8082
          initialDelaySeconds: 5
          periodSeconds: 5
        
        resources:
          requests:
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
        
        volumeMounts:
        - name: config
          mountPath: /etc/breakglass
          readOnly: true
        - name: webhook-certs
          mountPath: /tmp/k8s-webhook-server/serving-certs
          readOnly: true
      
      volumes:
      - name: config
        configMap:
          name: breakglass-config
      - name: webhook-certs
        secret:
          secretName: webhook-server-cert
      
      serviceAccountName: breakglass-controller
```

### Helm Values

```yaml
controller:
  args:
    - --enable-leader-election=true
    - --enable-frontend=true
    - --enable-api=true
    - --enable-cleanup=true
    - --enable-webhooks=true
    - --pod-namespace=breakglass-system

  env:
    - name: POD_NAMESPACE
      valueFrom:
        fieldRef:
          fieldPath: metadata.namespace

replicaCount: 3

resources:
  requests:
    memory: "256Mi"
    cpu: "200m"
  limits:
    memory: "512Mi"
    cpu: "1000m"
```

---

## Troubleshooting

### "Unknown flag" error

**Problem**: `flag provided but not defined: -unknown-flag`

**Solution**:
- Check flag name spelling (use hyphens, not underscores)
- See [Flag Categories](#flag-categories) for valid flags
- Use `breakglass-controller -help` to list all flags

### Environment variable not taking effect

**Problem**: Environment variable set but flag uses default

**Solution**:
- Check environment variable name (uppercase, underscores)
- Command-line flags override environment variables
- Remove command-line flag to use environment variable

```bash
# Wrong: using lowercase
export enable-leader-election=true  # ❌ Won't work

# Right: using uppercase with underscores
export ENABLE_LEADER_ELECTION=true  # ✅ Works
```

### Invalid duration format

**Problem**: `invalid value "5mins" for flag -cluster-config-check-interval`

**Solution**:
- Use valid Go duration format: `30s`, `5m`, `1h`
- Not `5mins`, `5minutes`, etc.

```bash
# Wrong duration formats
--cluster-config-check-interval=5mins      # ❌
--cluster-config-check-interval=5 minutes  # ❌

# Correct duration formats
--cluster-config-check-interval=5m         # ✅
--cluster-config-check-interval=300s       # ✅
```

---

## Related Documentation

- [Installation Guide](./installation.md) - Step-by-step setup
- [Scaling and Leader Election](./scaling-and-leader-election.md) - Horizontal scaling
- [Webhook Setup](./webhook-setup.md) - Webhook configuration
- [Troubleshooting](./troubleshooting.md) - Common issues
