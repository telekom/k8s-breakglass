# Audit Configuration

The breakglass controller includes an extremely granular, non-blocking audit system that captures all actions on a cluster. Audit events are sent to configurable sinks including Kafka with TLS/mTLS support.

## Overview

The audit system is designed for:
- **Extreme Granularity**: Captures 120+ event types covering every Kubernetes operation including non-resource URLs
- **Non-Blocking**: Never slows down cluster operations - events are queued and processed async
- **High Throughput**: Handles thousands of events per second with batching and backpressure
- **Multiple Sinks**: Send events to Kafka, webhooks, structured logs, or Kubernetes Events
- **Flexible Filtering**: Include/exclude by event type, user, namespace, or resource
- **Sampling**: Reduce volume for high-frequency events while always capturing critical ones

## AuditConfig CRD

The `AuditConfig` is a **cluster-scoped** resource that configures auditing globally:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: AuditConfig
metadata:
  name: audit-config
  # Note: No namespace - cluster-scoped resource
spec:
  enabled: true
  
  queue:
    size: 100000      # Buffer 100k events
    workers: 5        # 5 concurrent sink writers
    dropOnFull: true  # Never block - drop if full
  
  sinks:
    - name: kafka-primary
      type: kafka
      kafka:
        brokers:
          - kafka-0:9093
          - kafka-1:9093
        topic: breakglass-audit
        tls:
          enabled: true
          caSecretRef:
            name: kafka-ca
            namespace: breakglass-system  # REQUIRED - must be controller namespace
        sasl:
          mechanism: SCRAM-SHA-512
          credentialsSecretRef:
            name: kafka-credentials
            namespace: breakglass-system  # REQUIRED - must be controller namespace
```

## Security: Secret Namespace Enforcement

**All secrets MUST be in the same namespace as the breakglass controller** (typically `breakglass-system`). This is enforced for security - the controller cannot read secrets from arbitrary namespaces.

```yaml
# ✅ CORRECT - secrets in controller namespace
caSecretRef:
  name: kafka-ca
  namespace: breakglass-system

# ❌ WRONG - secrets in other namespaces are rejected
caSecretRef:
  name: kafka-ca
  namespace: some-other-namespace  # Will fail validation
```

## Sink Types

### Kafka Sink

The Kafka sink supports:
- **TLS encryption** with CA certificates
- **mTLS** with client certificates
- **SASL authentication**: PLAIN, SCRAM-SHA-256, SCRAM-SHA-512
- **Batching** for high throughput
- **Compression**: none, gzip, snappy, lz4, zstd

```yaml
sinks:
  - name: kafka-prod
    type: kafka
    kafka:
      brokers:
        - kafka-0.kafka.svc:9093
        - kafka-1.kafka.svc:9093
        - kafka-2.kafka.svc:9093
      topic: breakglass-audit-events
      
      # TLS configuration
      tls:
        enabled: true
        caSecretRef:
          name: kafka-ca-cert       # Secret with ca.crt key
        clientCertSecretRef:
          name: kafka-client-cert   # Secret with tls.crt and tls.key
      
      # SASL authentication
      sasl:
        mechanism: SCRAM-SHA-512    # PLAIN, SCRAM-SHA-256, or SCRAM-SHA-512
        credentialsSecretRef:
          name: kafka-credentials   # Secret with username and password keys
      
      # Performance tuning
      batchSize: 100                # Events per batch
      batchTimeoutSeconds: 1        # Max wait before flush
      requiredAcks: -1              # -1=all, 0=none, 1=leader
      compression: snappy           # none, gzip, snappy, lz4, zstd
      async: false                  # true for fire-and-forget
```

### Webhook Sink

Send events to external HTTP endpoints (SIEM, log aggregators):

```yaml
sinks:
  - name: splunk
    type: webhook
    minSeverity: warning  # Only warnings and critical
    webhook:
      url: https://splunk.example.com/services/collector/event
      headers:
        Content-Type: application/json
      authSecretRef:
        name: splunk-hec-token      # Secret with 'token' key for Bearer auth
      timeoutSeconds: 10
      tls:
        caSecretRef:
          name: splunk-ca
      batchSize: 50                 # Send events in batches
```

### Log Sink

Write events to structured logs (always available, useful for debugging):

```yaml
sinks:
  - name: logs
    type: log
    log:
      level: info
      format: json
```

### Kubernetes Event Sink

Create Kubernetes Events for session lifecycle:

```yaml
sinks:
  - name: k8s-events
    type: kubernetes
    eventTypes:
      - session.requested
      - session.approved
      - session.revoked
```

## Event Types

The audit system captures 120+ event types organized by category:

### Session Events
- `session.requested` - Session requested by user
- `session.approved` - Session approved by approver
- `session.denied` - Session denied by approver
- `session.rejected` - Session auto-rejected by policy
- `session.activated` - Session now active
- `session.expired` - Session time expired
- `session.revoked` - Session manually revoked
- `session.extended` - Session duration extended
- `session.validated` / `session.invalidated` - Session validation

### Access Events (per-request granularity)
- `access.allowed` / `access.granted` - Access permitted
- `access.denied` - Access denied
- `access.denied.policy` - Denied by DenyPolicy
- `access.checked` - Authorization check performed

### Kubernetes Resource Operations
- `resource.get` / `resource.list` / `resource.watch`
- `resource.create` / `resource.update` / `resource.patch`
- `resource.delete` / `resource.deletecollection`
- `resource.exec` / `resource.attach` / `resource.logs`
- `resource.portforward` / `resource.proxy`
- `resource.impersonate` / `resource.scale`
- `resource.approve` / `resource.sign` / `resource.bind`

### Non-Resource URL Events (metrics server, health endpoints)
These capture access to non-API endpoints:
- `nonresource.access` - Generic non-resource URL access
- `nonresource.metrics` - Access to /metrics (Prometheus, metrics-server)
- `nonresource.healthz` - Access to /healthz endpoints
- `nonresource.readyz` - Access to /readyz endpoints
- `nonresource.livez` - Access to /livez endpoints
- `nonresource.version` - Access to /version
- `nonresource.api` - Access to /api, /apis discovery
- `nonresource.openapi` - Access to /openapi/v2, /openapi/v3
- `nonresource.logs` - Access to /logs
- `nonresource.swagger` - Access to Swagger UI

### Secret Access (high security)
- `secret.accessed` / `secret.created`
- `secret.updated` / `secret.deleted`

### RBAC Events
- `role.created` / `role.updated` / `role.deleted`
- `rolebinding.created` / `rolebinding.updated` / `rolebinding.deleted`
- `clusterrole.created` / `clusterrole.updated` / `clusterrole.deleted`
- `clusterrolebinding.created` / `clusterrolebinding.updated` / `clusterrolebinding.deleted`

### Debug Session Events
- `debug_session.created` / `debug_session.started`
- `debug_session.attached` / `debug_session.terminated`
- `debug_session.command` / `debug_session.file_access`

### Authentication Events
- `auth.attempt` / `auth.success` / `auth.failure`
- `auth.mfa` / `auth.token_issued` / `auth.token_refresh`

## Filtering

Control which events are captured:

```yaml
spec:
  filtering:
    # Include only specific events
    includeEventTypes:
      - session.*
      - access.denied*
      - secret.*
    
    # Exclude noisy events
    excludeEventTypes:
      - resource.list
      - resource.watch
    
    # Filter by user (supports globs)
    excludeUsers:
      - "system:serviceaccount:kube-system:*"
      - "system:node:*"
    
    # Filter by namespace
    excludeNamespaces:
      - kube-system
      - kube-public
    
    # Filter by resource type
    includeResources:
      - secrets
      - configmaps
      - pods
```

### Namespace Filtering with Labels

Namespace filters support both string patterns and Kubernetes label selectors:

```yaml
spec:
  filtering:
    # Include namespaces matching patterns OR labels
    includeNamespaces:
      patterns:
        - "prod-*"
        - "staging-*"
      selectorTerms:
        - matchLabels:
            audit-enabled: "true"
    
    # Exclude system namespaces by pattern
    excludeNamespaces:
      patterns:
        - "kube-*"
      selectorTerms:
        - matchLabels:
            audit-exclude: "true"
```

This allows dynamic namespace selection based on labels, which is useful when:
- New namespaces are created frequently
- Namespace naming conventions vary
- You want to use Kubernetes-native label selectors

## Sampling

For high-volume environments, sample frequent events:

```yaml
spec:
  sampling:
    rate: "0.1"  # Sample 10% of high-volume events
    
    # These events are sampled
    highVolumeEventTypes:
      - resource.get
      - resource.list
      - resource.watch
      - api.request
    
    # These are ALWAYS captured (never sampled)
    alwaysCaptureEventTypes:
      - session.requested
      - session.approved
      - access.denied
      - secret.accessed
      - policy.violation
```

## Queue Configuration

Tune the async queue for your throughput:

```yaml
spec:
  queue:
    size: 100000      # Buffer up to 100k events
    workers: 5        # 5 parallel sink writers
    dropOnFull: true  # Drop events silently when full (non-blocking)
```

**Recommendations:**
- Production: `size: 100000`, `workers: 5-10`
- High-volume: `size: 500000`, `workers: 20`
- Low-latency: `size: 10000`, `workers: 3`, smaller batches

## Per-Sink Filtering

Each sink can have its own event type and severity filters:

```yaml
sinks:
  # All events to Kafka
  - name: kafka-all
    type: kafka
    kafka: {...}
  
  # Only security events to SIEM
  - name: siem
    type: webhook
    minSeverity: warning
    eventTypes:
      - access.denied*
      - secret.*
      - policy.violation
      - pod_security.*
      - auth.failure
    webhook: {...}
  
  # Session events as K8s Events
  - name: k8s
    type: kubernetes
    eventTypes:
      - session.*
```

## Metrics

The audit system exposes Prometheus metrics:

- `breakglass_audit_events_processed_total` - Events successfully written
- `breakglass_audit_events_dropped_total` - Events dropped (queue full)
- `breakglass_audit_sink_errors_total{sink="..."}` - Errors by sink
- `breakglass_audit_sink_latency_seconds{sink="..."}` - Write latency histogram

## Examples

See [config/samples/audit_config_kafka.yaml](../config/samples/audit_config_kafka.yaml) for complete examples including:
- Full Kafka with TLS and SCRAM authentication
- Development Kafka (no auth)
- Webhook to SIEM
- Multi-sink configuration

## Secrets Format

### Kafka CA Certificate
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kafka-ca-cert
type: Opaque
data:
  ca.crt: <base64-encoded-ca-certificate>
```

### Kafka Client Certificate (mTLS)
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kafka-client-cert
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-client-cert>
  tls.key: <base64-encoded-client-key>
```

### Kafka SASL Credentials
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kafka-credentials
type: Opaque
stringData:
  username: kafka-user
  password: secret-password
```

### Webhook Bearer Token
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: webhook-auth
type: Opaque
stringData:
  token: your-bearer-token
```
