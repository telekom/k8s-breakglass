# Circuit Breaker for Spoke Cluster Communication

The breakglass controller communicates with spoke clusters for SAR webhook
evaluation, debug session lifecycle, and session status synchronization. If a
spoke becomes unreachable, these calls block until TCP timeout (typically 30 s),
causing SAR webhook latency spikes, reconciliation queue backup, and potential
cascading failures affecting other spokes.

The **circuit breaker** detects unreachable spokes and fails fast — rejecting
requests immediately instead of waiting for TCP timeout.

## How It Works

Each spoke cluster gets its own circuit breaker that tracks consecutive
transient failures (network timeouts, connection refused, etc.).

```
  ┌────────┐    N failures     ┌────────┐    timeout elapsed    ┌───────────┐
  │ Closed │ ──────────────►  │  Open  │ ──────────────────►  │ Half-Open │
  │(normal)│                   │(reject)│                       │  (probe)  │
  └────────┘                   └────────┘  ◄──────────────────  └───────────┘
       ▲                                    any failure              │
       └─────────────────── M successes ─────────────────────────────┘
```

| State | Behavior |
|---|---|
| **Closed** | Normal operation. Requests flow through. Consecutive failures are counted. |
| **Open** | Cluster is considered unreachable. Requests are rejected immediately with `ErrCircuitOpen`. After the configured `openDuration`, limited probe requests are allowed through (default: 1). |
| **Half-Open** | A limited number of probe requests test whether the cluster has recovered. Success closes the circuit; any failure re-opens it. |

### Error Classification

Only **transient** errors trip the circuit breaker:

| Transient (counted) | Non-transient (ignored) |
|---|---|
| Connection refused | Unauthorized / Forbidden |
| Connection reset | Not Found |
| No route to host | Invalid request |
| Network unreachable | HTTP 429 (Too Many Requests) |
| I/O timeout | |
| TLS handshake timeout | |
| Context deadline exceeded | |
| EOF / broken pipe | |
| HTTP 5xx (502, 503, 504, etc.) | |
This prevents authentication or configuration errors from incorrectly
marking a reachable cluster as unavailable.

## Configuration

Add to your `config.yaml`:

```yaml
kubernetes:
  circuitBreaker:
    enabled: true
    failureThreshold: 3       # consecutive failures before opening
    successThreshold: 2       # consecutive successes in half-open before closing
    openDuration: "30s"       # how long to wait before probing
    halfOpenMaxRequests: 1    # concurrent requests allowed in half-open
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Opt-in. Set to `true` to enable circuit breaker protection. |
| `failureThreshold` | `3` | Consecutive transient failures required to open the circuit. |
| `successThreshold` | `2` | Consecutive successes in half-open state to close the circuit. |
| `openDuration` | `30s` | Time the circuit stays open before allowing a probe request. |
| `halfOpenMaxRequests` | `1` | Max concurrent probe requests in half-open state. |

## Prometheus Metrics

All metrics use the `breakglass_cluster_circuit_breaker_` prefix with a
`cluster` label.

| Metric | Type | Description |
|---|---|---|
| `breakglass_cluster_circuit_breaker_state` | Gauge | Current state (0=closed, 1=open, 2=half-open) |
| `breakglass_cluster_circuit_breaker_rejections_total` | Counter | Requests rejected due to open circuit |
| `breakglass_cluster_circuit_breaker_state_transitions_total` | Counter | State transitions (labels: `from`, `to`) |
| `breakglass_cluster_circuit_breaker_failures_total` | Counter | Transient failures recorded |
| `breakglass_cluster_circuit_breaker_successes_total` | Counter | Successful operations recorded |
| `breakglass_cluster_circuit_breaker_consecutive_failures` | Gauge | Current consecutive failure count |

### Example Alerting Rules

```yaml
# Alert when a spoke cluster circuit breaker opens
- alert: SpokeClusterCircuitOpen
  expr: breakglass_cluster_circuit_breaker_state == 1
  for: 1m
  labels:
    severity: warning
  annotations:
    summary: "Circuit breaker open for cluster {{ $labels.cluster }}"
    description: "Spoke cluster {{ $labels.cluster }} is unreachable. Requests are being rejected immediately."

# Alert on high rejection rate
- alert: SpokeClusterHighRejections
  expr: rate(breakglass_cluster_circuit_breaker_rejections_total[5m]) > 1
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "High circuit breaker rejection rate for {{ $labels.cluster }}"
```

## Integration Points

The circuit breaker wraps `ClientProvider.GetRESTConfig()` — the single entry
point for all spoke cluster communication. Callers should also report outcomes
back to the breaker:

```go
cfg, err := clientProvider.GetRESTConfig(ctx, clusterName)
if err != nil {
    // If circuit is open, err wraps ErrCircuitOpen
    return err
}

// Use the config to call the spoke cluster...
// Note: the circuit breaker transport automatically records success/failure
// for each HTTP request, so manual RecordSuccess/RecordFailure calls are only
// needed for non-HTTP operations (e.g., watch setup, informer startup).
// Always use the canonical "namespace/name" key for these calls.
result, err := doSomething(ctx, cfg)
if err != nil {
    clientProvider.RecordFailure(clusterName, err)
    return err
}
clientProvider.RecordSuccess(clusterName)
```

## Disabling the Circuit Breaker

The circuit breaker is **opt-in** and disabled by default. When disabled:
- `RecordSuccess` / `RecordFailure` are no-ops
- `GetRESTConfig` performs no circuit breaker checks
- No per-cluster Prometheus metrics are emitted

Changing `enabled` from `true` to `false` in the configuration takes effect only
after restarting the breakglass controller. On restart, all breaker state is
reset; clusters that were previously in the Open state become reachable again.
