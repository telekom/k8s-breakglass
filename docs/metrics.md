# Prometheus Metrics

Breakglass exposes comprehensive Prometheus metrics for monitoring system health, performance, and audit trails. Metrics are available at the `/api/metrics` endpoint in standard Prometheus format.

**Access Metrics:**

```bash
curl https://breakglass.example.com/api/metrics
```

**Prometheus Scrape Configuration:**

```yaml
scrape_configs:
  - job_name: 'breakglass'
    static_configs:
      - targets: ['breakglass.example.com:8080']
    metrics_path: '/api/metrics'
    scheme: 'https'
    bearer_token: '<bearer-token>'  # If authentication required
```

## Webhook Metrics

These metrics track authorization webhook activity and decisions.

### Request Volume

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_webhook_sar_requests_total` | Counter | `cluster` | Total SubjectAccessReview requests received |
| `breakglass_webhook_sar_requests_by_action_total` | Counter | `cluster`, `verb`, `api_group`, `resource`, `namespace`, `subresource` | SAR requests grouped by action (verb, resource, namespace) |

**Example Queries:**

```promql
# Requests per cluster
sum(rate(breakglass_webhook_sar_requests_total[5m])) by (cluster)

# Requests by action (e.g., get pod requests)
breakglass_webhook_sar_requests_by_action_total{verb="get", resource="pods"}
```

### Authorization Decisions

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_webhook_sar_allowed_total` | Counter | `cluster` | SAR requests allowed by webhook |
| `breakglass_webhook_sar_denied_total` | Counter | `cluster` | SAR requests denied by webhook |
| `breakglass_webhook_sar_decisions_by_action_total` | Counter | `cluster`, `verb`, `api_group`, `resource`, `namespace`, `subresource`, `decision`, `deny_source` | Decisions (allowed/denied) by action and deny source |

**Example Queries:**

```promql
# Allow/deny ratio
sum(rate(breakglass_webhook_sar_allowed_total[5m])) by (cluster) 
/
sum(rate(breakglass_webhook_sar_denied_total[5m])) by (cluster)

# Deny sources (e.g., "policy", "no_session")
sum(rate(breakglass_webhook_sar_decisions_by_action_total{decision="denied"}[5m])) by (deny_source)
```

### Session-Based Authorization

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_webhook_session_sar_allowed_total` | Counter | `cluster`, `session`, `group` | Session grants that allowed access |
| `breakglass_webhook_session_sar_denied_total` | Counter | `cluster`, `session`, `group` | Session grants that denied access |
| `breakglass_webhook_session_sar_errors_total` | Counter | `cluster`, `session`, `group` | Errors checking session grants |
| `breakglass_webhook_session_sars_skipped_total` | Counter | `cluster` | Session checks skipped (e.g., due to config errors) |

### Session Activity Tracking

Activity tracking records when sessions are actively used by the authorization webhook. Activity data is buffered and flushed periodically (default 30s) to reduce API server load. The `lastActivity` and `activityCount` fields on `BreakglassSessionStatus` are updated on each flush cycle via an optimistic-concurrency status merge-patch (retry-on-conflict). Failed flushes are re-queued with merge logic (up to 5 retries).

| Metric | Type | Labels | Description |
|--------|------|--------|-----------|
| `breakglass_session_activity_requests_total` | Counter | `cluster`, `granted_group` | Authorization requests that matched a breakglass session (bounded by granted group, not session name) |
| `breakglass_session_activity_flushes_total` | Counter | — | Activity tracker flush cycles completed |
| `breakglass_session_activity_flush_errors_total` | Counter | — | Failed activity status updates during flush |
| `breakglass_session_activity_dropped_total` | Counter | — | Activity entries dropped due to tracker capacity limit |
| `breakglass_session_idle_expired_total` | Counter | `cluster` | Sessions automatically expired due to idle timeout |

**Example Queries:**

```promql
# Activity rate by granted group
sum by (granted_group) (rate(breakglass_session_activity_requests_total[5m]))

# Activity rate per cluster
sum by (cluster) (rate(breakglass_session_activity_requests_total[5m]))

# Flush error rate
rate(breakglass_session_activity_flush_errors_total[5m])

# Idle expiration rate per cluster
sum by (cluster) (rate(breakglass_session_idle_expired_total[5m]))
```

### Session-Based Authorization (Example Queries)

```promql
# Success rate of session grant checks
sum(rate(breakglass_webhook_session_sar_allowed_total[5m]))
/
(
  sum(rate(breakglass_webhook_session_sar_allowed_total[5m]))
  + sum(rate(breakglass_webhook_session_sar_denied_total[5m]))
)

# Error rate
sum(rate(breakglass_webhook_session_sar_errors_total[5m]))
```

### SAR Processing Phase Timing

These metrics track the time spent in each phase of SubjectAccessReview processing, enabling detailed performance analysis and bottleneck identification.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_webhook_sar_phase_duration_seconds` | Histogram | `cluster`, `phase` | Duration of each SAR processing phase |

**Processing Phases:**

| Phase | Description |
|-------|-------------|
| `parse` | JSON request unmarshaling |
| `cluster_config` | ClusterConfig lookup |
| `sessions` | Load user groups and sessions |
| `debug_session` | Early debug session check |
| `deny_policy` | DenyPolicy evaluation |
| `rbac_check` | canDoFn RBAC verification (when applicable) |
| `session_sars` | Session authorization checks |
| `escalations` | Escalation discovery |
| `total` | Complete request duration |

**Example Queries:**

```promql
# Average time per phase
avg(rate(breakglass_webhook_sar_phase_duration_seconds_sum[5m]))
/
avg(rate(breakglass_webhook_sar_phase_duration_seconds_count[5m]))
  by (cluster, phase)

# Identify slowest phase (p95)
histogram_quantile(0.95, 
  rate(breakglass_webhook_sar_phase_duration_seconds_bucket[5m])
) by (phase)

# Total SAR processing time by cluster
histogram_quantile(0.99, 
  rate(breakglass_webhook_sar_phase_duration_seconds_bucket{phase="total"}[5m])
) by (cluster)

# Compare session lookup vs RBAC check duration
histogram_quantile(0.95,
  rate(breakglass_webhook_sar_phase_duration_seconds_bucket{phase=~"sessions|rbac_check"}[5m])
) by (phase)
```

## Session Lifecycle Metrics

Track breakglass session creation, state changes, and expiration.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_session_created_total` | Counter | `cluster` | Sessions created |
| `breakglass_session_updated_total` | Counter | `cluster` | Session status updates (approve/reject/etc) |
| `breakglass_session_deleted_total` | Counter | `cluster` | Sessions deleted |
| `breakglass_session_expired_total` | Counter | `cluster` | Sessions expired automatically (time-based) |
| `breakglass_session_idle_expired_total` | Counter | `cluster` | Sessions expired due to idle timeout |

**Example Queries:**

```promql
# Approval rate
sum(rate(breakglass_session_created_total[1h]))
# (created sessions per hour)

# Session churn
sum(rate(breakglass_session_expired_total[5m])) by (cluster)
/ 
sum(rate(breakglass_session_created_total[5m])) by (cluster)

# Growth of active sessions (approximate)
sum(increase(breakglass_session_created_total[1d])) 
- 
sum(increase(breakglass_session_expired_total[1d]))
```

## Mail Notification Metrics

Track success/failure of email notifications sent to approvers and requesters.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_mail_send_success_total` | Counter | `host` | Successfully sent emails |
| `breakglass_mail_send_failure_total` | Counter | `host` | Failed email sends |

**Example Queries:**

```promql
# Mail delivery success rate
sum(rate(breakglass_mail_send_success_total[5m]))
/
(
  sum(rate(breakglass_mail_send_success_total[5m]))
  + sum(rate(breakglass_mail_send_failure_total[5m]))
)

# Failed sends by mail server
breakglass_mail_send_failure_total
```

## API Endpoint Metrics

Track frontend and REST API usage with dedicated counters and histograms. All Breakglass session and escalation REST endpoints now emit these metrics automatically through a shared instrumentation wrapper, so create/read/update paths show up in dashboards without manual bookkeeping.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_api_endpoint_requests_total` | Counter | `endpoint` | Total requests routed through a given API handler (e.g., `handleGetEscalations`, `handleRequestBreakglassSession`, `getIdentityProvider`) |
| `breakglass_api_endpoint_errors_total` | Counter | `endpoint`, `status_code` | Error responses grouped by handler and HTTP status |
| `breakglass_api_endpoint_duration_seconds` | Histogram | `endpoint` | Request latency buckets (10ms to 1s) per handler |

**Example Queries:**

```promql
# Error rate per endpoint
sum(rate(breakglass_api_endpoint_errors_total[5m])) by (endpoint)
/
sum(rate(breakglass_api_endpoint_requests_total[5m])) by (endpoint)

# 95th percentile latency for the escalations API
histogram_quantile(
  0.95,
  sum by (le) (rate(breakglass_api_endpoint_duration_seconds_bucket{endpoint="handleGetEscalations"}[5m]))
)

**Session Endpoint Labels:**

| Endpoint Label | Description |
|----------------|-------------|
| `handleGetBreakglassSessionStatus` | GET `/api/breakglassSessions` list endpoint |
| `handleGetBreakglassSessionByName` | GET `/api/breakglassSessions/:name` detail endpoint |
| `handleRequestBreakglassSession` | POST create session |
| `handleApproveBreakglassSession` | POST `:name/approve` |
| `handleRejectBreakglassSession` | POST `:name/reject` |
| `handleWithdrawMyRequest` | POST `:name/withdraw` |
| `handleDropMySession` | POST `:name/drop` |
| `handleApproverCancel` | POST `:name/cancel` |
| `handleGetEscalations` | GET breakglassEscalations list |
```

## ClusterConfig Validation Metrics

Monitor the health of cluster configurations.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_clusterconfigs_checked_total` | Counter | `cluster` | ClusterConfig validations performed |
| `breakglass_clusterconfigs_failed_total` | Counter | `cluster` | ClusterConfig validations that failed |

**Example Queries:**

```promql
# Config health per cluster
sum(rate(breakglass_clusterconfigs_checked_total[5m])) by (cluster)
- 
sum(rate(breakglass_clusterconfigs_failed_total[5m])) by (cluster)

# Failure rate
sum(rate(breakglass_clusterconfigs_failed_total[5m])) by (cluster)
/
sum(rate(breakglass_clusterconfigs_checked_total[5m])) by (cluster)
```

## Pod Security Evaluation Metrics

Track risk-based pod security evaluation for exec/attach/portforward operations. See [DenyPolicy - Pod Security Rules](./deny-policy.md#podsecurityrules) for configuration.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_pod_security_evaluations_total` | Counter | `cluster`, `policy`, `action` | Total evaluations (action: allowed/denied/warned) |
| `breakglass_pod_security_risk_score` | Histogram | `cluster` | Distribution of calculated risk scores |
| `breakglass_pod_security_factors_total` | Counter | `cluster`, `factor` | Count of detected risk factors (e.g., hostNetwork, privilegedContainer) |
| `breakglass_pod_security_denied_total` | Counter | `cluster`, `policy` | Exec/attach requests denied by security policy |
| `breakglass_pod_security_warnings_total` | Counter | `cluster`, `policy` | Exec/attach requests allowed with security warnings |

**Example Queries:**

```promql
# Deny rate by policy
sum(rate(breakglass_pod_security_denied_total[5m])) by (policy)

# Average risk score by cluster
histogram_quantile(0.50, sum(rate(breakglass_pod_security_risk_score_bucket[5m])) by (le, cluster))

# Most common risk factors
topk(5, sum(rate(breakglass_pod_security_factors_total[5m])) by (factor))

# Warning vs denial ratio
sum(rate(breakglass_pod_security_warnings_total[5m])) by (cluster)
/
sum(rate(breakglass_pod_security_denied_total[5m])) by (cluster)
```

**Risk Factor Labels:**

| Factor Label | Description |
|--------------|-------------|
| `hostNetwork` | Pod uses host network namespace |
| `hostPID` | Pod uses host PID namespace |
| `hostIPC` | Pod uses host IPC namespace |
| `privilegedContainer` | Container runs in privileged mode |
| `hostPathWritable` | Pod has writable hostPath mounts |
| `hostPathReadOnly` | Pod has read-only hostPath mounts |
| `runAsRoot` | Container runs as UID 0 |
| `capability:*` | Linux capability detected (e.g., `capability:SYS_ADMIN`) |

## Alerting Recommendations

Use these alert rules to monitor system health:

```yaml
groups:
  - name: breakglass-alerts
    rules:
      # High webhook request latency
      - alert: BreakglassWebhookLatency
        expr: histogram_quantile(0.99, breakglass_webhook_sar_duration_seconds) > 1
        for: 5m
        annotations:
          summary: "Breakglass webhook latency is high"

      # High deny rate
      - alert: BreakglassHighDenyRate
        expr: |
          sum(rate(breakglass_webhook_sar_denied_total[5m])) by (cluster) 
          / 
          sum(rate(breakglass_webhook_sar_requests_total[5m])) by (cluster) > 0.5
        for: 10m
        annotations:
          summary: "High authorization denial rate on cluster {{ $labels.cluster }}"

      # Mail delivery failures
      - alert: BreakglassMailFailures
        expr: |
          sum(rate(breakglass_mail_send_failure_total[5m])) by (host) > 0.05
        for: 15m
        annotations:
          summary: "Mail delivery failures from {{ $labels.host }}"

      # Session SAR errors
      - alert: BreakglassSessionSARErrors
        expr: |
          sum(rate(breakglass_webhook_session_sar_errors_total[5m])) > 0.1
        for: 10m
        annotations:
          summary: "Session SAR check errors detected"

      # Cluster config failures
      - alert: BreakglassClusterConfigError
        expr: |
          sum(rate(breakglass_clusterconfigs_failed_total[5m])) by (cluster) > 0
        for: 5m
        annotations:
          summary: "ClusterConfig validation errors on {{ $labels.cluster }}"
```

## Dashboard Recommendations

Consider creating Grafana dashboards with these panels:

**Overview Dashboard:**

- Webhook requests per cluster (rate)
- Allow/deny decision pie chart
- Session lifecycle (created, expired, approved per day)
- Mail delivery success rate

**Operations Dashboard:**

- Denial rate trends (alert on spikes)
- Session approval time distribution
- Webhook latency percentiles (p50, p95, p99)
- ClusterConfig health per cluster

**Audit Dashboard:**

- Sessions created per cluster (daily)
- Sessions by approver
- High-frequency denials (potential issues)
- Failed mail notifications

## Metrics Retention & Cardinality

**Cardinality Considerations:**

- Webhook SAR metrics include `namespace` and `subresource` labels which may have high cardinality in large clusters
- Session labels (`session`, `group`) are included in session SAR metrics for audit trails
- Consider using label relabeling in Prometheus to drop high-cardinality labels if needed

**Example Prometheus relabeling:**

```yaml
metric_relabel_configs:
  - source_labels: [__name__]
    regex: 'breakglass_webhook_sar_requests_by_action_total'
    target_label: __tmp_cardinality
  - source_labels: [__tmp_cardinality]
    regex: '.+'
    action: drop_labels
    labels: [namespace]  # Drop namespace label to reduce cardinality
```

## IdentityProvider Lifecycle Metrics

Monitor the health and performance of identity provider configuration reloading and OIDC authentication.

### Configuration Reload Performance

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_identity_provider_reload_duration_seconds` | Histogram | `provider_type` | Duration of IdentityProvider configuration reloads (buckets: 0.1s to 60s) |
| `breakglass_identity_provider_reload_attempts_total` | Counter | `status`, `provider_type` | Total reload attempts by status (`success`, `error`, `skipped`) |
| `breakglass_identity_provider_last_reload_timestamp_seconds` | Gauge | `provider_type` | Unix timestamp of last successful reload per provider type |

**Example Queries:**

```promql
# Configuration reload latency (p95)
histogram_quantile(0.95, rate(breakglass_identity_provider_reload_duration_seconds_bucket[5m]))

# Reload failure rate (should be 0 or near 0)
sum(rate(breakglass_identity_provider_reload_attempts_total{status="error"}[5m]))
/
sum(rate(breakglass_identity_provider_reload_attempts_total[5m]))

# Time since last successful reload (staleness detection)
time() - breakglass_identity_provider_last_reload_timestamp_seconds
```

### Configuration State and Validity

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_identity_provider_config_version` | Gauge | `provider_type` | Hash of current loaded configuration (changes when config updates) |
| `breakglass_identity_provider_status` | Gauge | `provider_name`, `provider_type` | Provider status: `1` = Active, `0` = Error, `-1` = Disabled |

**Example Queries:**

```promql
# Configuration version changes (indicates successful reloads)
changes(breakglass_identity_provider_config_version[1h])

# Active providers count
count(breakglass_identity_provider_status == 1)

# Disabled providers count
count(breakglass_identity_provider_status == -1)

# Alert on provider errors
breakglass_identity_provider_status == 0
```

### Alert Rules

**Recommended Prometheus alert rules:**

```yaml
groups:
  - name: breakglass_identity_provider
    interval: 30s
    rules:
      - alert: IdentityProviderReloadFailure
        expr: |
          rate(breakglass_identity_provider_reload_attempts_total{status="error"}[5m]) > 0
        for: 2m
        annotations:
          summary: "IdentityProvider reload failing"
          description: "Identity provider configuration reload has failed: {{ $value }}"

      - alert: IdentityProviderStale
        expr: |
          time() - breakglass_identity_provider_last_reload_timestamp_seconds > 900
        for: 5m
        annotations:
          summary: "IdentityProvider configuration is stale (>15m)"
          description: "No successful reload for 15+ minutes on {{ $labels.provider_type }}"

      - alert: IdentityProviderReloadSlow
        expr: |
          histogram_quantile(0.95, rate(breakglass_identity_provider_reload_duration_seconds_bucket[5m])) > 5
        for: 5m
        annotations:
          summary: "IdentityProvider reload is slow (>5s)"
          description: "p95 reload latency: {{ $value | humanizeDuration }}"

      - alert: IdentityProviderDown
        expr: |
          breakglass_identity_provider_status == 0
        for: 2m
        annotations:
          summary: "IdentityProvider {{ $labels.provider_name }} is DOWN"
          description: "Provider cannot be loaded or is in error state"
```

## Scrape Configuration Best Practices

1. **Set appropriate scrape intervals** - Default 15s is usually fine, but high-volume environments may use 30s
2. **Add authentication** - Use bearer tokens if the metrics endpoint requires authentication
3. **Enable compression** - Consider gzip compression for large metric exports
4. **Add relabel configs** - Drop unnecessary labels to reduce storage overhead
5. **Set appropriate retention** - Breakglass metrics are mostly counters; 15 days retention is typical

**Example production configuration:**

```yaml
scrape_configs:
  - job_name: 'breakglass'
    scrape_interval: 30s
    scrape_timeout: 10s
    static_configs:
      - targets: ['breakglass.example.com:8080']
    metrics_path: '/api/metrics'
    scheme: 'https'
    bearer_token: 'your-bearer-token'
    tls_config:
      insecure_skip_verify: false  # Verify TLS certificates
    metric_relabel_configs:
      # Drop high-cardinality labels
      - source_labels: [__name__]
        regex: 'breakglass_webhook_sar_.*'
        action: drop_labels
        labels: [subresource]
```

## Troubleshooting with Metrics

**No metrics appearing:**

- Check bearer token/authentication credentials
- Verify `/api/metrics` endpoint is accessible
- Check firewall rules between Prometheus and breakglass service

**High denial rate:**

- Check for policy misconfigurations
- Review `DenyPolicy` rules
- Examine webhook logs for details

**Mail delivery failures:**

- Check mail server connectivity via `kubectl get mailproviders`
- Verify MailProvider status shows `Ready`
- Check SMTP credentials secret exists and is accessible
- Verify firewall rules to mail server
- Review mail provider metrics (`breakglass_mail_provider_*`)

**Session SAR errors:**

- Review ClusterConfig health
- Check if clusters are reachable
- Look for webhook timeout errors

For more troubleshooting guidance, see [Troubleshooting Guide](./troubleshooting.md).
