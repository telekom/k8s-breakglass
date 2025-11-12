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

**Example Queries:**

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

## Session Lifecycle Metrics

Track breakglass session creation, state changes, and expiration.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `breakglass_session_created_total` | Counter | `cluster` | Sessions created |
| `breakglass_session_updated_total` | Counter | `cluster` | Session status updates (approve/reject/etc) |
| `breakglass_session_deleted_total` | Counter | `cluster` | Sessions deleted |
| `breakglass_session_expired_total` | Counter | `cluster` | Sessions expired automatically |

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
- Check mail server connectivity
- Verify SMTP credentials in config
- Check firewall rules to mail server

**Session SAR errors:**
- Review ClusterConfig health
- Check if clusters are reachable
- Look for webhook timeout errors

For more troubleshooting guidance, see [Troubleshooting Guide](./troubleshooting.md).
