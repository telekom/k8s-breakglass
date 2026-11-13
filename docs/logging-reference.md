<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Logging Reference

This page lists, for every program in this repository, what it logs, at which
level, in which format and with which fields. It complements
[Logging and Debugging](logging-and-debugging.md#log-level-and-format), which
explains how to set the level and format.

The [message catalogue](#message-catalogue) at the end is generated from the
log calls in the Go code by `go run ./hack/logref`. The unit test in
`hack/logref` (part of `make test`) fails when the catalogue does not match the
code. A pull request that adds, removes or changes a log message, level or
literal field key must regenerate the catalogue.

## Programs that log

| Program | Runs as | Logger | Levels | Output |
|---------|---------|--------|--------|--------|
| Controller (`/breakglass`, `cmd/main.go`) | `breakglass-manager` Deployment. Covers the hub API, frontend, SubjectAccessReview webhook, validating webhooks, reconcilers, cleanup, audit, mail, leader election, debug sessions, terminal recordings and artifacts | zap | debug, info, warn, error | `json` (default) or `console` on stderr |
| `breakglass artifacts provision` (`cmd/artifacts.go`) | one-off subcommand of the controller binary | plain text | none | text on stdout; `fatal: …` on stderr |
| `bgctl` (`cmd/bgctl`) | operator CLI | plain text | `--verbose` / `BGCTL_VERBOSE=true` | the verbose request trace (`[DEBUG] [bgctl] METHOD path (correlationID=…)`, then `-> status`) goes to stderr; command output goes to stdout (`-o table\|wide\|json\|yaml`) |
| `cluster-validator` (`cmd/cluster-validator`) | validator image | plain text | none | `cluster-validator: <error>` on stderr; the JSON report on stdout or a file |
| Node-maintenance helpers: `utils/node-maintenance/cmd/hotfix-action`, `utils/node-maintenance/cmd/kexec-action`, `utils/node-maintenance/cmd/network-action`, `utils/node-maintenance/cmd/service-action`, and the `node-maintenance` shell entrypoint | node-maintenance utility image | plain text | none | `<name>: <error>` on stderr; `hotfix-action` writes its JSON result to stdout and the termination log |
| Diagnostic artifact collector: `utils/images/diagnostic-artifact-collector/copier`, `utils/images/diagnostic-artifact-collector/uploader`, and the shell entrypoint | artifact collection pod | plain text | none | `diagnostic-artifact-collector: …` on stderr. The uploader replaces upload URLs, tokens and archive paths with `[URL]`, `[TOKEN]` and `[ARCHIVE]` |
| `utils/network-debug/tools` (`fetch`) | network-debug image build only; not in the runtime image | plain text | none | errors on stderr during the image build |
| `dump-reader`, `storage-debug`, `network-debug`, `workload-debug` images | debug-session pods | shell `printf`/`echo` | none | `<name>: <message>` on stderr. The third-party tools built into them (`pwru`, `kubestr`) keep their own logging |
| Frontend | browser (the controller serves the files) | browser console | debug only in a development build (`?debugLogs=` or the `breakglass:debugLogs` local-storage key) | browser console; nothing is sent to the server |

Only the controller has log levels. The rest of this page covers the
controller.

## Controller

### Levels

| Level | Use | Recommended |
|-------|-----|-------------|
| `error` | A request or reconcile failed, or a dependency (cluster, mail, audit sink, storage) is unavailable. Needs attention. | — |
| `warn` | A degraded state that the code handles: retries, fallbacks, skipped invalid objects, deprecations, dropped mail or audit events. | — |
| `info` | Lifecycle and state changes: startup configuration, leader election, session and debug-session transitions, the `http_request` line of each HTTP request, audit events of the `log` sink. | **production** |
| `debug` | Decision details: authorization and group checks, cache hits and misses, reconcile steps, token-claim summaries. High volume. | while debugging |

The controller code uses no logr V-levels and no `dpanic`, `panic` or `fatal`
calls. controller-runtime and client-go log through the same logger: their
V(0) lines appear at info, their V(1) lines at debug, and higher V-levels are
not written.

When debugging, raise the level of the whole process with
`--log-level=debug`. There is no per-component level. Keep `--log-format=json`
when a collector reads the logs; use `console` only on a terminal.

### Formats

`json` writes one JSON object per line. The fields every line has are
documented in [Logging and Debugging](logging-and-debugging.md#json-fields):
`level`, `ts`, `caller`, `msg`, `logger` (named loggers) and `error` (when
the line carries an error). The other keys are the structured fields listed
for each message in the catalogue. `console` writes the same content as
tab-separated text for people; its layout is not stable.

### Sampling and rate limits

The controller does not sample its logs. Every log call at or above the
configured level is written, so repeated lines such as authorization decisions
are all kept (test `TestNewDoesNotSample`). There is no log rate limiting or
de-duplication. Trace sampling (`--otel-sampling-rate`) does not affect the
log. Audit event sampling (`AuditConfig`) does: a sampled-out event reaches no
sink, so the `log` sink writes no `audit_event` line for it (see
[Logs and audit events](#logs-and-audit-events)).

### Lines from libraries

These lines come from libraries, so the catalogue does not list them:

| Source | Level | Message | Fields |
|--------|-------|---------|--------|
| HTTP access log (`gin-contrib/zap`), one line per request | info; error once per handler error | the request path | `status`, `method`, `path`, `query`†, `ip`†, `user-agent`, `latency`, `time` |
| controller-runtime (manager, controllers, webhooks, cache) | info, error; V(1) at debug | for example `Starting Controller`, `Reconciler error` | `logger` (for example `controller-runtime.webhook`), `controller`, `controllerGroup`, `controllerKind`, `name`, `namespace`, `reconcileID` |
| client-go (klog) | info, error | for example leader-election and reflector errors | free text |
| OpenTelemetry SDK | error; internal V-levels at debug or not written | for example exporter errors | free text |
| Go standard `log` package, for example `http: TLS handshake error from …` of `net/http` servers | warn | the text of the message | `logger` is `stdlog` |

### Request context fields

Every HTTP request gets a request-scoped logger with the fields `cid`
(correlation ID, also returned as `cid` in error responses), `method`, `path`
(the route template, for example `/api/breakglassSessions/:name`) and
`remote`† (client IP). Lines logged through it carry these fields in addition
to the fields in the catalogue. Handlers that authenticate the caller add
`email`†, `username`† and `groupCount`. Besides the library access-log line,
the controller writes one `http_request` line (info) for each request, with
`cid`, `method`, `path`, `status` and `latency`, and one `handler_error` line
(error) for each failed request, with `error` and `meta`. A panic in a
handler is logged as `[Recovery from panic]` (error) with `error`, `cid`,
`method` and `path`, without the request headers.

### Personal data

Fields marked † on this page and in the catalogue can contain personal or
host data:

- user identities: `user`, `username`, `email`, `requester`, `approver`,
  `subject`, `sub`, `actor_user`;
- group names and lists: `group`, `groups`, `actor_groups`;
- network data: `remote`, `ip`, `clientIP`, `actor_ip`;
- command lines: `command`, `args`;
- the access-log `query`, which can hold the `user` and `group` filters of
  API calls.

Messages built from errors (`(dynamic)` in the catalogue) can also contain
such data, for example in a Kubernetes API error message.

`server.redactLogs: true` in `config.yaml` replaces group names with
`[REDACTED]` and group lists with `[N items]` where the code passes them
through `system.RedactGroupName` or `system.RedactSlice`. The authorization
webhook, the session controller, the escalation manager and the debug-session
reconciler do this. The setting is off by default. It does not redact user
names, e-mail addresses, IP addresses, or the `actor_groups` field of audit
events.

### Never logged

- **Tokens.** After authentication the API removes the `Authorization` header
  from the request (`pkg/api/auth.go`). The access log and the panic log do
  not log headers (test `TestRecoverPanicsDoesNotLogCredentials`). For OIDC
  claims, only the claim names, `sub` and `username` are logged, at debug.
  Session and cluster token code logs lengths and booleans (`tokenLen`,
  `hasRefreshToken`, `hasActorToken`, `expiresIn`), never the token.
- **Secrets.** Kubeconfigs, SMTP passwords and S3 credentials are not logged;
  when loading them fails, only the error is logged. Audit webhook URLs are
  redacted in errors (test `TestWebhookSinkRedactsTransportURL`). Mail
  subjects, which name the requester and the requested group, are logged only as
  `subjectLength`. Recipients are not logged when an
  SMTP server rejects them (test `TestPlainSMTPRecipientReplyIsPrivate`).
- **Terminal content.** The terminal stream and the recordings
  (`pkg/breakglass/debug/terminal_protocol.go`, `recording.go`) have no log
  calls. The recording API logs only the session, the recording ID and errors.
  See [Terminal recording](terminal-recording.md).

The access log writes the raw query string (`query`). Do not put credentials
in URL query parameters.

### Logs and audit events

Logs are for operating the controller; they are not an audit trail. Audit
events, such as a session being requested, approved, rejected or expired, a
debug-session operation, or an authorization decision, go through the audit
sinks configured in `AuditConfig`: `log`, `webhook`, `kafka`, `kubernetes`,
and the chat sink. See [Audit configuration](audit-config.md) for the event
types and [Audit delivery](audit-delivery.md) for delivery, retries and loss.

Only the `log` sink writes into the controller log: one info line per event,
with `logger` set to `audit-service.audit` and the message `audit_event`.
Because these are ordinary controller log lines, two things can make an
audit event missing from the log although it happened:

- `--log-level=warn` or `error` drops all `audit_event` lines, because they are
  at info;
- audit event sampling and the include/exclude event types in `AuditConfig`
  drop events before they reach any sink.

Use the `webhook`, `kafka` or `kubernetes` sink when the audit trail must be
complete. Fields of an `audit_event` line:

| Field | Type | Present |
|-------|------|---------|
| `event_id` | string | always |
| `event_type` | string | always |
| `severity` | string | always |
| `timestamp` | RFC 3339 time | always |
| `actor_user`† | string | always |
| `target_kind`, `target_name` | string | always |
| `actor_idp` | string | when known |
| `actor_groups`† | array of strings | when known; `server.redactLogs` does not apply |
| `actor_ip`† | string | when known |
| `target_namespace`, `target_cluster` | string | when known |
| `session_name`, `escalation_name`, `correlation_id` | string | when known |
| `details` | JSON-encoded string | when the event has details |

The `level` and `format` settings of the `log` sink in `AuditConfig` have no
effect: the sink always writes at info, through the controller logger, in the
controller's `--log-format`.

### Examples

```json
{"level":"debug","ts":1763030400.120,"caller":"cmd/main.go:191","msg":"Debug logging enabled","logLevel":"debug","logFormat":"json"}
{"level":"info","ts":1763030400.531,"caller":"api/api.go:260","msg":"http_request","cid":"5f0c…","method":"GET","path":"/api/breakglassSessions","status":200,"latency":0.0042}
{"level":"warn","ts":1763030401.002,"caller":"cmd/main.go:189","msg":"--debug is deprecated; use --log-level=debug and, for this output format, --log-format=console"}
{"level":"error","ts":1763030402.877,"caller":"api/api.go:271","msg":"handler_error","cid":"5f0c…","method":"POST","path":"/api/breakglassSessions","remote":"10.0.0.7","error":"…","meta":"…"}
{"level":"info","ts":1763030403.100,"logger":"audit-service.audit","caller":"audit/sink.go:165","msg":"audit_event","event_id":"…","event_type":"session.approved","severity":"info","timestamp":"2026-11-13T10:00:03Z","actor_user":"jane@example.com","target_kind":"BreakglassSession","target_name":"…"}
```

The values and callers above are illustrations, not output to match against.

## Message catalogue

`go run ./hack/logref` writes the sections below. Each table lists the
distinct messages of one package by level, with the literal field keys of the
call (including keys added with `With` in the same expression) and the file.
Fields bound earlier to a logger variable, such as the [request context
fields](#request-context-fields), and fields passed as a slice, such as those
of `audit_event`, are not listed.

<!-- BEGIN GENERATED: go run ./hack/logref -->

## Levels in use

Number of distinct messages per process and level.

| Process | debug | info | warn | error | dpanic | fatal | V-levels |
|---|---|---|---|---|---|---|---|
| controller | 468 | 345 | 353 | 272 | 0 | 0 | 0 |

## Message catalogue

Fields marked † can hold personal or host data (user identities, e-mail
addresses, group names, IP addresses, command lines). `(dynamic)` is a
message built at run time, typically from an error value; `…` marks the
variable part of a concatenated message.

### controller

#### `api/v1alpha1`

| Level | Message | Fields | File |
|---|---|---|---|
| warn | `ensureClusterWideUniqueName called without context, using fallback` |  | validation_helpers.go |
| warn | `validateIdentityProviderFields called without context, using fallback` |  | validation_helpers.go |
| warn | `validateIdentityProviderRefs called without context, using fallback` |  | validation_helpers.go |
| warn | `validateMailProviderReference called without context, using fallback` |  | validation_helpers.go |
| warn | `validateSessionIdentityProviderAuthorization called without context, using fallback` |  | validation_helpers.go |
| error | `CRITICAL: ensureClusterWideUniqueIssuer called without context - creating timeout-bounded fallback` |  | validation_helpers.go |

#### `cmd`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Debug logging enabled` | `logFormat`, `logLevel` | main.go |
| debug | `Scheme initialized with CRDs` | `types` | main.go |
| info | `Audit service shut down successfully` |  | main.go |
| info | `Breakglass controller shutdown complete` |  | main.go |
| info | `Cache invalidation handlers disabled via --enable-controllers=false` |  | main.go |
| info | `Cleanup routine started` |  | main.go |
| info | `Configuration loaded (redacted)` | `configPath`, `enableAPI`, `enableCleanup`, `enableFrontend`, `enableWebhooks`, `frontendBaseURL`, `trustedProxies` | main.go |
| info | `Creating leader election lease` | `id`, `namespace` | main.go |
| info | `HTTP server disabled: both --enable-frontend and --enable-api are false` |  | main.go |
| info | `Leader election disabled via --enable-leader-election=false, background loops will run on all replicas` |  | main.go |
| info | `Leader election resource lock created` | `id`, `identity`†, `namespace` | main.go |
| info | `Log redaction enabled via config` |  | main.go |
| info | `Mail service shut down successfully` |  | main.go |
| info | `OpenTelemetry tracing shut down successfully` |  | main.go |
| info | `Received shutdown signal, initiating graceful shutdown` |  | main.go |
| info | `Starting breakglass controller` | `version` | main.go |
| info | `Waiting for all goroutines to finish` |  | main.go |
| info | `Webhooks disabled via --enable-webhooks flag` |  | main.go |
| info | `Webhooks enabled via --enable-webhooks flag` |  | main.go |
| info | `identity_provider_set_on_api_server` | `type` | main.go |
| info | `using specified kubeconfig context` | `context` | main.go |
| warn | `--debug is deprecated; use --log-level=debug and, for this output format, --log-format=console` |  | main.go |
| warn | `Audit service shutdown error` | `error` | main.go |
| warn | `Failed to get hostname for event source, using empty string` | `error` | main.go |
| warn | `Failed to load IdentityProvider: %v; group sync disabled` |  | main.go |
| warn | `Failed to register cluster cache invalidation handlers` | `error` | main.go |
| warn | `HTTP server graceful shutdown error` | `error` | main.go |
| warn | `Mail service initialization failed - mail notifications disabled until MailProvider is created` | `error` | main.go |
| warn | `Mail service shutdown error` | `error` | main.go |
| warn | `OpenTelemetry initialization failed, tracing disabled` | `error` | main.go |
| warn | `OpenTelemetry shutdown error` | `error` | main.go |
| warn | `Session creation rate limiter disabled via --disable-session-rate-limit flag; do not use in production` |  | main.go |
| warn | `artifact storage shutdown error` | `error` | main.go |
| error | `background component failed, shutting down: %s` |  | main.go |

#### `pkg/api`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | (dynamic) | `claims_keys`, `sub`†, `username`† | auth.go |
| debug | `escalation reconciler not available, returning empty escalation→IDP mapping` |  | api.go |
| debug | `identity_provider_exposed` | `type` | api.go |
| debug | `multi_idp_config_returned` | `escalation_count`, `idp_count` | api.go |
| debug | `oidc_proxy_request` | `path`, `target_host`, `target_path`, `target_scheme` | api.go |
| debug | `oidc_proxy_upstream_response` | `elapsed`, `status`, `target` | api.go |
| debug | `oidc_proxy_using_custom_authority` | `authority`, `path` | api.go |
| debug | `using cached escalation→IDP mapping` | `escalationCount` | api.go |
| info | `API controllers enabled` | `components` | api.go |
| info | `CORS: allowed origins configured` | `origins` | api.go |
| info | `Debug session API controller enabled` |  | api.go |
| info | `Frontend UI enabled via --enable-frontend=true` |  | api.go |
| info | `HTTP server shutdown complete` |  | api.go |
| info | `Initiating graceful HTTP server shutdown` |  | api.go |
| info | `Reloaded client CA bundle` | `file` | api.go |
| info | `Session activity tracking enabled` |  | api.go |
| info | `Starting HTTP server` | `address` | api.go |
| info | `Starting HTTPS server` | `address`, `clientAuth`, `tlsMinVersion`, `tlsReload` | api.go |
| info | `http_request` | `cid`, `latency`, `method`, `path`, `status` | api.go |
| info | `identity provider loaded` | `authority`, `name`, `type` | api.go |
| info | `identity provider reloaded successfully` | `name`, `type` | api.go |
| warn | `CORS: no allowed origins configured and defaults not enabled — browser requests with Origin header will be blocked; set server.allowedOrigins in config` |  | api.go |
| warn | `CORS: using default localhost origins because BREAKGLASS_ALLOW_DEFAULT_ORIGINS is enabled — not suitable for production; set server.allowedOrigins in config` | `BREAKGLASS_ALLOW_DEFAULT_ORIGINS`, `origins` | api.go |
| warn | `Cannot reload client CA bundle; the current one stays in use` | `error`, `file` | api.go |
| warn | `Failed to set trusted proxies` | `error` | api.go |
| warn | `HTTP server shutdown error` | `error` | api.go |
| warn | `OIDC proxy: server.allowOIDCProxyRedirects is enabled — the proxy will follow upstream 30x responses without re-checking the authority allowlist, which permits SSRF via a redirecting identity provider; unset this field to restore the secure default` |  | api.go |
| warn | `blocked_request_origin` | `cid`, `normalized_origin`, `origin` | api.go |
| warn | `failed to parse OIDC authority URL` | `authority`, `error` | api.go |
| warn | `identity_provider_not_loaded` |  | api.go |
| warn | `idp reconciler not available, returning empty config` |  | api.go |
| warn | `oidc_proxy_absolute_url_detected` | `path` | api.go |
| warn | `oidc_proxy_idp_authority_lookup_failed` | `authority`, `error` | api.go |
| warn | `oidc_proxy_idp_config_lookup_failed` | `authority`, `error` | api.go |
| warn | `oidc_proxy_insecure_http_authority` | `authority`, `idpName`, `impact`, `remediation` | api.go |
| warn | `oidc_proxy_invalid_authority_header` | `customAuthority`, `error` | api.go |
| warn | `oidc_proxy_malformed_path` | `error`, `normalized`, `path` | api.go |
| warn | `oidc_proxy_missing_authority` |  | api.go |
| warn | `oidc_proxy_path_not_whitelisted` | `normalized`, `path` | api.go |
| warn | `oidc_proxy_suspicious_pattern` | `path` | api.go |
| warn | `oidc_proxy_unknown_authority` | `customAuthority` | api.go |
| warn | `oidc_proxy_url_resolution_attack` | `originalPath` | api.go |
| warn | `refusing insecure TLS verification for identity provider` | `authority`, `idpName`, `remediation` | api.go |
| error | `Invalid server TLS configuration` | `error` | api.go |
| error | `Server certificate watcher stopped; the current certificate stays in use` | `error` | api.go |
| error | `Server listen error` | `error` | api.go |
| error | `[Recovery from panic]` | `cid`, `error`, `method`, `path` | api.go |
| error | `failed_to_reload_identity_provider` | `error` | api.go |
| error | `handler_error` | `cid`, `error`, `meta` | api.go |
| error | `oidc_proxy_authority_error` | `customAuthority`, `error` | api.go |
| error | `oidc_proxy_build_error` | `error`, `target` | api.go |
| error | `oidc_proxy_client_error` | `error` | api.go |
| error | `oidc_proxy_copy_error` | `error`, `target` | api.go |
| error | `oidc_proxy_missing_authority_base` | `path` | api.go |
| error | `oidc_proxy_response_truncated` | `limitBytes`, `remediation`, `target` | api.go |
| error | `oidc_proxy_unknown_path_error` | `error`, `path` | api.go |
| error | `oidc_proxy_upstream_error` | `elapsed`, `error`, `target` | api.go |

#### `pkg/apiresponses`

| Level | Message | Fields | File |
|---|---|---|---|
| error | (dynamic) | `error` | responses.go |

#### `pkg/audit`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `audit session identity unavailable` | `session` | resource_identity.go |
| debug | `handed-over audit event excluded by this sink's filters` | `event_id`, `event_type` | queued_sink.go |
| debug | `manager event-type pre-filter disabled because enabled AuditConfigs use different event-type filters` |  | service.go |
| debug | `sink configuration loaded` |  | service.go |
| debug | `webhook batch request failed` | `batch_size`, `error`, `url` | sink.go |
| debug | `webhook batch returned error` | `batch_size`, `status_code`, `url` | sink.go |
| debug | `webhook batch sent successfully` | `batch_size`, `total_events` | sink.go |
| debug | `webhook event sent successfully` | `event_id`, `event_type` | sink.go |
| debug | `webhook request failed` | `error`, `event_id`, `event_type`, `url` | sink.go |
| debug | `webhook returned error` | `event_id`, `event_type`, `status_code`, `url` | sink.go |
| info | `Kafka audit sink created` | `brokers`, `name`, `sasl_enabled`, `tls_enabled`, `topic` | kafka_sink.go |
| info | `Kafka sink connection restored` | `batch_size`, `duration`, `name` | kafka_sink.go |
| info | `Webhook audit sink created` | `batchURL`, `name`, `timeout`, `url` | sink.go |
| info | `attempting to close circuit breaker` | `sink` | queued_sink.go |
| info | `audit events handed over to the replacement pipeline` | `count` | queued_sink.go |
| info | `audit manager started` | `batch_enabled`, `queue_size`, `sample_rate`, `stats_interval`, `workers` | manager.go |
| info | `audit manager stopped` | `dropped`, `processed` | manager.go |
| info | `audit service closed` |  | service.go |
| info | `audit sink circuit breaker state change` | `from`, `to` | service.go |
| info | `audit system configured with aggregated sinks` | `configs`, `dropOnFull`, `queueSize`, `sampleRate`, `totalSinks`, `workers` | service.go |
| info | `audit system disabled (no enabled configs)` |  | service.go |
| info | `audit_event` |  | sink.go |
| info | `circuit breaker created` | `failure_threshold`, `open_timeout`, `sink`, `success_threshold` | circuit_breaker.go |
| info | `circuit breaker reset` |  | circuit_breaker.go |
| info | `circuit breaker state changed` | `from`, `to` | circuit_breaker.go |
| info | `closing Kafka audit sink` | `batches_sent`, `messages_failed`, `messages_written`, `name` | kafka_sink.go |
| info | `closing circuit breaker sink` | `state` | circuit_breaker.go |
| info | `closing webhook audit sink` | `batches_written`, `events_failed`, `events_written`, `name` | sink.go |
| info | `queued sink started` | `circuit_breaker_threshold`, `queue_size`, `workers`, `write_timeout` | queued_sink.go |
| info | `retained audit events delivered` | `count`, `retained_for` | queued_sink.go |
| info | `splitting audit batch after a permanent failure` | `count`, `error` | queued_sink.go |
| info | `wrapped sink with circuit breaker` | `failure_threshold`, `open_timeout`, `sink`, `type` | service.go |
| warn | `Kafka sink temporarily unavailable, event dropped` |  | kafka_sink.go |
| warn | `audit delivery retry window exhausted; retaining events until the sink recovers` | `count`, `error`, `operation` | queued_sink.go |
| warn | `audit events dropped` | `count`, `dropped_total`, `queue_length`, `reason` | queued_sink.go |
| warn | `audit manager enqueue timed out` | `error` | manager.go |
| warn | `audit reload failed; the previous audit pipeline stays active` | `configs`, `error` | service.go |
| warn | `audit service closed while previous audit sinks were still closing` |  | service.go |
| warn | `audit sink write failed` | `error`, `sink` | sink.go |
| warn | `circuit open but event is sensitive, attempting synchronous write` | `event_type`, `sink` | queued_sink.go |
| warn | `failed to close audit manager` | `error` | service.go |
| warn | `failed to close audit sink` | `error`, `sink` | service.go |
| warn | `failed to load system CA pool, using custom webhook CA pool only` | `error` | service.go |
| warn | `failed to write batch to Kafka` | `batch_size`, `duration`, `error`, `error_type` | kafka_sink.go |
| warn | `queue full but event is sensitive, attempting synchronous write` | `event_type`, `sink` | queued_sink.go |
| warn | `unknown compression codec, defaulting to snappy` | `codec` | kafka_sink.go |
| error | `Kafka TLS error` |  | kafka_sink.go |
| error | `Kafka authentication/authorization failed` |  | kafka_sink.go |
| error | `asynchronous Kafka delivery failed` | `count`, `error` | kafka_sink.go |
| error | `audit delivery retries exhausted` | `count`, `error`, `operation` | queued_sink.go |
| error | `audit event cannot be delivered` | `error`, `event_id`, `event_type`, `operation` | queued_sink.go |
| error | `audit sink write panicked` | `panic`, `stack` | queued_sink.go |
| error | `direct sink write failed for sensitive event` | `error`, `event_id`, `sink` | manager.go |
| error | `enabled AuditConfig produced no audit sinks` |  | service.go |
| error | `failed to build Kafka SASL mechanism` | `error`, `mechanism` | kafka_sink.go |
| error | `failed to build Kafka TLS config` | `brokers`, `error` | kafka_sink.go |
| error | `failed to build audit sinks from config` | `config`, `error` | service.go |
| error | `failed to write audit batch` | `batch_size`, `error`, `worker` | manager.go |
| error | `failed to write audit event` | `error`, `event_id`, `event_type`, `worker` | manager.go |
| error | `failed to write audit event to Kafka` |  | kafka_sink.go |
| error | `kafka writer panicked` | `panic`, `stack` | kafka_sink.go |
| error | `panic in audit batch queue worker recovered` | `panic`, `stack`, `worker` | queued_sink.go |
| error | `panic in audit queue worker recovered` | `panic`, `stack`, `worker` | queued_sink.go |

#### `pkg/breakglass`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `About to filter approvers` | `escalationName`, `preFilterApproverCount`† | session_request_helpers.go |
| debug | `About to send breakglass request email` | `approvalsRequired`, `cluster`, `group`†, `requestorEmail`†, `requestorUsername`† | session_request_helpers.go |
| debug | `Added explicit approver user` | `escalation`, `totalApproversNow`†, `user`† | session_request_helpers.go |
| debug | `Added group members to approvers` | `escalation`, `group`†, `newMembersAdded`, `totalApproversNow`† | session_request_helpers.go |
| debug | `After filterExcludedNotificationRecipients` | `excludedCount`, `postExcludeApproverCount`† | session_request_helpers.go |
| debug | `After filterHiddenFromUIRecipients` | `hiddenFilteredOutCount`, `postHiddenFilterApproverCount`† | session_request_helpers.go |
| debug | `Approver email unavailable; using authenticated username` | `error`, `username`† | session_controller_approval_utils.go |
| debug | `Approver evaluation context` | `approverEmail`†, `candidateEscalationCount`, `session`, `sessionGroup`† | session_controller_approval_utils.go |
| debug | `Approver identity verified` | `cluster`, `email`†, `username`† | session_controller_approval_utils.go |
| debug | `Attempting to resolve excluded group members` | `group`† | session_controller_actions.go |
| debug | `Attempting to resolve hidden item as group` | `itemHint` | session_controller_actions.go |
| debug | `BreakglassSession not found by name across namespaces` | `name` | session_manager.go |
| debug | `Built excluded users set` | `directExcludedUserCount`† | session_controller_actions.go |
| debug | `Built hidden users set` | `directHiddenUserCount`† | session_controller_actions.go |
| debug | `Cannot resolve additional excluded group members` | `escalationManagerNil`, `groupCount`†, `knownGroupMemberCount`†, `resolverNil` | session_controller_actions.go |
| debug | `Checking debug session for expiration` |  | cleanup_task.go |
| debug | `Checking if groups can perform SAR operation` | `cluster`, `groupCount`† | group_checker.go |
| debug | `Checking session for expiration` |  | cleanup_task.go |
| debug | `Checking session retainedUntil` | `retainedUntil` | cleanup_task.go |
| debug | `Cluster config not available for IDP check (will default to false for restriction)` | `cluster` | session_request_helpers.go |
| debug | `Cluster escalations (for visibility)` | `cluster`, `escalations` | session_request_helpers.go |
| debug | `Continuing without global config` | `error` | session_controller.go |
| debug | `Could not fetch cluster config for user identifier claim` | `cluster`, `error` | session_request_helpers.go |
| debug | `Custom duration applied` | `customMaxValidFor`, `defaultMaxValidFor`, `duration` | session_request_helpers.go |
| debug | `Decoded breakglass session request` | `cluster`, `hasReason`, `hasScheduledStartTime`, `requestedDurationSeconds`, `requestedGroup`†, `requestedUsername`† | session_controller.go |
| debug | `Deleted expired breakglass session` |  | cleanup_task.go |
| debug | `Deleted orphaned breakglass session` |  | cleanup_task.go |
| debug | `Direct GET failed; falling back to list across namespaces` | `error`, `name` | session_manager.go |
| debug | `Email claim unavailable; continuing with authenticated username` | `error`, `username`† | session_controller.go |
| debug | `Email sending disabled via --disable-email flag` |  | session_request_helpers.go |
| debug | `Email template rendered successfully` | `bodyLength`, `group`†, `recipientCount`†, `session` | session_controller_actions.go |
| debug | `Escalation found but user not in approvers (continuing)` | `approverGroupCount`†, `approverUserCount`†, `escalation`, `session`, `user`†, `userGroupCount`† | session_controller_approval_utils.go |
| debug | `Escalation found but user not in deduplicated approvers (continuing)` | `dedupMemberCount`, `escalation`, `session`, `user`† | session_controller_approval_utils.go |
| debug | `Evaluating matching escalation` | `escalation`, `groups`†, `users`† | session_controller_approval_utils.go |
| debug | `Extracted raw token groups from JWT claims` | `rawTokenGroupCount`†, `rawTokenGroups`† | session_request_helpers.go |
| debug | `Failed to resolve members of hidden group` | `error`, `errorType`, `itemHint` | session_controller_actions.go |
| debug | `Fetching BreakglassSession by name (direct GET)` |  | session_manager.go |
| debug | `Fetching BreakglassSessions by states (using field index)` | `states` | session_manager.go |
| debug | `Fetching BreakglassSessions for cluster and user (using field index)` | `cluster`, `user`† | session_manager.go |
| debug | `Fetching BreakglassSessions for user (using field index)` | `user`† | session_manager.go |
| debug | `Fetching BreakglassSessions with selector` | `selector` | session_manager.go |
| debug | `Fetching BreakglassSessions with selector string` | `selector` | session_manager.go |
| debug | `Fetching all BreakglassSessions` |  | session_manager.go |
| debug | `Field index lookup failed; falling back to selector` | `error`, `name` | session_manager.go |
| debug | `Field index lookup returned no sessions; falling back to selector` | `name` | session_manager.go |
| debug | `Field index not available; falling back to client-side filtering` | `cluster`, `error`, `states`, `user`† | session_manager.go |
| debug | `Found session slot candidate` | `session`, `state` | session_controller_status.go |
| debug | `Getting user groups for cluster user group` | `cluster`, `username`† | group_checker.go |
| debug | `Getting user groups for cluster user group with custom config` | `cluster`, `configPath`, `username`† | group_checker.go |
| debug | `Handling GET /status for breakglass session` |  | session_controller_status.go |
| debug | `Ignoring approver group cache entry with unexpected type` | `cacheKey`, `cachedType` | session_controller_approval_utils.go |
| debug | `Impersonated SelfSubjectAccessReview result` | `allowed`, `impersonationConstraint`, `mode` | group_checker_impersonation.go |
| debug | `Keycloak provider retrieved email` | `email`† | identity_provider.go |
| debug | `Keycloak provider retrieved user identifier` | `claimType`, `identifier` | identity_provider.go |
| debug | `Keycloak provider retrieved user_id` | `user_id`† | identity_provider.go |
| debug | `Keycloak provider retrieved username` | `username`† | identity_provider.go |
| debug | `Loaded rest.Config for cluster context` | `cluster`, `context` | group_checker.go |
| debug | `Loaded rest.Config via kind- fallback` | `cluster`, `context` | group_checker.go |
| debug | `Matched IDP group override` | `idp`, `matchedGroupHint`†, `patternHint`, `unlimited` | session_controller_status.go |
| debug | `Matched escalation found during session creation` | `escalationName`, `escalationNamespace`, `escalationUID` | session_request_helpers.go |
| debug | `Matched escalation selected for approver resolution` | `denyPolicyCount`, `escalatedGroup`†, `escalationName` | session_request_helpers.go |
| debug | `No ClusterConfig found for approval policy, continuing with defaults` | `cluster`, `error` | session_controller_approval_utils.go |
| debug | `No IDP name set, skipping IDP-level session limits` |  | session_controller_status.go |
| debug | `No OIDC prefixes configured, returning groups unchanged` |  | group_checker.go |
| debug | `No OIDC prefixes configured, using original groups` |  | group_checker.go |
| debug | `No approver groups found to sync` | `cluster`, `escalationCount` | session_request_helpers.go |
| debug | `No escalation with matching granted group for approval` | `approverEmail`†, `approverGroupCount`†, `session` | session_controller_approval_utils.go |
| debug | `No hidden approvers configured, returning all approvers` | `escalationNil`, `hiddenCount` | session_controller_actions.go |
| debug | `No matching escalation found during session creation; no ownerRef will be attached` | `cluster`, `requestedGroup`† | session_request_helpers.go |
| debug | `No notification exclusions configured` | `escalationNil` | session_controller_actions.go |
| debug | `No session limit applicable` | `escalation`, `idp` | session_controller_status.go |
| debug | `No session limits configured on IDP` | `idp` | session_controller_status.go |
| debug | `OIDC prefix stripping complete` | `originalGroupCount`†, `strippedGroupCount`† | group_checker.go |
| debug | `OwnerReference prepared for session create` | `ownerRefs` | session_request_helpers.go |
| debug | `Parsing user info from v1.SelfSubjectReview` |  | group_checker.go |
| debug | `Parsing user info from v1beta1.SelfSubjectReview` |  | group_checker.go |
| debug | `Possible escalations found` | `cluster`, `count`, `user`† | session_request_helpers.go |
| debug | `Processing escalation for approver resolution` | `approverGroupCount`†, `escalatedGroup`†, `escalationName`, `explicitUserCount`† | session_request_helpers.go |
| debug | `Querying for active breakglass session` | `cluster`, `group`†, `user`† | session_controller_status.go |
| debug | `Rendering breakglass session request email` | `approvers`†, `group`†, `recipientCount`†, `requestEmail`†, `requestUsername`†, `session`, `subjectLength`† | session_controller_actions.go |
| debug | `Resolved approver group members` | `escalation`, `group`†, `memberCount` | session_request_helpers.go |
| debug | `Resolved group members for sync` | `count`, `group`† | session_request_helpers.go |
| debug | `Resolved user groups via spoke cluster rest.Config` | `cluster`, `groupCount`†, `user`† | session_controller_approval_utils.go |
| debug | `Resolved user identifier for session` | `requestUsername`†, `userIdentifier`†, `userIdentifierClaim`† | session_request_helpers.go |
| debug | `Resolving approver group members` | `escalation`, `group`† | session_request_helpers.go |
| debug | `Scheduled start time set` | `nowUTC`, `scheduledStartTimeISO`, `scheduledTimeLocal`, `scheduledTimeUTC`, `secondsInFuture` | session_request_helpers.go |
| debug | `Self-approval blocked by escalation/cluster setting` | `approver`†, `escalation` | session_controller_approval_utils.go |
| debug | `Sending email for approver` | `groupCount`†, `recipientCount`†, `session` | session_controller_actions.go |
| debug | `Sending email for explicit users` | `recipientCount`†, `session` | session_controller_actions.go |
| debug | `Sending emails per approver group` | `groupCount`†, `session`, `totalApprovers`† | session_controller_actions.go |
| debug | `Session count for user` | `activeCount`, `limit`, `source`, `user`† | session_controller_status.go |
| debug | `Session created` | `cluster`, `generatedName`, `group`†, `user`† | session_controller.go |
| debug | `Session creation initiated by user` | `requestedCluster`, `requestedGroup`†, `requestorEmail`†, `requestorUsername`† | session_controller.go |
| debug | `Session limits disabled via escalation override (unlimited)` | `escalation` | session_controller_status.go |
| debug | `Set AllowIDPMismatch flag for session` | `allowIDPMismatch`, `clusterHasIDPRestriction`, `escalationHasIDPRestriction` | session_request_helpers.go |
| debug | `Skipping debug session expired email: no recipients` |  | cleanup_task.go |
| debug | `Skipping deletion of session without OwnerReferences (non-terminal state or has RetainedUntil)` |  | cleanup_task.go |
| debug | `Skipping escalation that does not own the session` | `escalation`, `session` | session_controller_approval_utils.go |
| debug | `Skipping idle check: no activity recorded yet` | `idleTimeout`, `session` | expire_idle_sessions.go |
| debug | `Skipping session already marked for deletion` |  | cleanup_task.go |
| debug | `Skipping terminal debug session (within retention period)` |  | cleanup_task.go |
| debug | `Skipping unready escalation during approver resolution` | `escalationName` | session_request_helpers.go |
| debug | `Starting approver resolution from escalations` | `escalationCount`, `requestedGroup`† | session_request_helpers.go |
| debug | `Starting expired debug session cleanup` |  | cleanup_task.go |
| debug | `Starting expired session cleanup` |  | cleanup_task.go |
| debug | `Stripped OIDC prefix from group` | `prefix` | group_checker.go |
| debug | `Stripping OIDC prefixes from groups` | `originalGroupCount`†, `prefixCount` | group_checker.go |
| debug | `Syncing approver groups` | `cluster`, `groupCount`† | session_request_helpers.go |
| debug | `Token validation: session not found` | `tokenLen` | session_controller_status.go |
| debug | `Total session count for escalation` | `activeCount`, `escalation`, `escalationUID`, `limit`, `source` | session_controller_status.go |
| debug | `User is authorized to approve/reject session` | `isRequester`†, `session`, `user`† | session_controller_status.go |
| debug | `User is not authorized to approve session` | `message`, `reason`, `session`, `user`† | session_controller_status.go |
| debug | `User is session approver (direct user)` | `escalation`, `session`, `user`† | session_controller_approval_utils.go |
| debug | `User is session approver (request identity group fallback)` | `escalation`, `group`†, `session` | session_controller_approval_utils.go |
| debug | `User is session approver (resolved group member)` | `escalation`, `member`, `session` | session_controller_approval_utils.go |
| debug | `User is session approver (target cluster group)` | `escalation`, `group`†, `session` | session_controller_approval_utils.go |
| debug | `Using already-fetched cluster config for IDP restriction check` | `cluster`, `clusterHasIDPRestriction`, `escalationHasIDPRestriction` | session_request_helpers.go |
| debug | `Using approval timeout from escalation spec` | `approvalTimeout` | session_request_helpers.go |
| debug | `Using cluster-specific userIdentifierClaim` | `cluster`, `userIdentifierClaim`† | session_request_helpers.go |
| debug | `Using escalation-level per-user session limit override` | `escalation`, `maxPerUser`† | session_controller_status.go |
| debug | `Using escalation-level total session limit override` | `escalation`, `maxTotal` | session_controller_status.go |
| debug | `Using field selector for sessions query` | `selector` | session_controller_status.go |
| debug | `Using provided approver groups for email` | `approverGroupCount`†, `session` | session_controller_actions.go |
| debug | `Using resolved approver group members from escalation status` | `escalation`, `group`†, `memberCount` | session_controller_approval_utils.go |
| debug | `Using state index for sessions query` | `states` | session_controller_status.go |
| debug | `filterExcludedNotificationRecipients called` | `approverCount`†, `escalationNil`, `hasNotificationExclusions` | session_controller_actions.go |
| debug | `filterHiddenFromUIRecipients called` | `approverCount`†, `escalationNil`, `hiddenFromUICount` | session_controller_actions.go |
| debug | `skipping approval-timeout debug session status update after concurrent change` |  | cleanup_task.go |
| debug | `skipping expired debug session status update after concurrent change` |  | cleanup_task.go |
| info | `Activating scheduled session` | `namespace`, `now`, `scheduledStartTime`, `session` | scheduled_activation.go |
| info | `Adding new BreakglassSession` |  | session_manager.go |
| info | `Applied OIDC prefix stripping` | `finalGroupCount`†, `oidcPrefixCount`, `originalGroupCount`† | group_checker.go |
| info | `Breakglass session request email queued` | `group`†, `recipientCount`†, `session` | session_controller_actions.go |
| info | `Breakglass session request email sent` | `group`†, `recipientCount`†, `session` | session_controller_actions.go |
| info | `BreakglassSession created successfully` |  | session_manager.go |
| info | `BreakglassSession deleted successfully` |  | session_manager.go |
| info | `BreakglassSession status updated successfully` |  | session_manager.go |
| info | `BreakglassSession updated successfully` |  | session_manager.go |
| info | `Cert-controller's manager stopping before acquiring leadership (context cancelled)` |  | cleanup_task.go |
| info | `Cleanup routine waiting for leadership signal before starting...` |  | cleanup_task.go |
| info | `Completed approver resolution from escalations` | `approverGroupsCount`†, `requestedGroup`†, `totalApproversCollected`† | session_request_helpers.go |
| info | `Concurrent session creation already in-flight, returning conflict` | `cluster`, `group`†, `user`† | session_controller.go |
| info | `Constrained impersonation confirmed on spoke` | `cluster`, `serverVersion` | group_checker_capability.go |
| info | `Constrained impersonation is not usable on this spoke; using legacy impersonation. Expected when the ConstrainedImpersonation feature gate is disabled, or before config/rbac/impersonate_constrained_role.yaml has been applied to the spoke.` | `cluster`, `error`, `serverVersion` | group_checker_capability.go |
| info | `Constrained impersonation refused by spoke; falling back to legacy impersonation for the RBAC probe. This is expected on Kubernetes below 1.35, with the ConstrainedImpersonation gate disabled, or before the constrained RBAC is applied.` | `cluster`, `error`, `mode` | group_checker_impersonation.go |
| info | `Context cancelled during idle session expiry` | `error` | expire_idle_sessions.go |
| info | `Debug session approval timed out, marking as Failed` |  | cleanup_task.go |
| info | `Debug session cleanup completed` | `expired`, `timedOut` | cleanup_task.go |
| info | `Debug session cleanup interrupted by context cancellation` | `deleted`, `expired` | cleanup_task.go |
| info | `Debug session expired, marking as Expired` |  | cleanup_task.go |
| info | `Deleting debug session past retention period` |  | cleanup_task.go |
| info | `Deleting session without OwnerReferences (orphaned/legacy - no RetainedUntil)` |  | cleanup_task.go |
| info | `Duplicate cleanup interrupted by context cancellation` | `cluster`, `group`†, `user`† | cleanup_duplicate_sessions.go |
| info | `Email sending disabled for this escalation via DisableNotifications` | `cluster`, `escalationName`, `group`† | session_request_helpers.go |
| info | `Excluded group resolution summary` | `requestResolvedGroupMemberCount`†, `resolvedGroupCount`†, `totalGroupMemberCount`†, `uniqueExcludedGroupMemberCount`† | session_controller_actions.go |
| info | `Existing session found` | `cluster`, `group`†, `session`, `state`, `user`† | session_request_helpers.go |
| info | `Expired breakglass sessions deletion completed` | `deleted` | cleanup_task.go |
| info | `Expiring approved session due to reached ExpiresAt` | `expiresAt`, `now`, `session` | expire_approved_sessions.go |
| info | `Expiring pending session due to approval timeout` | `session` | expire_pending_sessions.go |
| info | `Expiring scheduled session whose validity ended before activation` | `expiresAt`, `namespace`, `now`, `scheduledStartTime`, `session` | scheduled_activation.go |
| info | `Expiring session due to idle timeout` | `idleSince`, `idleTimeout`, `lastActivity`, `session` | expire_idle_sessions.go |
| info | `Fetched BreakglassSession by name (direct GET)` |  | session_manager.go |
| info | `Fetched BreakglassSession by name (fallback list)` |  | session_manager.go |
| info | `Fetched BreakglassSession by name (field index)` |  | session_manager.go |
| info | `Fetched BreakglassSessions` | `count` | session_manager.go |
| info | `Fetched BreakglassSessions (indexed)` | `cluster`, `count`, `user`† | session_manager.go |
| info | `Fetched BreakglassSessions by states (indexed)` | `count`, `states` | session_manager.go |
| info | `Fetched BreakglassSessions for user (indexed)` | `count`, `user`† | session_manager.go |
| info | `Fetched BreakglassSessions from live reader after cache lookup found no eligible session` | `cluster`, `count`, `user`† | session_manager.go |
| info | `Fetched BreakglassSessions from live reader after cluster cache lookup` | `cluster`, `count` | session_manager.go |
| info | `Fetched BreakglassSessions with selector` | `count`, `selector` | session_manager.go |
| info | `Fetched BreakglassSessions with selector string` | `count`, `selector` | session_manager.go |
| info | `Filtering results` | `excludedApproverCount`†, `hiddenApproverCount`†, `originalApproverCount`†, `totalDirectExcluded`, `totalDirectHidden`, `totalGroupMembersExcluded`†, `totalGroupMembersHidden`†, `visibleApproverCount`† | session_controller_actions.go |
| info | `Finished breakglass session cleanup task` |  | cleanup_task.go |
| info | `GetUserGroups complete` | `cluster`, `groupCount`†, `username`† | group_checker.go |
| info | `GetUserGroupsWithConfig complete` | `cluster`, `groupCount`†, `username`† | group_checker.go |
| info | `Handling GET /breakglassSessions/:name` | `session` | session_controller_status.go |
| info | `Handling duplicate session` | `created`, `namespace`, `session`, `state` | cleanup_duplicate_sessions.go |
| info | `Hidden approvers configured` | `hiddenItemCount` | session_controller_actions.go |
| info | `Hidden group resolution summary` | `requestResolvedGroupMemberCount`†, `resolvedGroupCount`†, `totalGroupMemberCount`†, `uniqueHiddenGroupMemberCount`† | session_controller_actions.go |
| info | `Leadership acquired - starting cleanup routine` |  | cleanup_task.go |
| info | `Maximum total approvers limit reached, stopping escalation processing` | `limit`, `matchedEscalation` | session_request_helpers.go |
| info | `No active breakglass session found` | `cluster`, `group`†, `user`† | session_controller_status.go |
| info | `No approvers remain eligible for session request notifications after configured exclusions and hidden approvers` | `escalationName`, `originalApproverCount`† | session_request_helpers.go |
| info | `Notification exclusions configured` | `excludedGroupCount`†, `excludedUserCount`† | session_controller_actions.go |
| info | `Processing breakglass session request` |  | session_controller.go |
| info | `Resolved approvers from escalation (explicit users + group members)` | `approverCount`†, `cluster`, `group`† | session_request_helpers.go |
| info | `Returning active breakglass session` | `session` | session_controller_status.go |
| info | `Returning filtered breakglass sessions` | `count` | session_controller_status.go |
| info | `Running breakglass session cleanup task` |  | cleanup_task.go |
| info | `Session already transitioned after refetch; skipping idle expiry` | `currentState`, `session` | expire_idle_sessions.go |
| info | `Session approved and activated immediately` | `expiresAt`, `session` | session_controller_status.go |
| info | `Session approved with scheduled start time` | `expiresAt`, `scheduledStartTime`, `session` | session_controller_status.go |
| info | `Session cleanup interrupted by context cancellation` | `processed` | cleanup_task.go |
| info | `Session no longer approved or expired after refetch; skipping time expiry` | `currentState`, `session` | expire_approved_sessions.go |
| info | `Session no longer has activity after refetch; skipping idle expiry` | `session` | expire_idle_sessions.go |
| info | `Session no longer has idle timeout after refetch; skipping idle expiry` | `session` | expire_idle_sessions.go |
| info | `Session no longer idle after refetch; skipping expiry` | `idleTimeout`, `refreshedIdleSince`, `session` | expire_idle_sessions.go |
| info | `Session no longer pending or timed out after refetch; skipping approval timeout` | `currentState`, `session` | expire_pending_sessions.go |
| info | `Session retrieved with approval metadata` | `canApprove`, `denialReason`, `isApprover`†, `isRequester`†, `session`, `state` | session_controller_status.go |
| info | `Session ticket reference recorded` | `session`, `ticketSystemID` | session_controller.go |
| info | `SessionManager initialized` | `context` | session_manager.go |
| info | `Skipping duplicate session because fewer than two active sessions remain` | `namespace`, `session` | cleanup_duplicate_sessions.go |
| info | `Skipping duplicate session that changed after survivor selection` | `namespace`, `session`, `state` | cleanup_duplicate_sessions.go |
| info | `Skipping duplicate session that is no longer in the active duplicate set` | `namespace`, `session` | cleanup_duplicate_sessions.go |
| info | `Skipping duplicate session that is now the preferred survivor` | `namespace`, `session`, `state` | cleanup_duplicate_sessions.go |
| info | `Spoke cannot support constrained impersonation; using legacy impersonation. This is expected below Kubernetes 1.35 and whenever the spoke's version cannot be read.` | `cluster`, `serverVersion` | group_checker_capability.go |
| info | `Successfully activated scheduled session` | `actualStartTime`, `namespace`, `session` | scheduled_activation.go |
| info | `Successfully resolved excluded group members` | `group`†, `memberCount` | session_controller_actions.go |
| info | `Successfully resolved hidden group members` | `group`†, `memberCount` | session_controller_actions.go |
| info | `Total approvers limit reached and matched escalation found, stopping` | `limit`, `matchedEscalation` | session_request_helpers.go |
| info | `Updating BreakglassSession` |  | session_manager.go |
| info | `Updating BreakglassSession status` |  | session_manager.go |
| info | `Validated session request parameters` |  | session_controller.go |
| info | `approval email enqueued for sending` | `session`, `to` | session_controller_approval_utils.go |
| info | `rejection email enqueued for sending` | `session`, `to` | session_controller_approval_utils.go |
| info | `skipping approved session expiry because context is cancelled` | `error` | expire_approved_sessions.go |
| info | `skipping pending session expiry because context is cancelled` | `error` | expire_pending_sessions.go |
| info | `skipping scheduled session activation because context is cancelled` | `error` | scheduled_activation.go |
| info | `skipping scheduled session activation because state changed before update` | `error`, `namespace`, `session` | scheduled_activation.go |
| info | `skipping scheduled session activation email because context is cancelled` | `error`, `namespace`, `session` | scheduled_activation.go |
| info | `skipping scheduled session expiry because state changed before update` | `error`, `namespace`, `reason`, `session` | scheduled_activation.go |
| info | `skipping scheduled session … because live session was deleted` | `namespace`, `session` | scheduled_activation.go |
| info | `skipping scheduled session … because state changed` | `namespace`, `session`, `state` | scheduled_activation.go |
| info | `stopping approved session expiry because context is cancelled` | `error` | expire_approved_sessions.go |
| info | `stopping pending session expiry because context is cancelled` | `error` | expire_pending_sessions.go |
| info | `stopping scheduled session activation because context is cancelled` | `error` | scheduled_activation.go |
| warn | `Approval authorized on UNVERIFIED groups: cluster group lookup failed and the JWT-claim group fallback was load-bearing for this decision` | `approver`†, `cluster`, `identityProvider`†, `matchedGroup`†, `remediation`, `session` | session_controller_approval_utils.go |
| warn | `Approver authenticated with disallowed identity provider` | `allowedIdentityProviderCount`†, `approver`†, `escalation`, `identityProvider`† | session_controller_approval_utils.go |
| warn | `Approver email does not match allowed domains for escalation` | `allowedDomains`, `approver`†, `escalation` | session_controller_approval_utils.go |
| warn | `Approver group has too many members, truncating` | `escalation`, `group`†, `limit`, `originalCount` | session_request_helpers.go |
| warn | `Breakglass session approver reason is invalid` | `action`, `error`, `session` | session_controller_status.go |
| warn | `Cannot resolve additional hidden group members - resolver not available` | `escalationManagerNil`, `knownGroupMemberCount`†, `resolverNil` | session_controller_actions.go |
| warn | `Cannot send emails by group: matched escalation is nil` | `session` | session_controller_actions.go |
| warn | `Could not determine constrained-impersonation capability for spoke; leaving it undetermined and retrying on the next request` | `cluster`, `error`, `serverVersion` | group_checker_capability.go |
| warn | `Duplicate active sessions detected — terminating duplicates` | `cluster`, `duplicateCount`, `group`†, `keepSession`, `user`† | cleanup_duplicate_sessions.go |
| warn | `Duplicate cleanup audit delivered but acknowledgement failed; retaining retryable outbox state` | `error`, `namespace`, `session` | cleanup_duplicate_sessions.go |
| warn | `Duration validation failed` | `error`, `maxAllowed`, `requestedDuration` | session_request_helpers.go |
| warn | `Failed to drain duplicate cleanup audit` | `error`, `namespace`, `session` | cleanup_duplicate_sessions.go |
| warn | `Failed to enqueue session request email (will not retry)` | `error`, `recipientCount`†, `session`, `subjectLength`† | session_controller_actions.go |
| warn | `Failed to enqueue session request email via mail service` | `error`, `recipientCount`†, `session`, `subjectLength`† | session_controller_actions.go |
| warn | `Failed to get authenticated identity for approval meta` | `error` | session_controller_status.go |
| warn | `Failed to list approved sessions for activity tracker pruning` | `error` | cleanup_task.go |
| warn | `Failed to list escalations for group sync` | `error` | session_request_helpers.go |
| warn | `Failed to list sessions for duplicate cleanup` | `error`, `state` | cleanup_duplicate_sessions.go |
| warn | `Failed to list terminal sessions for duplicate cleanup audit drain` | `error`, `state` | cleanup_duplicate_sessions.go |
| warn | `Failed to load rest.Config for cluster` | `cluster`, `error` | group_checker.go |
| warn | `Failed to parse MaxValidFor duration` | `error`, `value` | session_request_helpers.go |
| warn | `Failed to parse scheduledStartTime` | `error`, `value` | session_request_helpers.go |
| warn | `Failed to refresh BreakglassSessions from live reader after cache lookup found no eligible session` | `cluster`, `error`, `user`† | session_manager.go |
| warn | `Failed to refresh BreakglassSessions from live reader after cluster cache lookup found no eligible session` | `cluster`, `error` | session_manager.go |
| warn | `Failed to resolve ClusterConfig while enforcing session readiness; blocking request` | `cluster`, `error` | session_request_helpers.go |
| warn | `Failed to resolve approver group members` | `error`, `group`† | session_request_helpers.go |
| warn | `Failed to resolve members of excluded group` | `error`, `errorType`, `group`† | session_controller_actions.go |
| warn | `Failed to revalidate duplicate session set` | `cluster`, `error`, `group`†, `user`† | cleanup_duplicate_sessions.go |
| warn | `Failed to send email for approver` | `error`, `groupCount`†, `recipientCount`†, `session` | session_controller_actions.go |
| warn | `Failed to send email for explicit users` | `error`, `recipientCount`†, `session` | session_controller_actions.go |
| warn | `Failed to update duplicate session status` | `error`, `session` | cleanup_duplicate_sessions.go |
| warn | `Falling back to authentication.k8s.io/v1beta1 SelfSubjectReview (cluster predates K8s 1.28)` |  | group_checker.go |
| warn | `Group member resolution failed during sync` | `error`, `group`† | session_request_helpers.go |
| warn | `IdentityProvider not found — session limits cannot be enforced; failing closed` | `idp` | session_controller_status.go |
| warn | `Invalid glob pattern in IDP group override, skipping` | `error`, `idp`, `patternHint` | session_controller_status.go |
| warn | `Invalid session request parameters` | `cluster`, `error`, `requestedGroup`†, `requestedUsername`† | session_controller.go |
| warn | `Keycloak provider failed to retrieve email identity from context` |  | identity_provider.go |
| warn | `Missing required request reason` | `group`† | session_controller.go |
| warn | `No approvers resolved for email notification; cannot send email with empty recipients` | `cluster`, `group`†, `requestorEmail`†, `requestorUsername`† | session_request_helpers.go |
| warn | `No authenticated identity claims found for session ownership filtering` | `error` | session_controller_status.go |
| warn | `No escalation groups found for user` | `cluster`, `requestedGroup`†, `resolvedUserGroups`†, `user`† | session_request_helpers.go |
| warn | `No mail provider configured - email notification skipped` | `recipientCount`†, `session`, `subject`† | session_controller_actions.go |
| warn | `No remaining capacity for approvers, skipping group` | `escalation`, `group`†, `totalApproversLimit`† | session_request_helpers.go |
| warn | `Reason field sanitization failed` | `error` | session_controller.go |
| warn | `Refusing to create session without matched escalation` | `cluster`, `group`†, `user`† | session_request_helpers.go |
| warn | `Request username does not match authenticated identity` | `authIdentifiers`, `requestUsername`† | session_request_helpers.go |
| warn | `Requested ClusterConfig is not ready` | `cluster` | session_request_helpers.go |
| warn | `Requested cluster has no ClusterConfig` | `cluster` | session_request_helpers.go |
| warn | `Requested escalation exists but is not ready` | `cluster`, `group`† | session_request_helpers.go |
| warn | `Retaining terminal session while duplicate cleanup audit is pending` |  | cleanup_task.go |
| warn | `Retaining terminal session while expiry notification enqueue is pending` |  | cleanup_task.go |
| warn | `Session admission recovery deferred` | `error`, `session` | session_admission.go |
| warn | `Session admission recovery failed` | `error` | cleanup_task.go |
| warn | `Session admission status recovery deferred` | `error`, `session` | session_admission.go |
| warn | `Session limit check failed` | `error`, `escalation`, `user`† | session_request_helpers.go |
| warn | `Session not found` | `error`, `session` | session_controller_status.go |
| warn | `SessionManager using global logger — use WithSessionLogger() in production` |  | session_manager.go |
| warn | `Skipping debug session audit event: template audit policy unavailable` | `error`, `session`, `template` | debug_session_audit_policy.go |
| warn | `Suppressing session request notifications because excluded-group membership could not be resolved` | `escalationName`, `originalApproverCount`† | session_request_helpers.go |
| warn | `Suppressing session request notifications because hidden-group membership could not be resolved` | `escalationName`, `originalApproverCount`† | session_request_helpers.go |
| warn | `Ticket system ID validation failed` | `error` | session_controller.go |
| warn | `Token validation: unable to verify session read authorization` | `error`, `tokenLen` | session_controller_status.go |
| warn | `Token validation: user is not authorized to read session` | `tokenLen` | session_controller_status.go |
| warn | `Total approvers limit reached while adding explicit users` | `escalation`, `limit` | session_request_helpers.go |
| warn | `Total approvers limit reached, skipping remaining groups` | `escalation`, `group`†, `limit` | session_request_helpers.go |
| warn | `Truncating members to fit within total approvers limit` | `escalation`, `group`†, `originalCount`, `totalApproversLimit`†, `truncatedTo` | session_request_helpers.go |
| warn | `Unable to look up ClusterConfig for approval policy` | `cluster`, `error` | session_controller_approval_utils.go |
| warn | `Unable to resolve unique ClusterConfig for approval policy` | `cluster`, `error` | session_controller_approval_utils.go |
| warn | `Unable to verify session read authorization` | `error`, `session` | session_controller_status.go |
| warn | `User is not authorized to read session` | `session` | session_controller_status.go |
| warn | `User not authorized for group` | `group`†, `user`† | session_controller.go |
| warn | `cleanup routine stopped (context cancelled)` |  | cleanup_task.go |
| warn | `constrainedImpersonation.probeMode must be user-info or legacy: the RBAC probe impersonates groups, and user-info is the only mode that can carry them. Using user-info.` | `configured` | group_checker_impersonation.go |
| warn | `could not refetch session before idle status update; skipping idle expiry` | `error`, `namespace`, `session` | expire_idle_sessions.go |
| warn | `failed to update idle-expired session status (will retry)` | `attempt`, `error`, `session` | expire_idle_sessions.go |
| warn | `invalid idleTimeout on refetched session, skipping idle expiry` | `error`, `idleTimeout`, `session` | expire_idle_sessions.go |
| warn | `invalid idleTimeout on session, skipping` | `error`, `idleTimeout`, `session` | expire_idle_sessions.go |
| warn | `mail not available, cannot send approval email` | `session` | session_controller_approval_utils.go |
| warn | `mail not available, cannot send rejection email` | `session` | session_controller_approval_utils.go |
| warn | `requester email unavailable, cannot send activation email` | `session` | scheduled_activation.go |
| warn | `requester email unavailable, cannot send approval email` | `session` | session_controller_approval_utils.go |
| warn | `requester email unavailable, cannot send idle-expired email` | `session` | expire_idle_sessions.go |
| warn | `requester email unavailable, cannot send rejection email` | `session` | session_controller_approval_utils.go |
| warn | `scheduledStartTime is in the past` | `nowLocal`, `nowUTC`, `parsedLocal`, `parsedUTC`, `requestedTime`, `timeDiffSeconds` | session_request_helpers.go |
| error | `Ambiguous BreakglassSession name across namespaces` | `name`, `namespaces` | session_manager.go |
| error | `Ambiguous BreakglassSession name across namespaces (field index)` | `name`, `namespaces` | session_manager.go |
| error | `Cannot send breakglass request email: approvers list is empty` | `cluster`, `group`†, `requestEmail`†, `requestUsername`†, `session` | session_controller_actions.go |
| error | `Error getting breakglass escalations` | `error` | session_request_helpers.go |
| error | `Error getting breakglass sessions` | `error` | session_controller_status.go, session_request_helpers.go |
| error | `Error getting user identifier from token` | `error`, `userIdentifierClaim`† | session_request_helpers.go |
| error | `Error listing cluster escalations for approval` | `error` | session_controller_approval_utils.go |
| error | `Failed to create field selector` | `error`, `selector` | session_manager.go |
| error | `Failed to create new BreakglassSession` |  | session_manager.go |
| error | `Failed to create new client` | `error` | session_manager.go |
| error | `Failed to decode JSON request body` | `error` | session_controller.go |
| error | `Failed to delete BreakglassSession` |  | session_manager.go |
| error | `Failed to get BreakglassSessionList` | `error` | session_manager.go |
| error | `Failed to get config with context` | `context`, `error` | session_manager.go |
| error | `Failed to get user info from response` | `error` | group_checker.go |
| error | `Failed to get user's subject review` | `error` | group_checker.go |
| error | `Failed to list BreakglassSessionList for fallback lookup` | `error`, `selector` | session_manager.go |
| error | `Failed to list BreakglassSessionList with selector` | `error`, `selector` | session_manager.go |
| error | `Failed to list BreakglassSessionList with string selector` | `error`, `selector` | session_manager.go |
| error | `Failed to list BreakglassSessions by state` | `error`, `state` | session_manager.go |
| error | `Failed to list BreakglassSessions for cluster/user` | `cluster`, `error`, `user`† | session_manager.go |
| error | `Failed to list BreakglassSessions for user` | `error`, `user`† | session_manager.go |
| error | `Failed to list ClusterConfig resources` | `error` | cluster_config_manager.go |
| error | `Failed to list sessions for getActiveBreakglassSession` | `error` | session_controller_status.go |
| error | `Failed to load config for OIDC prefixes` | `error` | group_checker.go |
| error | `Failed to parse field selector for fallback lookup` | `error`, `selector` | session_manager.go |
| error | `Failed to resolve BreakglassSession before status update` |  | session_manager.go |
| error | `Failed to retrieve cluster-verified approver groups; approval will be evaluated without verified groups` | `approver`†, `cluster`, `error`, `requestContextGroupCount`† | session_controller_approval_utils.go |
| error | `Failed to retrieve user groups for escalation determination` | `error` | session_request_helpers.go |
| error | `Failed to update BreakglassSession` |  | session_manager.go |
| error | `Failed to update BreakglassSession status` |  | session_manager.go |
| error | `GetUserGroups: client construction failed` | `cluster`, `error` | group_checker.go |
| error | `GetUserGroups: rest.Config load failed` | `cluster`, `error` | group_checker.go |
| error | `No authenticated identity claims found in request context` |  | session_request_helpers.go |
| error | `Refusing to create session for matched escalation without UID` | `error`, `escalationName`, `escalationNamespace` | session_request_helpers.go |
| error | `There is more than a single active breakglass session; this should not happen` | `cluster`, `group`†, `num_sessions`, `username`† | session_controller_status.go |
| error | `Token validation: unable to load session` | `error`, `tokenLen` | session_controller_status.go |
| error | `Unable to identify approver` | `error` | session_controller_approval_utils.go |
| error | `Unexpected response type for user info extraction` | `type` | group_checker.go |
| error | `error deleting debug session past retention` | `error` | cleanup_task.go |
| error | `error deleting expired breakglass session` |  | cleanup_task.go |
| error | `error deleting orphaned breakglass session` |  | cleanup_task.go |
| error | `error getting authenticated user identifiers` | `error` | session_controller_actions.go |
| error | `error listing breakglass sessions for approved expiry` |  | expire_approved_sessions.go |
| error | `error listing breakglass sessions for cleanup` | `error` | cleanup_task.go |
| error | `error listing breakglass sessions for idle expiry` | `error` | expire_idle_sessions.go |
| error | `error listing breakglass sessions for pending expiry` |  | expire_pending_sessions.go |
| error | `error listing debug sessions for cleanup` | `error` | cleanup_task.go |
| error | `error listing sessions for scheduled activation` | `error` | scheduled_activation.go |
| error | `error setting session status to idle which should be only initial state` |  | session_controller_status.go |
| error | `error updating expired debug session status` |  | cleanup_task.go |
| error | `error updating timed-out debug session status` |  | cleanup_task.go |
| error | `error while adding breakglass session` | `error` | session_request_helpers.go |
| error | `error while getting breakglass session` | `error` | session_controller_actions.go, session_controller_status.go |
| error | `error while re-reading breakglass session before approval transition` | `error` | session_controller_status.go |
| error | `error while updating breakglass session` | `error` | session_controller_actions.go, session_controller_status.go, session_request_helpers.go |
| error | `expiring session in WaitingForScheduledTime state with no ScheduledStartTime` | `namespace`, `session` | scheduled_activation.go |
| error | `failed to acknowledge disabled expiry notification` | `error`, `namespace`, `session` | expire_approved_sessions.go |
| error | `failed to activate scheduled session` | `error`, `namespace`, `session` | scheduled_activation.go |
| error | `failed to enqueue approval email` | `error`, `session`, `to` | session_controller_approval_utils.go |
| error | `failed to enqueue approval email via mail service` | `error`, `session`, `to` | session_controller_approval_utils.go |
| error | `failed to enqueue approval timeout notification` | `error`, `namespace`, `session` | expire_pending_sessions.go |
| error | `failed to enqueue approved session expiry notification` | `error`, `namespace`, `session` | expire_approved_sessions.go |
| error | `failed to enqueue debug session expired email` |  | cleanup_task.go |
| error | `failed to enqueue idle-expired session email` | `error`, `session` | expire_idle_sessions.go |
| error | `failed to enqueue rejection email` | `error`, `session`, `to` | session_controller_approval_utils.go |
| error | `failed to enqueue rejection email via mail service` | `error`, `session`, `to` | session_controller_approval_utils.go |
| error | `failed to enqueue session activated email` | `error`, `namespace`, `session` | scheduled_activation.go |
| error | `failed to enqueue session expired email` | `error`, `namespace`, `session` | expire_approved_sessions.go |
| error | `failed to expire scheduled session` | `error`, `namespace`, `reason`, `session` | scheduled_activation.go |
| error | `failed to list sessions with pending expiry notifications` | `error`, `state` | expire_approved_sessions.go |
| error | `failed to render approval email template` | `error`, `session` | session_controller_approval_utils.go |
| error | `failed to render debug session expired email` |  | cleanup_task.go |
| error | `failed to render email template` | `error`, `group`†, `recipientCount`†, `session` | session_controller_actions.go |
| error | `failed to render idle-expired session email` | `error`, `session` | expire_idle_sessions.go |
| error | `failed to render rejection email template` | `error`, `session` | session_controller_approval_utils.go |
| error | `failed to render session activated email` | `error`, `namespace`, `session` | scheduled_activation.go |
| error | `failed to render session expired email` | `error`, `namespace`, `session` | expire_approved_sessions.go |
| error | `failed to retry session expiry notification enqueue` | `error`, `namespace`, `session` | expire_approved_sessions.go |
| error | `failed to send request email` | `error`, `recipientCount`†, `session`, `subjectLength`† | session_controller_actions.go |
| error | `failed to update expired session status` | `error`, `session` | expire_approved_sessions.go |
| error | `failed to update idle-expired session after retries` | `error`, `session` | expire_idle_sessions.go |
| error | `failed to update session status while expiring pending session` | `error` | expire_pending_sessions.go |
| error | `skipping scheduled session … because live session could not be read` | `error`, `namespace`, `session` | scheduled_activation.go |
| error | `unknown session condition type` | `type` | session_controller_status.go |

#### `pkg/breakglass/clusterconfig`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Cluster CA pin present in secret` | `cluster`, `key`, `secret`, `secretNamespace` | checker.go |
| debug | `ClusterConfig OIDC config validated` | `clientID`, `cluster`, `fallbackPolicy`, `hasRefreshToken`, `hasTokenExchange`, `issuerURL`, `server` | checker.go |
| debug | `ClusterConfig OIDC from IdentityProvider validated` | `cluster`, `fallbackPolicy`, `hasRefreshToken`, `hasTokenExchange`, `identityProvider`†, `server` | checker.go |
| debug | `ClusterConfig deleted before status update, skipping` | `cluster` | checker.go |
| debug | `ClusterConfig kubeconfig validated` | `cluster`, `secret`, `secretNamespace` | checker.go |
| debug | `ClusterConfig status recently updated, skipping` | `cluster`, `lastUpdateAge`, `skipReason` | checker.go |
| debug | `ClusterConfig status updated successfully` | `cluster`, `ready` | checker.go |
| debug | `ClusterConfig validation check completed` |  | checker.go |
| debug | `Conflict updating ClusterConfig status, another controller likely handled it` | `cluster` | checker.go |
| debug | `Emitting Normal event for ClusterConfig` | `cluster`, `message` | checker.go |
| debug | `Emitting Warning event for ClusterConfig` | `cluster`, `message` | checker.go |
| debug | `Running ClusterConfig validation check` |  | checker.go |
| info | `CA key not found in secret, TOFU will attempt to discover and persist` | `cluster`, `key`, `secret`, `secretNamespace` | checker.go |
| info | `Cluster config checker stopping before acquiring leadership (context cancelled)` |  | checker.go |
| info | `Cluster config checker waiting for leadership signal before starting...` |  | checker.go |
| info | `ClusterConfigChecker stopping (context canceled)` |  | checker.go |
| info | `Leadership acquired - starting cluster config checker` |  | checker.go |
| warn | (dynamic) | `canonicalKey`, `clientID`, `cluster`, `error`, `identityProvider`†, `identityProviderRef`†, `issuerURL`, `legacyKey`, `namespace`, `secret`, `secretCreation`, `secretNamespace`, `server` | checker.go |
| warn | `Failed to re-fetch ClusterConfig for status update` | `cluster`, `error` | checker.go |
| warn | `No Event recorder configured; skipping Kubernetes Event emission` | `cluster` | checker.go |
| warn | `failed to clear condition on recovery` | `cluster`, `condition`, `error` | checker.go |
| warn | `failed to fetch ClusterConfig for condition clearing` | `cluster`, `error` | checker.go |
| warn | `failed to persist Ready=False for ClusterConfig` | `cluster`, `error` | checker.go |
| warn | `failed to persist status/event for ClusterConfig` | `cluster`, `error` | checker.go |
| warn | `failed to set DegradedAuth condition` | `cluster`, `error` | checker.go |
| warn | `failed to update ClusterConfig status` | `cluster`, `error` | checker.go |

#### `pkg/breakglass/debug`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Additional auxiliary resource not ready yet` | `kind`, `name`, `resource`, `status` | auxiliary_resource_manager.go |
| debug | `Auxiliary resource not ready yet` | `kind`, `message`, `name`, `resource`, `status` | auxiliary_resource_manager.go |
| debug | `Auxiliary resource produced no documents (conditional exclusion)` | `name` | auxiliary_resource_manager.go |
| debug | `Binding cluster resolution` | `binding`, `lookingFor`, `resolvedClusters` | debug_session_api_email_ops.go |
| debug | `Cluster access validated` | `allowedBySource`, `requestedCluster` | debug_session_api.go |
| debug | `Cluster allowed by binding` | `binding`, `cluster` | debug_session_api_email_ops.go |
| debug | `Cluster denied - template has no cluster restrictions and no bindings (unavailable template)` | `cluster`, `template` | debug_session_api_email_ops.go |
| debug | `Debug resource already deleted` | `kind`, `name`, `namespace` | debug_session_reconciler_lifecycle.go |
| debug | `Debug session approval email disabled by notification settings` | `session` | debug_session_api_email_ops.go |
| debug | `Debug session created email disabled by notification settings` | `session` | debug_session_api_email_ops.go |
| debug | `Debug session rejection email disabled by notification settings` | `session` | debug_session_api_email_ops.go |
| debug | `Debug session request email disabled by notification settings` | `session` | debug_session_api_email_ops.go |
| debug | `Debug session request is auto-approved, skipping approver request email` | `session` | debug_session_api_email_ops.go |
| debug | `DebugSession not found, ignoring` |  | debug_session_reconciler.go |
| debug | `Default namespace rejected by namespace constraints` | `bindingUsed`, `defaultNamespace`, `error`, `template`, `templateDefaultSet` | debug_session_api_constraints.go |
| debug | `Deferring group-restricted session until authenticated group provenance is persisted` | `debugSession`, `namespace` | debug_session_reconciler.go |
| debug | `Failed to load binding for notification config` | `binding`, `error` | debug_session_api_resolution.go |
| debug | `Failed to load template for notification config` | `error`, `template` | debug_session_api_resolution.go |
| debug | `Found bindings for template` | `applicableBindingNames`, `applicableBindingsCount`, `template` | debug_session_api_email_ops.go |
| debug | `Ignoring auxiliary resource deployment failure` |  | auxiliary_resource_manager.go |
| debug | `Ignoring scheduling option - no options defined in template or binding` | `selectedOption`, `template` | debug_session_api_constraints.go |
| debug | `Impersonating identity for debug session deployment` | `cluster`, `impersonatedUser`†, `impersonationConstraint`, `mode` | debug_session_impersonation.go |
| debug | `Merged namespace constraints from binding` | `binding`, `bindingNamespace`, `mergedAllowUserNamespace`†, `mergedDefaultNamespace`, `template` | debug_session_api_constraints.go |
| debug | `Namespace constraints found` | `allowUserNamespace`†, `defaultNamespace`, `denyUserNamespace`†, `hasAllowedNamespaces`, `hasDeniedNamespaces`, `template` | debug_session_api_constraints.go |
| debug | `Namespace defaulted` | `defaultedTo` | debug_session_api.go |
| debug | `Namespace rejected by effective namespace constraints` | `error`, `requestedNamespace`, `template` | debug_session_api_constraints.go |
| debug | `No approvers configured for debug session template, skipping request email` | `session`, `template` | debug_session_api_email_ops.go |
| debug | `No email recipients configured for debug session approvers, skipping request email` | `session`, `template` | debug_session_api_email_ops.go |
| debug | `No namespace constraints, using default` | `resolvedNamespace`, `template` | debug_session_api_constraints.go |
| debug | `No namespace constraints, using requested namespace` | `resolvedNamespace`, `template` | debug_session_api_constraints.go |
| debug | `No namespace requested, using effective default namespace` | `bindingUsed`, `resolvedNamespace`, `template` | debug_session_api_constraints.go |
| debug | `Overriding RestartPolicy to Always for workload type` | `debugSession`, `originalPolicy`, `workloadType` | debug_session_reconciler_workload.go |
| debug | `Pod template resource already deleted` | `kind`, `name` | debug_session_reconciler_lifecycle.go |
| debug | `Prepared kubectl-debug operation remains after cleanup; retrying recovery` |  | debug_session_reconciler.go |
| debug | `Received CreateDebugSession request` | `bindingRef`, `cluster`, `requestedDuration`, `selectedSchedulingOption`, `targetNamespace`, `templateRef` | debug_session_api.go |
| debug | `Requested default namespace rejected by namespace constraints` | `bindingUsed`, `defaultNamespace`, `error`, `template` | debug_session_api_constraints.go |
| debug | `Requested namespace matches default, allowing` | `defaultNamespace`, `requestedNamespace`, `template` | debug_session_api_constraints.go |
| debug | `Resolved debug session cluster alias` | `clusterConfig`, `requestedCluster`, `tenant` | debug_session_api.go |
| debug | `Resolving target namespace` | `hasNamespaceConstraints`, `requestedNamespace`, `template` | debug_session_api_constraints.go |
| debug | `Scheduling option defaulted` | `defaultedTo` | debug_session_api.go |
| debug | `Scheduling option ignored` | `ignoredOption` | debug_session_api.go |
| debug | `Skipping auxiliary resource cleanup because deleteAfter is false` | `namespace`, `resource`, `resourceName` | auxiliary_resource_manager.go |
| debug | `Skipping template without available clusters` | `includeUnavailable`, `template` | debug_session_api_templates.go |
| debug | `Updated pod template usedBy` | `addedSessionTemplate`, `podTemplate`, `usedBy` | debug_session_reconciler_lifecycle.go |
| debug | `User-specified namespace explicitly denied` | `denySource`, `denyUserNamespace`†, `requestedNamespace`, `template` | debug_session_api_constraints.go |
| debug | `User-specified namespace not allowed by template` | `allowUserNamespace`†, `requestedNamespace`, `template` | debug_session_api_constraints.go |
| debug | `findBindingsForTemplate: checking templateSelector` | `binding`, `matches`, `selectorString`, `template`, `templateLabels` | debug_session_api_templates.go |
| debug | `findBindingsForTemplate: matched by templateRef` | `binding`, `template` | debug_session_api_templates.go |
| debug | `findBindingsForTemplate: skipping inactive binding` | `binding`, `template` | debug_session_api_templates.go |
| debug | `isClusterAllowedByTemplateOrBinding result` | `allowed`, `cluster`, `source` | debug_session_api_email_ops.go |
| debug | `isClusterAllowedByTemplateOrBinding starting` | `applicableBindingsProvided`, `cluster`, `hasTemplateClusterRestriction`, `template`, `totalClusterConfigs` | debug_session_api_email_ops.go |
| debug | `resolveClustersFromBinding: checking clusterSelector` | `binding`, `clusterMapSize`, `selectorString` | debug_session_api_templates.go |
| debug | `resolveClustersFromBinding: cluster matched selector` | `binding`, `cluster`, `clusterLabels` | debug_session_api_templates.go |
| debug | `resolveClustersFromBinding: explicit clusters` | `binding`, `explicitClusters`, `matchedExplicitClusters` | debug_session_api_templates.go |
| debug | `resolveClustersFromBinding: final result` | `binding`, `resolvedClusters` | debug_session_api_templates.go |
| debug | `skipping approval-timeout status update after concurrent debug session change` | `error` | debug_session_reconciler.go |
| debug | `skipping expiration status update after concurrent debug session change` | `error` | debug_session_reconciler.go |
| debug | `skipping expiring-soon status update after concurrent debug session change` | `error` | debug_session_reconciler.go |
| info | `Additional auxiliary resource is ready` | `kind`, `name`, `resource` | auxiliary_resource_manager.go |
| info | `All auxiliary resources cleaned up` |  | auxiliary_resource_manager.go |
| info | `Approval required by binding` | `binding`, `bindingNamespace`, `session` | debug_session_reconciler.go |
| info | `Auto-approving debug session based on cluster match` | `cluster`, `pattern`, `session` | debug_session_reconciler.go |
| info | `Auto-approving debug session based on group match` | `matchedGroupHint`†, `session`, `user`† | debug_session_reconciler.go |
| info | `Auto-discovered binding for session` | `binding`, `namespace` | debug_session_reconciler.go |
| info | `Auxiliary resource is ready` | `kind`, `name`, `resource` | auxiliary_resource_manager.go |
| info | `Auxiliary resources deployed` | `deployed`, `errors`, `total` | auxiliary_resource_manager.go |
| info | `Blocking self-approval attempt` | `approver`†, `approverEmail`†, `policySource`, `requester`†, `requesterEmail`†, `session` | debug_session_api_resolution.go |
| info | `Cleaning up auxiliary resources` | `count` | auxiliary_resource_manager.go |
| info | `Cleanup of spoke resources completed for failed debug session` |  | debug_session_reconciler.go |
| info | `Constrained impersonation downgraded to legacy for debug session deployment` | `cluster`, `impersonatedUser`†, `reason`, `requestedMode` | debug_session_impersonation.go |
| info | `Debug session activated` | `duration`, `expiresAt`, `mode`, `terminalSharing` | debug_session_reconciler.go |
| info | `Debug session approval email queued` | `session` | debug_session_api_email_ops.go |
| info | `Debug session approved` | `approver`†, `session` | debug_session_api_session_ops.go |
| info | `Debug session cleanup complete` |  | debug_session_reconciler.go |
| info | `Debug session created` | `cluster`, `name`, `template`, `user`† | debug_session_api.go |
| info | `Debug session created email queued` | `requester`†, `session` | debug_session_api_email_ops.go |
| info | `Debug session expired` |  | debug_session_reconciler.go |
| info | `Debug session failed email queued` | `requester`†, `session` | debug_session_api_email_ops.go, debug_session_reconciler.go |
| info | `Debug session rejected` | `reason`, `rejector`, `session` | debug_session_api_session_ops.go |
| info | `Debug session rejection email queued` | `session` | debug_session_api_email_ops.go |
| info | `Debug session renewed` | `extendBy`, `newExpiry`, `renewalCount`, `session` | debug_session_api_session_ops.go |
| info | `Debug session request email queued` | `approvers`†, `session` | debug_session_api_email_ops.go |
| info | `Debug session terminated` | `session`, `user`† | debug_session_api_session_ops.go |
| info | `Debug workload applied` | `name` | debug_session_reconciler_workload.go |
| info | `Deleted auxiliary resource` | `kind`, `name`, `namespace`, `resourceName` | auxiliary_resource_manager.go |
| info | `Deleted debug resource` | `kind`, `name`, `namespace` | debug_session_reconciler_lifecycle.go |
| info | `Deleted pod template resource` | `kind`, `name`, `namespace` | debug_session_reconciler_lifecycle.go |
| info | `Denying debug session approval: no approvers configured, so no user is an approver` | `approver`†, `approverSource`†, `session` | debug_session_api_resolution.go |
| info | `Deployed auxiliary resource document` | `auxiliaryResource`, `kind`, `name`, `namespace` | auxiliary_resource_manager.go |
| info | `Deployed debug workload` | `kind`, `name`, `namespace` | debug_session_reconciler_workload.go |
| info | `Deployed multiple resources from single auxiliary resource` | `name`, `resources` | auxiliary_resource_manager.go |
| info | `Deployed pod template resource` | `kind`, `name`, `namespace` | debug_session_reconciler_workload.go |
| info | `Deploying auxiliary resources` | `count` | auxiliary_resource_manager.go |
| info | `Deploying pod template resources` | `count`, `debugSession` | debug_session_reconciler_workload.go |
| info | `Ephemeral container injected` | `container`, `namespace`, `pod`, `session`, `user`† | debug_session_api_email_ops.go |
| info | `Node debug pod created` | `namespace`, `node`, `podName`, `session`, `user`† | debug_session_api_email_ops.go |
| info | `Pod copy created` | `copyName`, `copyNamespace`, `originalNamespace`, `originalPod`, `session`, `user`† | debug_session_api_email_ops.go |
| info | `PodDisruptionBudget applied` | `name` | debug_session_reconciler_workload.go |
| info | `Recorded binding is not active; denying debug session approval authorization` | `binding`, `session` | debug_session_api_resolution.go |
| info | `ResourceQuota applied` | `name` | debug_session_reconciler_workload.go |
| info | `Session created with warnings` | `warnings` | debug_session_api.go |
| info | `Terminal sharing configured` | `debugSession`, `provider`, `sessionName` | debug_session_reconciler_lifecycle.go |
| info | `User joined debug session` | `role`, `session`, `user`† | debug_session_api_session_ops.go |
| info | `User left debug session` | `session`, `user`† | debug_session_api_session_ops.go |
| info | `Using impersonation for deployment` | `serviceAccount` | debug_session_reconciler_workload.go |
| info | `Workload denied while PolicyException propagates; requeueing` | `error` | debug_session_reconciler.go |
| warn | `Additional auxiliary resource failed` | `kind`, `message`, `name`, `resource` | auxiliary_resource_manager.go |
| warn | `Admission recipe drift check failed; will retry` | `error` | debug_session_admission_recipe.go |
| warn | `Auxiliary resource deployment failed` |  | auxiliary_resource_manager.go |
| warn | `Auxiliary resource deployment failed with unknown failure policy` |  | auxiliary_resource_manager.go |
| warn | `Auxiliary resource failed` | `kind`, `message`, `name`, `resource` | auxiliary_resource_manager.go |
| warn | `Best-effort cleanup of partially deployed resources failed during session failure; cleanup will be retried on subsequent reconciles` | `cleanupError` | debug_session_reconciler.go |
| warn | `Binding does not grant requested cluster` | `bindingClusters`, `bindingRef`, `requestedCluster` | debug_session_api.go |
| warn | `Binding does not reference requested template` | `bindingRef`, `templateRef` | debug_session_api.go |
| warn | `Binding extra deploy variable constraints are invalid` | `error` | debug_session_api.go |
| warn | `Binding is not active` | `bindingRef`, `disabled`, `effectiveFrom`, `expiresAt` | debug_session_api.go |
| warn | `Binding not found` | `bindingRef` | debug_session_api.go |
| warn | `Binding session limits exceeded` | `bindingRef`, `error`, `user`†, `userEmail`† | debug_session_api.go |
| warn | `Cleanup reported success but spoke resources are still tracked; will retry` |  | debug_session_reconciler.go |
| warn | `Cluster not allowed by template or binding` | `bindingsChecked`, `requestedCluster`, `templateAllowedClusters`, `templateClusterSelector`, `templateRef` | debug_session_api.go |
| warn | `ClusterConfig is not ready for debug session creation` | `cluster`, `clusterConfig`, `namespace` | debug_session_api.go |
| warn | `ClusterConfig name is ambiguous for debug session creation` | `cluster`, `clusterConfig` | debug_session_api.go |
| warn | `ClusterConfig no longer exists; retaining cleanup inventory for retry` | `cluster` | debug_session_reconciler_lifecycle.go |
| warn | `ClusterConfig not found for debug session creation` | `cluster` | debug_session_api.go |
| warn | `ClusterConfig tenant alias is ambiguous for debug session creation` | `cluster` | debug_session_api.go |
| warn | `Conflicting debug session namespace fields` | `error`, `namespace`, `targetNamespace` | debug_session_api.go |
| warn | `Could not fetch binding while checking debug session read authorization` | `binding`, `error`, `session` | debug_session_api.go |
| warn | `Could not fetch recorded binding while checking debug session approval authorization` | `binding`, `error`, `session` | debug_session_api_resolution.go |
| warn | `Could not fetch template while checking debug session read authorization` | `error`, `session`, `template` | debug_session_api.go |
| warn | `Debug operation succeeded but activity recording failed` | `error` | debug_session_api_email_ops.go |
| warn | `Debug session approval reason is invalid` | `error`, `session` | debug_session_api_session_ops.go |
| warn | `Debug session container has restarted` | `container`, `lastTerminationReason`, `pod`, `podNamespace`, `restartCount` | debug_session_reconciler_lifecycle.go |
| warn | `Debug session container in problematic waiting state` | `container`, `pod`, `podNamespace`, `waitingMessage`, `waitingReason` | debug_session_reconciler_lifecycle.go |
| warn | `Debug session pod failed` | `message`, `node`, `pod`, `podNamespace`, `reason` | debug_session_reconciler_lifecycle.go |
| warn | `Debug session rejection reason is invalid` | `error`, `session` | debug_session_api_session_ops.go |
| warn | `Debug session request reason is invalid` | `bindingRef`, `error`, `templateRef` | debug_session_api.go |
| warn | `Debug session status update conflict` | `action`, `error`, `session` | debug_session_api_status_patch.go |
| warn | `DebugSession failed structural validation, skipping reconciliation` | `errors` | debug_session_reconciler.go |
| warn | `Deleted orphaned debug pod after status update failure` | `pod`, `podNamespace`, `statusError`† | debug_session_kubectl.go |
| warn | `ExtraDeployValues validation failed` | `errors`, `templateRef`, `userGroupCount`† | debug_session_api.go |
| warn | `Failed to cleanup auxiliary resources` | `error` | debug_session_reconciler_lifecycle.go |
| warn | `Failed to cleanup pod template resources` | `error` | debug_session_reconciler_lifecycle.go |
| warn | `Failed to converge debug session connection lease; will retry` | `error` | debug_session_reconciler.go |
| warn | `Failed to delete additional auxiliary resource` | `error`, `kind`, `namespace`, `resource`, `resourceName` | auxiliary_resource_manager.go |
| warn | `Failed to delete auxiliary resource` | `error`, `namespace`, `resource`, `resourceName` | auxiliary_resource_manager.go |
| warn | `Failed to delete debug resource` | `error`, `kind`, `name`, `namespace` | debug_session_reconciler_lifecycle.go |
| warn | `Failed to delete pod template resource` | `error`, `kind`, `name` | debug_session_reconciler_lifecycle.go |
| warn | `Failed to list cluster configs for pattern resolution` | `error` | debug_session_api_templates.go |
| warn | `Failed to parse ApproveDebugSession request` | `error` | debug_session_api_session_ops.go |
| warn | `Failed to parse CreateDebugSession request` | `error` | debug_session_api.go |
| warn | `Failed to parse GVK for pod template resource` | `apiVersion`, `error`, `kind` | debug_session_reconciler_lifecycle.go |
| warn | `Failed to parse GVK for resource` | `apiVersion`, `error`, `kind` | auxiliary_resource_manager.go |
| warn | `Failed to parse RejectDebugSession request` | `error` | debug_session_api_session_ops.go |
| warn | `Failed to recover prepared kubectl-debug operations` | `error` | debug_session_reconciler.go |
| warn | `Failed to release unused terminal recording reservation` | `error`, `recordingId`, `session` | terminal_recording_api.go |
| warn | `Failed to repair optional pod template usage; periodic reconciliation will retry` | `error`, `podTemplate` | debug_session_reconciler_lifecycle.go |
| warn | `Failed to revoke terminal recording lease` | `error` | debug_session_reconciler.go |
| warn | `Failed to send audit event to webhook destination` | `error`, `eventType`, `session`, `url` | debug_session_reconciler.go |
| warn | `Failed to synchronize renewed debug workload deadline; will retry` | `error` | debug_session_reconciler.go |
| warn | `HotfixRecord drift check failed; keeping the last observation` | `error`, `record` | hotfix_record_reconciler.go |
| warn | `Invalid bindingRef format` | `bindingRef` | debug_session_api.go |
| warn | `No binding allows the requester for this template and cluster` | `bindingsChecked`, `cluster`, `groupCount`†, `templateRef`, `user`† | debug_session_api.go |
| warn | `Node-maintenance target validation unavailable` | `error` | debug_session_node_maintenance.go |
| warn | `Optional discovery aliases unavailable; retaining identity authorization` | `error` | debug_session_api_templates.go |
| warn | `Preserved orphaned debug pod because its immutable identity changed` | `pod`, `podNamespace`, `statusError`† | debug_session_kubectl.go |
| warn | `Preserved pod after ambiguous create failure because ownership could not be verified` | `createError`, `pod`, `podNamespace` | debug_session_kubectl.go |
| warn | `Rejected ephemeral container injection` | `error` | debug_session_api_email_ops.go |
| warn | `Rejected ephemeral container request` | `error` | debug_session_api_email_ops.go |
| warn | `Rejected node debug pod request` | `error` | debug_session_api_email_ops.go |
| warn | `Rejected pod copy request` | `error` | debug_session_api_email_ops.go |
| warn | `Rejecting session because binding variable constraints or values are invalid` | `error` | debug_session_reconciler.go |
| warn | `Renewal committed; connection lease convergence will retry` | `error`, `session` | debug_session_api_session_ops.go |
| warn | `Renewal committed; connection lease expiry status convergence will retry` | `error`, `session` | debug_session_api_session_ops.go |
| warn | `Renewal committed; will retry extending debug workload deadline` | `error`, `name` | debug_session_api_session_ops.go |
| warn | `Requested cluster not found in ClusterConfig map` | `availableClusters`, `cluster` | debug_session_api_email_ops.go |
| warn | `Requested debug session duration is invalid` | `bindingRef`, `error`, `requestedDuration`, `templateRef` | debug_session_api.go |
| warn | `Retrying cleanup of spoke resources for a failed debug session` | `error` | debug_session_reconciler.go |
| warn | `Scheduling option validation failed` | `error`, `selectedSchedulingOption`, `templateRef` | debug_session_api.go |
| warn | `Skipping approval email - no valid email address` | `recipient`†, `session` | debug_session_api_email_ops.go |
| warn | `Skipping debug notification because excluded group membership could not be resolved` | `error` | debug_session_api_resolution.go |
| warn | `Skipping debug notification because excluded group membership is unavailable` |  | debug_session_api_resolution.go |
| warn | `Skipping debug session failed email - no valid email address` | `session` | debug_session_reconciler.go |
| warn | `Skipping invalid binding variable policy` | `binding`, `error` | debug_session_reconciler.go |
| warn | `Skipping rejection email - no valid email address` | `recipient`†, `session` | debug_session_api_email_ops.go |
| warn | `Skipping session created email - no valid email address` | `recipient`†, `session` | debug_session_api_email_ops.go |
| warn | `Target namespace does not exist, fail-open mode` | `namespace` | debug_session_reconciler_workload.go |
| warn | `Target namespace validation failed` | `allowUserNamespace`†, `bindingUsed`, `defaultNamespace`, `error`, `requestedNamespace`, `templateRef` | debug_session_api.go |
| warn | `Template not found` | `templateRef` | debug_session_api.go |
| warn | `Unknown debug session state` | `state` | debug_session_reconciler.go |
| warn | `User is not allowed to request debug session` | `bindingRef`, `groupCount`†, `selectedBindingRef`, `templateRef`, `user`† | debug_session_api.go |
| warn | `deprecated notify-only expiration still enforces hard expiry` |  | debug_session_reconciler.go |
| warn | `findBindingsForTemplate: failed to parse templateSelector` | `binding`, `error` | debug_session_api_templates.go |
| warn | `findBindingsForTemplate: skipping binding with invalid variable constraints` | `binding`, `error` | debug_session_api_templates.go |
| warn | `resolveClustersFromBinding: failed to parse clusterSelector` | `binding`, `error` | debug_session_api_templates.go |
| error | `Connection lease validator is not configured` |  | debug_session_api_email_ops.go |
| error | `Could not fetch template to check approvers, denying approval` | `error`, `session`, `template` | debug_session_api_resolution.go |
| error | `Debug session approval timed out` | `debugSession`, `namespace`, `reason` | debug_session_reconciler.go |
| error | `Debug session failed` | `previousState`, `reason`, `requestedBy`†, `template` | debug_session_reconciler.go |
| error | `Debug session failed closed because its active lease is missing` | `cluster`, `debugSession`, `namespace` | debug_session_reconciler.go |
| error | `Failed to admit debug session quota` | `error`, `name`, `namespace` | debug_session_api.go |
| error | `Failed to apply template security context` | `error` | debug_session_api_email_ops.go |
| error | `Failed to clean up debug session after provenance persistence failure` | `error` | debug_session_api.go |
| error | `Failed to cleanup debug session resources` | `error` | debug_session_reconciler.go |
| error | `Failed to cleanup kubectl-debug resources` | `error` | debug_session_reconciler_lifecycle.go |
| error | `Failed to create debug session` | `error` | debug_session_api.go |
| error | `Failed to create node debug pod` | `error` | debug_session_api_email_ops.go |
| error | `Failed to create pod copy` | `error` | debug_session_api_email_ops.go |
| error | `Failed to delete orphaned debug pod after status update failure; the pod is not tracked in the session status and will not be cleaned up automatically` | `deleteError`, `pod`, `podNamespace`, `statusError`† | debug_session_kubectl.go |
| error | `Failed to deploy debug resources` | `error` | debug_session_reconciler.go |
| error | `Failed to encode admission policy` | `error` | debug_session_api.go |
| error | `Failed to enqueue debug session approval email` | `error`, `session` | debug_session_api_email_ops.go |
| error | `Failed to enqueue debug session created email` | `error`, `session` | debug_session_api_email_ops.go |
| error | `Failed to enqueue debug session failed email` | `error`, `session` | debug_session_api_email_ops.go, debug_session_reconciler.go |
| error | `Failed to enqueue debug session rejection email` | `error`, `session` | debug_session_api_email_ops.go |
| error | `Failed to enqueue debug session request email` | `error`, `session` | debug_session_api_email_ops.go |
| error | `Failed to evaluate debug session read authorization` | `error`, `name`, `namespace`, `session` | debug_session_api.go |
| error | `Failed to get DebugSession` | `error` | debug_session_reconciler.go |
| error | `Failed to get DebugSessionTemplate` | `error`, `template` | debug_session_reconciler.go |
| error | `Failed to get binding` | `binding`, `error` | debug_session_api.go |
| error | `Failed to get debug session` | `error`, `name` | debug_session_api.go, debug_session_api_email_ops.go, debug_session_api_session_ops.go |
| error | `Failed to get pod template` | `error`, `name` | debug_session_api_resolution.go |
| error | `Failed to get referenced pod template` | `error`, `podTemplate` | debug_session_api.go |
| error | `Failed to get template` | `error`, `name`, `template` | debug_session_api.go, debug_session_api_templates.go |
| error | `Failed to inject ephemeral container` | `error` | debug_session_api_email_ops.go |
| error | `Failed to inspect pod after ambiguous create failure` | `createError`, `getError`, `pod`, `podNamespace` | debug_session_kubectl.go |
| error | `Failed to list bindings for cluster validation` | `error` | debug_session_api.go |
| error | `Failed to list bindings for template authorization` | `error`, `name` | debug_session_api_templates.go |
| error | `Failed to list bindings for template cluster resolution` | `error` | debug_session_api_templates.go |
| error | `Failed to list cluster bindings` | `error` | debug_session_api_templates.go |
| error | `Failed to list cluster configs for cluster validation` | `error` | debug_session_api.go |
| error | `Failed to list cluster configs for template authorization` | `error` | debug_session_api_templates.go |
| error | `Failed to list debug pod templates` | `error` | debug_session_api_resolution.go |
| error | `Failed to list debug session templates` | `error` | debug_session_api_templates.go |
| error | `Failed to list debug sessions` | `error` | debug_session_api.go |
| error | `Failed to mark timed-out debug session approval` | `error`, `session` | debug_session_api_session_ops.go |
| error | `Failed to mark timed-out debug session rejection` | `error`, `session` | debug_session_api_session_ops.go |
| error | `Failed to persist authenticated debug-session group provenance` | `error` | debug_session_api.go |
| error | `Failed to read orphaned debug pod before deletion` | `getError`, `pod`, `podNamespace`, `statusError`† | debug_session_kubectl.go |
| error | `Failed to remove pod after ambiguous create failure` | `createError`, `deleteError`, `pod`, `podNamespace` | debug_session_kubectl.go |
| error | `Failed to render debug session approval email` | `error`, `session` | debug_session_api_email_ops.go |
| error | `Failed to render debug session created email` | `error`, `session` | debug_session_api_email_ops.go |
| error | `Failed to render debug session failed email` | `error`, `session` | debug_session_api_email_ops.go, debug_session_reconciler.go |
| error | `Failed to render debug session rejection email` | `error`, `session` | debug_session_api_email_ops.go |
| error | `Failed to render debug session request email` | `error`, `session` | debug_session_api_email_ops.go |
| error | `Failed to revoke debug session connection lease` | `error` | debug_session_reconciler.go |
| error | `Failed to terminalize debug session after provenance persistence failure` | `error` | debug_session_api.go |
| error | `Failed to update DebugSession status after validation failure` | `error` | debug_session_reconciler.go |
| error | `Failed to validate ephemeral container request` | `error` | debug_session_api_email_ops.go |
| error | `Failed to …` | `error`, `session` | debug_session_api_status_patch.go |
| error | `Refusing to delete orphaned debug pod without immutable identity` | `pod`, `statusError`† | debug_session_kubectl.go |
| error | `Refusing to evaluate debug session: explicit bindingRef is unresolvable, approval requirement is indeterminate; not falling back to auto-discovery` | `binding`, `bindingNamespace`, `cluster`, `debugSession`, `error`, `namespace`, `reason`, `state` | debug_session_reconciler.go |
| error | `Required auxiliary resource deployment failed` |  | auxiliary_resource_manager.go |
| error | `Terminal recording audit event was not delivered` | `correlationID`, `error`, `event`, `session` | terminal_recording_api.go |
| error | `Validated debug session binding could not be selected` | `bindingRef`, `cluster`, `error`, `templateRef` | debug_session_api.go |

#### `pkg/breakglass/escalation`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Acquiring token via client credentials` | `baseURL`, `clientID`, `clientSecretProvided`, `endpoint`, `grantType`, `realm` | escalation_status_updater.go |
| debug | `Auto-detected multiple IDPs, using multi-IDP mode` | `escalation`, `idpCount`, `idps` | escalation_status_updater.go |
| debug | `BreakglassEscalationController initialization completed successfully` |  | escalation_controller.go |
| debug | `Calling group member resolver` | `escalation`, `group`†, `resolverType` | escalation_status_updater.go |
| debug | `Cluster-group escalation lookup complete` | `cluster`, `evaluated`, `matched` | escalation_manager.go |
| debug | `Completed escalation status update cycle` |  | escalation_status_updater.go |
| debug | `Configured Keycloak group exists but has no resolvable members` | `group`† | escalation_status_updater.go |
| debug | `Configured approver group exists but has no resolvable members` | `escalation`, `group`†, `idp` | escalation_status_updater.go |
| debug | `Continuing without OIDC prefix stripping` | `error` | escalation_controller.go |
| debug | `Direct members fetch completed` | `directMemberCount`, `group`† | escalation_status_updater.go |
| debug | `Email claim unavailable; using authenticated username for escalation lookup` | `error`, `username`† | escalation_controller.go |
| debug | `Escalation did not match filter` |  | escalation_manager.go |
| debug | `Escalation does not match any user groups` |  | escalation_manager.go |
| debug | `Escalation endpoint registered successfully (RESTful)` | `endpoint` | escalation_controller.go |
| debug | `Escalation has no approver groups; updating group sync status` | `escalation` | escalation_status_updater.go |
| debug | `Escalation matched filter` |  | escalation_manager.go |
| debug | `Escalation matches user group` |  | escalation_manager.go |
| debug | `Escalation skipped: group mismatch` | `allowedGroups`†, `escalation`, `userGroupCount`† | escalation_manager.go |
| debug | `Escalation status update cycle canceled while listing escalations` | `error` | escalation_status_updater.go |
| debug | `Extracted raw token groups from JWT claims` | `rawTokenGroupCount`† | escalation_controller.go |
| debug | `Fell back to full escalation scan` | `cluster`, `totalEscalations` | escalation_manager.go |
| debug | `Fell back to full target escalation scan` | `cluster`, `targetGroupHint`†, `totalEscalations` | escalation_manager.go |
| debug | `Fetched escalation candidates with group index` | `candidateCount`, `cluster` | escalation_manager.go |
| debug | `Fetched escalation candidates with target-group index` | `candidateCount`, `cluster`, `targetGroupHint`† | escalation_manager.go |
| debug | `Fetched escalations for status update` | `count` | escalation_status_updater.go |
| debug | `Fetched group escalation candidates with group index` | `candidateCount`, `matched` | escalation_manager.go |
| debug | `Fetching BreakglassEscalation by name` | `name`, `namespace` | escalation_manager.go |
| debug | `Fetching BreakglassEscalations with filter` |  | escalation_manager.go |
| debug | `Fetching BreakglassEscalations with selector` | `selector` | escalation_manager.go |
| debug | `Fetching all BreakglassEscalations` |  | escalation_manager.go |
| debug | `Fetching cluster BreakglassEscalations` | `cluster` | escalation_manager.go |
| debug | `Fetching cluster-group BreakglassEscalations` | `cluster`, `groupCount`† | escalation_manager.go |
| debug | `Fetching cluster-group-target BreakglassEscalations` | `cluster`, `targetGroupHint`†, `userGroupCount`† | escalation_manager.go |
| debug | `Fetching group BreakglassEscalations` | `groupCount`† | escalation_manager.go |
| debug | `Fetching group members from IDP` | `escalation`, `groupCount`†, `idp` | escalation_status_updater.go |
| debug | `Found matching group by name` | `group`†, `groupID`†, `matchedNameHint` | escalation_status_updater.go |
| debug | `GetGroup API call details` | `baseURL`, `endpoint`, `groupID`†, `realm`, `tokenLen` | escalation_status_updater.go |
| debug | `GetGroupMembers API call details` | `baseURL`, `endpoint`, `groupID`†, `realm`, `tokenLen` | escalation_status_updater.go |
| debug | `GetGroupMembers API call for subgroup` | `baseURL`, `endpoint`, `realm`, `subgroupID`†, `tokenLen` | escalation_status_updater.go |
| debug | `GetGroups API call details` | `baseURL`, `endpoint`, `realm`, `searchParamHint`, `tokenLen` | escalation_status_updater.go |
| debug | `Group member resolution returning successfully` | `group`†, `memberCount` | escalation_status_updater.go |
| debug | `Group member resolver returned members` | `escalation`, `group`†, `rawMemberCount` | escalation_status_updater.go |
| debug | `Group members changed; marking for update` | `escalation`, `group`†, `newCount`, `oldCount` | escalation_status_updater.go |
| debug | `Group search result` | `groupID`†, `groupNameHint`†, `hasSubgroups`†, `index` | escalation_status_updater.go |
| debug | `IDPLoader not configured; using single resolver fallback` | `escalation` | escalation_status_updater.go |
| debug | `Initializing BreakglassEscalationController with Keycloak identity provider` |  | escalation_controller.go |
| debug | `Keycloak cache hit for group` | `group`†, `membersCount` | escalation_status_updater.go |
| debug | `Keycloak cache miss for group; will perform lookup` | `group`† | escalation_status_updater.go |
| debug | `Keycloak client configured with custom CA certificate` | `baseURL`, `realm` | escalation_status_updater.go |
| debug | `Keycloak group search returned a nil group entry` | `index` | escalation_status_updater.go |
| debug | `Keycloak groups search completed` | `group`†, `returnedGroupCount`† | escalation_status_updater.go |
| debug | `Keycloak token acquisition canceled` | `clientID`, `endpoint`, `error`, `grantType` | escalation_status_updater.go |
| debug | `Keycloak token lookup canceled` | `error`, `group`† | escalation_status_updater.go |
| debug | `KeycloakIdentityProvider configured for user identity extraction` |  | escalation_controller.go |
| debug | `Processing escalation with approver groups` | `escalation`, `groupCount`† | escalation_status_updater.go |
| debug | `Processing subgroup` | `group`†, `parentGroupID`†, `subgroupID`†, `subgroupIndex`†, `subgroupNameHint`† | escalation_status_updater.go |
| debug | `Resolved user groups (token first)` | `userGroupCount`† | escalation_controller.go |
| debug | `Resolving group for escalation` | `escalation`, `group`†, `resolverType` | escalation_status_updater.go |
| debug | `Retrieved escalations for filtering` | `totalCount` | escalation_manager.go |
| debug | `Returning escalations response (filtered, hidden groups removed)` | `responseCount` | escalation_controller.go |
| debug | `Skipping escalation status update cycle because context is done` | `error` | escalation_status_updater.go |
| debug | `Starting direct members fetch step` | `group`†, `groupID`† | escalation_status_updater.go |
| debug | `Starting escalation status update cycle` | `resolver` | escalation_status_updater.go |
| debug | `Starting group search step` | `group`† | escalation_status_updater.go |
| debug | `Starting member list normalization` | `beforeNormalizationCount`, `group`† | escalation_status_updater.go |
| debug | `Starting subgroups fetch step` | `currentMemberCount`, `group`†, `groupID`† | escalation_status_updater.go |
| debug | `Stopping escalation status update cycle because IDP loading was canceled` | `error` | escalation_status_updater.go |
| debug | `Stopping escalation status update cycle because context is done` | `error` | escalation_status_updater.go |
| debug | `Subgroup members fetch completed` | `memberCount`, `subgroupID`† | escalation_status_updater.go |
| debug | `Subgroups fetch completed` | `group`†, `subgroupCount`† | escalation_status_updater.go |
| debug | `Successfully extracted user identity from token` | `email`†, `username`† | escalation_controller.go |
| debug | `Successfully fetched escalations from manager` | `escalationCount` | escalation_controller.go |
| debug | `Token acquired successfully` | `clientID`, `expiresIn`, `tokenLen`, `tokenType` | escalation_status_updater.go |
| debug | `Updated escalation successfully` | `escalation`, `groupCount`† | escalation_status_updater.go |
| debug | `Using cached token` | `expiresIn` | escalation_status_updater.go |
| debug | `Using explicitly configured IDPs` | `escalation`, `idps` | escalation_status_updater.go |
| debug | `Using legacy single resolver mode` | `escalation` | escalation_status_updater.go |
| debug | `Using multi-IDP group sync` | `escalation`, `idps` | escalation_status_updater.go |
| debug | `Using pre-configured service account token` | `tokenLen` | escalation_status_updater.go |
| info | `BreakglassEscalation status updated` | `name` | escalation_manager.go |
| info | `Escalation status updater stopping (context done)` |  | escalation_status_updater.go |
| info | `Escalation status updater stopping before acquiring leadership (context canceled)` |  | escalation_status_updater.go |
| info | `Escalation status updater waiting for leadership signal before starting...` |  | escalation_status_updater.go |
| info | `EscalationManager initialized successfully` |  | escalation_manager.go |
| info | `EscalationManager resolver updated` |  | escalation_manager.go |
| info | `Fetched BreakglassEscalations` | `count` | escalation_manager.go |
| info | `Fetched BreakglassEscalations with selector` | `count`, `selector` | escalation_manager.go |
| info | `Filtered BreakglassEscalations` | `count`, `totalEvaluated` | escalation_manager.go |
| info | `Initializing EscalationManager` | `context` | escalation_manager.go |
| info | `Keycloak group member resolution completed successfully` | `finalResolvedCount`, `group`† | escalation_status_updater.go |
| info | `Keycloak group sync disabled or not fully configured; using no-op resolver` |  | escalation_status_updater.go |
| info | `Keycloak group sync enabled` | `baseURL`, `realm` | escalation_status_updater.go |
| info | `Leadership acquired - starting escalation status updater` |  | escalation_status_updater.go |
| info | `Multi-IDP group sync completed` | `errorCount`, `escalation`, `failureCount`, `idpCount`, `successCount`, `syncStatus` | escalation_status_updater.go |
| info | `Processing escalations request` |  | escalation_controller.go |
| info | `Registering escalation controller endpoints (RESTful)` | `basePath` | escalation_controller.go |
| info | `Resolved approver group members (normalized)` | `escalation`, `group`†, `normalizedCount`, `rawCount` | escalation_status_updater.go |
| info | `Retaining previously cached group members due to fetch error` | `count`, `escalation`, `group`†, `idp` | escalation_status_updater.go |
| info | `Starting escalation status updater` | `interval` | escalation_status_updater.go |
| info | `Updating BreakglassEscalation status` | `name` | escalation_manager.go |
| info | `Updating escalation status with resolved group members` | `escalation`, `groupCount`† | escalation_status_updater.go |
| warn | `Configured Keycloak group disappeared during lookup` | `error`, `group`† | escalation_status_updater.go |
| warn | `Configured Keycloak group was not found` | `group`† | escalation_status_updater.go |
| warn | `Configured approver group resolved but has no members` | `escalation`, `group`† | escalation_status_updater.go |
| warn | `Configured approver group was not found; removed stale members from escalation status` | `escalation`, `group`† | escalation_status_updater.go |
| warn | `EscalationManager: configLoader not set, falling back to disk read (performance impact)` |  | escalation_manager.go |
| warn | `Failed to create resolver for IDP` | `escalation`, `idp` | escalation_status_updater.go |
| warn | `Failed to load IDPs for auto-detection, falling back to legacy mode` | `error`, `escalation` | escalation_status_updater.go |
| warn | `Failed to load system cert pool; only the custom CA will be trusted` | `error` | escalation_status_updater.go |
| warn | `Failed to parse CA certificate PEM; falling back to system certificates` | `baseURL`, `realm` | escalation_status_updater.go |
| warn | `Failed to resolve group members from IDP` | `error`, `escalation`, `group`†, `idp` | escalation_status_updater.go |
| warn | `Keycloak group detail fetch failed` | `endpoint`, `error`, `errorType`, `group`†, `tokenLen` | escalation_status_updater.go |
| warn | `No group member resolver configured; skipping group resolution` | `escalation`, `group`† | escalation_status_updater.go |
| warn | `Subgroup members fetch failed` | `endpoint`, `error`, `errorType`, `group`†, `subgroupID`†, `tokenLen` | escalation_status_updater.go |
| error | `Failed listing BreakglassEscalations for status update` | `error` | escalation_status_updater.go |
| error | `Failed resolving group members from resolver` | `error`, `escalation`, `group`†, `resolverType` | escalation_status_updater.go |
| error | `Failed to acquire token` | `clientID`, `endpoint`, `error`, `grantType` | escalation_status_updater.go |
| error | `Failed to create new client` | `error` | escalation_manager.go |
| error | `Failed to extract an authenticated user identity` | `error` | escalation_controller.go |
| error | `Failed to get BreakglassEscalationList` | `error` | escalation_manager.go |
| error | `Failed to get Keycloak token` | `error`, `group`† | escalation_status_updater.go |
| error | `Failed to get config with context` | `context`, `error` | escalation_manager.go |
| error | `Failed to list BreakglassEscalation for filtered get` | `error` | escalation_manager.go |
| error | `Failed to list BreakglassEscalation with selector` | `error`, `selector` | escalation_manager.go |
| error | `Failed to load ClusterConfig readiness for active escalations` | `error` | escalation_controller.go |
| error | `Failed to load IDP configuration` | `error`, `escalation`, `idp` | escalation_status_updater.go |
| error | `Failed to resolve group members` | `error`, `escalation`, `group`† | escalation_status_updater.go |
| error | `Failed to retrieve escalations from manager` | `error` | escalation_controller.go |
| error | `Failed to retrieve user groups for escalation determination` | `error`, `user`† | escalation_controller.go |
| error | `Failed to update BreakglassEscalation status` | `error`, `name` | escalation_manager.go |
| error | `Failed updating escalation group sync condition` | `error`, `escalation` | escalation_status_updater.go |
| error | `Failed updating escalation status` | `error`, `escalation` | escalation_status_updater.go |
| error | `Keycloak client rejected InsecureSkipVerify=true; configure CertificateAuthority instead` | `baseURL`, `realm` | escalation_status_updater.go |
| error | `Keycloak group search returned a group without an ID` | `error`, `group`† | escalation_status_updater.go |
| error | `Keycloak group sync disabled because InsecureSkipVerify=true is not supported` | `baseURL`, `realm` | escalation_status_updater.go |
| error | `Keycloak groups search failed` | `endpoint`, `error`, `errorType`, `group`†, `params`, `tokenLen` | escalation_status_updater.go |
| error | `Keycloak members fetch failed` | `endpoint`, `error`, `errorType`, `group`†, `groupID`†, `tokenLen` | escalation_status_updater.go |
| error | `Keycloak resolver has incomplete configuration; cannot resolve groups` | `baseURL`, `clientID`, `group`†, `realm` | escalation_status_updater.go |
| error | `Refusing to create Keycloak group sync resolver with InsecureSkipVerify=true` | `baseURL`, `idp`, `realm` | escalation_status_updater.go |

#### `pkg/breakglass/eventrecorder`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `kubernetes Event created` |  | event_recorder.go |
| info | `skipping kubernetes Event creation: object has no namespace and controller namespace is not set` | `object` | event_recorder.go |
| warn | `failed to create kubernetes Event` |  | event_recorder.go |

#### `pkg/cert`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `certificates loaded` |  | cert.go |
| debug | `certs ready` |  | cert.go |
| debug | `waiting for certs generation` |  | cert.go |
| info | `Cert-controller's manager stopping before acquiring leadership (context cancelled)` |  | cert.go |
| info | `Cert-controller's manager waiting for leadership signal before starting...` |  | cert.go |
| info | `Configuring cert-controller's manager` |  | cert.go |
| info | `Leadership acquired - cert-controller's manager` |  | cert.go |
| info | `Setting up cert-controller's rotator` | `namespace`, `webhook-cert-path`, `webhook-service-name`, `webhook-validating-config-name` | cert.go |
| info | `Starting cert-controller's manager` |  | cert.go |

#### `pkg/cli`

| Level | Message | Fields | File |
|---|---|---|---|
| info | `CLI Configuration` | `breakglass_namespace`, `cluster_config_check_interval`, `config_path`, `debug`, `disable_email`†, `disable_session_rate_limit`, `enable_api`, `enable_cleanup`, `enable_controllers`, `enable_frontend`, `enable_http2`, `enable_leader_election`, `enable_validating_webhooks`, `enable_webhooks`, `escalation_status_update_interval`, `health_probe_bind_address`, `leader_elect_id`, `leader_elect_namespace`, `log_format`, `log_level`, `metrics_bind_address`, `metrics_cert_path`, `metrics_secure`, `otel_enabled`, `otel_endpoint`, `otel_exporter`, `otel_insecure`, `otel_required`, `otel_sampling_rate`, `pod_namespace`, `webhook-cert-generation`, `webhook-service-name`, `webhook-validating-config-name`, `webhook_bind_address`, `webhook_cert_key`, `webhook_cert_name`, `webhook_cert_path`, `webhooks_metrics_bind_address`, `webhooks_metrics_secure` | cli.go |
| warn | (dynamic) |  | cli.go |

#### `pkg/cluster`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Acquired OIDC token` | `cluster`, `expiresIn`, `hasRefreshToken`, `namespace` | oidc.go |
| debug | `Attempting token refresh from cache` | `cluster`, `namespace` | oidc.go |
| debug | `CA secret not found, will attempt TOFU` | `cluster` | oidc.go |
| debug | `Cached REST config` | `authType`, `cluster`, `ttl` | cache.go |
| debug | `ClusterConfig OIDC caches invalidated due to Secret delete` | `secret` | watchers.go |
| debug | `ClusterConfig OIDC caches invalidated due to Secret update` | `secret` | watchers.go |
| debug | `ClusterConfig cache invalidated` | `cluster` | watchers.go |
| debug | `ClusterConfig cache invalidated due to delete` | `cluster` | watchers.go |
| debug | `ClusterConfig caches invalidated due to Secret delete` | `secret` | watchers.go |
| debug | `ClusterConfig caches invalidated due to Secret update` | `secret` | watchers.go |
| debug | `Invalidating cluster cache due to OIDC secret change` | `cluster`, `secret` | cache.go |
| debug | `Loaded cluster CA from secret` | `cluster`, `key`, `secret` | oidc.go |
| debug | `No CA configured and TOFU disabled; using system trust store` | `cluster` | oidc.go |
| debug | `REST config cache expired` | `cluster`, `expiredAt` | cache.go |
| debug | `Resolved OIDC config from IdentityProvider` | `clientID`, `cluster`, `fallbackPolicy`, `hasRefreshTokenSecretRef`, `hasTokenExchange`, `identityProvider`†, `issuerURL`, `server` | oidc.go |
| debug | `Rotated refresh token key not found, falling back to original key` | `error`, `rotatedKey` | oidc.go |
| debug | `Skipping loopback kubeconfig host rewrite due to BREAKGLASS_DISABLE_LOOPBACK_REWRITE` | `host` | cache.go |
| debug | `Storing IDP Keycloak SA credentials for potential fallback` | `cluster`, `fallbackPolicy`, `identityProvider`† | oidc.go |
| debug | `Token exchange successful` | `expiresIn` | oidc.go |
| debug | `Token exchange with actor successful` | `expiresIn`, `hasActorToken` | oidc.go |
| debug | `Token refreshed from secret` | `cluster`, `expiresIn`, `namespace` | oidc.go |
| debug | `Token refreshed successfully from cache` | `cluster`, `expiresIn`, `namespace` | oidc.go |
| debug | `Using Keycloak service account credentials for OIDC auth` | `cluster`, `identityProvider`† | oidc.go |
| debug | `Using cached TOFU CA for OIDC issuer` | `issuer` | oidc.go |
| debug | `Using cached TOFU CA for cluster` | `cluster` | oidc.go |
| debug | `Using cached token` | `cluster`, `expiresAt`, `namespace` | oidc.go |
| debug | `Using rotated refresh token` | `key` | oidc.go |
| debug | `created circuit breaker for cluster` | `cluster` | circuitbreaker.go |
| info | `Invalidated cluster caches due to OIDC secret change` | `clusterCount`, `secret` | cache.go |
| info | `Persisted TOFU CA to secret` | `cluster`, `secret` | oidc.go |
| info | `Persisted rotated refresh token` | `key`, `namespace`, `secret` | oidc.go |
| info | `Registered ClusterConfig/Secret invalidation handlers` |  | watchers.go |
| info | `Rewriting loopback kubeconfig host to in-cluster DNS` | `original`, `replacement` | cache.go |
| info | `TOFU: Trusting API server certificate` | `apiServer`, `fingerprint`, `issuer`, `notAfter`, `notBefore`, `subject`† | oidc.go |
| info | `TOFU: captured CA for cluster` | `cluster` | oidc.go |
| info | `TOFU: captured and cached OIDC issuer CA` | `issuer` | oidc.go |
| info | `circuit breaker state changed` | `from`, `to` | circuitbreaker.go |
| warn | `Cached refresh token failed, trying next auth method` | `cluster`, `error`, `namespace` | oidc.go |
| warn | `Cluster CA secret key missing or empty; will attempt TOFU` | `cluster`, `key`, `secret` | oidc.go |
| warn | `Cluster is operating in degraded auth mode (using fallback credentials)` | `cluster`, `namespace` | oidc.go |
| warn | `Cluster operating in degraded auth mode` | `cluster`, `namespace` | oidc.go |
| warn | `Cluster operating in degraded auth mode (using fallback credentials)` | `cluster`, `error` | cache.go |
| warn | `Failed to persist TOFU CA to secret` | `cluster`, `error` | oidc.go |
| warn | `Failed to persist rotated refresh token (best-effort)` | `error`, `key`, `namespace`, `secret` | oidc.go |
| warn | `InsecureSkipTLSVerify enabled for cluster connection - NOT recommended for production` | `cluster` | oidc.go |
| warn | `Loaded pinned cluster CA from the legacy secret key; it will be migrated to the canonical key on the next TOFU write. Set caSecretRef.key explicitly to pin it.` | `canonicalKey`, `cluster`, `legacyKey`, `secret` | oidc.go |
| warn | `Refresh token failed, falling back to client_credentials with degraded warning (fallbackPolicy=Warn)` | `cluster`, `namespace` | oidc.go |
| warn | `Refresh token failed, silently falling back to client_credentials (fallbackPolicy=Auto)` | `cluster`, `namespace` | oidc.go |
| warn | `Refresh token from secret failed` | `cluster`, `error`, `namespace` | oidc.go |
| warn | `circuit breaker registry at capacity, returning always-closed sentinel` | `cluster`, `max`, `overflowCount` | circuitbreaker.go |
| warn | `invalid circuitBreaker failureThreshold, using default` | `default`, `value` | circuitbreaker.go |
| warn | `invalid circuitBreaker halfOpenMaxRequests, using default` | `default`, `value` | circuitbreaker.go |
| warn | `invalid circuitBreaker openDuration, using default` | `default`, `value` | circuitbreaker.go |
| warn | `invalid circuitBreaker successThreshold, using default` | `default`, `value` | circuitbreaker.go |
| error | `Refresh token failed and fallbackPolicy=None, cluster is unreachable` | `cluster`, `error`, `namespace` | oidc.go |
| error | `TOFU CA pin mismatch: refusing to re-pin a different CA for cluster` | `cluster`, `error`, `secret` | oidc.go |

#### `pkg/config`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Adding finalizer to ClusterConfig` | `cluster` | cluster_config_reconciler.go |
| debug | `AuditConfig is valid and enabled, including in aggregation` | `name`, `sinks` | audit_config_reconciler.go |
| debug | `AuditConfig is valid but disabled, skipping` | `name` | audit_config_reconciler.go |
| debug | `Conflict on status update retry, another controller likely handled it` | `name` | identity_provider_reconciler.go |
| debug | `Conflict updating IdentityProvider status, another controller likely handled it` | `name` | identity_provider_reconciler.go |
| debug | `Conflict updating status, another controller likely handled it` | `mailprovider` | mail_provider_reconciler.go |
| debug | `Converted MailProvider to runtime config` | `default`, `host`, `name`, `port` | mail_provider_loader.go |
| debug | `Converting IdentityProvider to runtime config` | `name` | identity_provider_loader.go |
| debug | `Empty IdentityProviderRefs - will accept all enabled providers` |  | identity_provider_loader.go |
| debug | `Found IdentityProvider by issuer` | `issuer`, `name` | identity_provider_loader.go |
| debug | `Found enabled IdentityProvider` | `name`, `primary` | identity_provider_loader.go |
| debug | `Found primary IdentityProvider` | `name` | identity_provider_loader.go |
| debug | `IdentityProvider created` | `name` | identity_provider_reconciler.go |
| debug | `IdentityProvider deleted` | `name` | identity_provider_reconciler.go |
| debug | `IdentityProvider deleted before status update, skipping` | `name` | identity_provider_reconciler.go |
| debug | `IdentityProvider spec changed` | `name`, `newGen`, `oldGen` | identity_provider_reconciler.go |
| debug | `IdentityProvider spec changed during reconcile, skipping stale status update` | `latestGeneration`, `name`, `preparedGeneration` | identity_provider_reconciler.go |
| debug | `IdentityProvider status recently updated, skipping status update` | `lastUpdateAge`, `name`, `skipReason` | identity_provider_reconciler.go |
| debug | `IdentityProviderRefs validation passed` |  | identity_provider_loader.go |
| debug | `Keycloak client secret loaded successfully` |  | identity_provider_loader.go |
| debug | `Listed IdentityProvider resources` | `count` | identity_provider_loader.go |
| debug | `Loaded IdentityProvider` | `displayName`, `name` | identity_provider_loader.go |
| debug | `Loaded enabled IdentityProviders` | `count` | identity_provider_loader.go |
| debug | `Loading IdentityProvider by issuer` | `issuer` | identity_provider_loader.go |
| debug | `Loading Keycloak client secret` | `secretKey`, `secretName` | identity_provider_loader.go |
| debug | `Loading all enabled IdentityProviders` |  | identity_provider_loader.go |
| debug | `Loading primary IdentityProvider resource` |  | identity_provider_loader.go |
| debug | `Loading specific IdentityProvider resource` | `name` | identity_provider_loader.go |
| debug | `MailProvider status recently updated, skipping` | `lastUpdateAge`, `mailprovider`, `skipReason` | mail_provider_reconciler.go |
| debug | `No group sync provider configured` |  | identity_provider_loader.go |
| debug | `No primary IdentityProvider found, looking for first enabled one` |  | identity_provider_loader.go |
| debug | `OIDC config loaded` | `authority`, `clientID`, `issuer` | identity_provider_loader.go |
| debug | `Performing SMTP health check` | `addr` | mail_provider_reconciler.go |
| debug | `Reconciling AuditConfig (will aggregate all configs)` | `trigger` | audit_config_reconciler.go |
| debug | `Reconciling BreakglassEscalation` | `name`, `namespace` | escalation_reconciler.go |
| debug | `Reconciling DebugPodTemplate` | `name` | debug_pod_template_reconciler.go |
| debug | `Reconciling DebugSessionClusterBinding` | `name`, `namespace` | debug_session_cluster_binding_reconciler.go |
| debug | `Reconciling DebugSessionTemplate` | `name` | debug_session_template_reconciler.go |
| debug | `Reconciling DenyPolicy` | `name` | deny_policy_reconciler.go |
| debug | `Reconciling MailProvider` |  | mail_provider_reconciler.go |
| debug | `STARTTLS not available or failed` | `error` | mail_provider_reconciler.go |
| debug | `STARTTLS not available or failed (insecure mode)` | `error` | mail_provider_reconciler.go |
| debug | `Setting up Keycloak group sync` | `baseURL`, `clientID`, `realm` | identity_provider_loader.go |
| debug | `Skipping disabled MailProvider` | `name` | mail_provider_loader.go |
| debug | `Successfully reconciled BreakglassEscalation` | `name`, `namespace` | escalation_reconciler.go |
| debug | `Successfully reconciled DebugPodTemplate` | `name`, `valid` | debug_pod_template_reconciler.go |
| debug | `Successfully reconciled DebugSessionClusterBinding` | `clusters`, `name`, `namespace`, `ready`, `templates` | debug_session_cluster_binding_reconciler.go |
| debug | `Successfully reconciled DebugSessionTemplate` | `name`, `valid` | debug_session_template_reconciler.go |
| debug | `Successfully reconciled DenyPolicy` | `name`, `valid` | deny_policy_reconciler.go |
| debug | `TLS disabled for SMTP connection, skipping STARTTLS` |  | mail_provider_reconciler.go |
| debug | `Updated IdentityProvider status to mark conversion failure` | `error`, `name` | identity_provider_loader.go |
| debug | `Using cluster-specific MailProvider` | `provider` | mail_provider_loader.go |
| debug | `Using default MailProvider` |  | mail_provider_loader.go |
| debug | `Using escalation-specific MailProvider` | `provider` | mail_provider_loader.go |
| debug | `Using first enabled IdentityProvider` | `name` | identity_provider_loader.go |
| debug | `Validating IdentityProvider configuration exists` |  | identity_provider_loader.go |
| debug | `Validating IdentityProviderRefs` | `count`, `refs` | identity_provider_loader.go |
| debug | `group sync provider health check passed` | `name`, `provider` | identity_provider_reconciler.go |
| debug | `reconciling identity provider` | `name`, `namespace` | identity_provider_reconciler.go |
| info | `AuditConfigs reconciled successfully (aggregated)` | `configNames`, `totalSinks`, `validConfigs` | audit_config_reconciler.go |
| info | `Cleared MailProvider from cache` | `provider` | mail_provider_loader.go |
| info | `Cleared entire MailProvider cache` |  | mail_provider_loader.go |
| info | `ClusterConfig cleanup complete, finalizer removed` | `cluster` | cluster_config_reconciler.go |
| info | `ClusterConfig is being deleted, cleaning up sessions` | `cluster` | cluster_config_reconciler.go |
| info | `Finalizer added to ClusterConfig` | `cluster` | cluster_config_reconciler.go |
| info | `Health check passed` |  | mail_provider_reconciler.go |
| info | `Loaded MailProviders` | `count`, `default` | mail_provider_loader.go |
| info | `MailProvider deleted, invalidating cache` |  | mail_provider_reconciler.go |
| info | `Terminated BreakglassSessions for deleted cluster` | `cluster`, `count` | cluster_config_reconciler.go |
| info | `Terminated DebugSessions for deleted cluster` | `cluster`, `count` | cluster_config_reconciler.go |
| info | `Terminating BreakglassSession due to cluster deletion` | `cluster`, `namespace`, `previousState`, `session` | cluster_config_reconciler.go |
| info | `Terminating DebugSession due to cluster deletion` | `cluster`, `namespace`, `previousState`, `session` | cluster_config_reconciler.go |
| info | `group sync provider recovered to healthy state` | `name`, `provider` | identity_provider_reconciler.go |
| info | `identity provider configuration reloaded successfully` | `name` | identity_provider_reconciler.go |
| info | `identity provider deleted` | `name` | identity_provider_reconciler.go |
| info | `setting up IdentityProvider reconciler` | `kind`, `resyncPeriod` | identity_provider_reconciler.go |
| warn | `All IdentityProvider resources are disabled - session/escalation features will be limited` |  | identity_provider_loader.go |
| warn | `AuditConfig failed structural validation` | `errors`, `name` | audit_config_reconciler.go |
| warn | `AuditConfig validation failed, skipping` | `errors`, `name` | audit_config_reconciler.go |
| warn | `BreakglassEscalation failed structural validation` | `errors`, `name` | escalation_reconciler.go |
| warn | `DebugPodTemplate validation failed` | `errors`, `template` | debug_pod_template_reconciler.go |
| warn | `DenyPolicy validation failed` | `error`, `policy` | deny_policy_reconciler.go |
| warn | `Escalation validation failed` | `conditionType`, `error`, `escalation` | escalation_reconciler.go |
| warn | `Failed to convert IdentityProvider, skipping` | `displayName`, `error`, `name`, `namespace` | identity_provider_loader.go |
| warn | `Failed to fetch BreakglassEscalation for validation` | `error` | escalation_reconciler.go |
| warn | `Failed to fetch DebugPodTemplate` | `error` | debug_pod_template_reconciler.go |
| warn | `Failed to fetch DebugSessionTemplate` | `error` | debug_session_template_reconciler.go |
| warn | `Failed to fetch DenyPolicy` | `error` | deny_policy_reconciler.go |
| warn | `Failed to list BreakglassEscalations for dependency change` | `dependencyKind`, `dependencyName`, `error` | escalation_reconciler.go |
| warn | `Failed to list DebugSessionClusterBindings by cluster reference` | `cluster`, `clusterNamespace`, `error` | debug_session_cluster_binding_reconciler.go |
| warn | `Failed to list DebugSessionClusterBindings by template reference` | `error`, `template` | debug_session_cluster_binding_reconciler.go |
| warn | `Failed to list DebugSessionClusterBindings for cluster selector mapping` | `cluster`, `clusterNamespace`, `error` | debug_session_cluster_binding_reconciler.go |
| warn | `Failed to list DebugSessionClusterBindings for cluster watch mapping` | `cluster`, `clusterNamespace`, `error` | debug_session_template_reconciler.go |
| warn | `Failed to list DebugSessionClusterBindings for template selector mapping` | `error`, `template` | debug_session_cluster_binding_reconciler.go |
| warn | `Failed to list DebugSessionTemplates for binding watch mapping` | `binding`, `error`, `namespace` | debug_session_template_reconciler.go |
| warn | `Failed to load SMTP password` | `error` | mail_provider_reconciler.go |
| warn | `Failed to load cluster-specific MailProvider, falling back to default` | `error`, `provider` | mail_provider_loader.go |
| warn | `Failed to load escalation-specific MailProvider, falling back` | `error`, `provider` | mail_provider_loader.go |
| warn | `Failed to parse CA certificate` |  | mail_provider_reconciler.go |
| warn | `Failed to resolve DebugSessionTemplate binding status` | `error`, `template` | debug_session_template_reconciler.go |
| warn | `Failed to terminate BreakglassSession` | `error`, `session` | cluster_config_reconciler.go |
| warn | `Failed to terminate DebugSession` | `error`, `session` | cluster_config_reconciler.go |
| warn | `Failed to update DebugPodTemplate status` | `error`, `template` | debug_pod_template_reconciler.go |
| warn | `Failed to update DebugSessionClusterBinding status` | `error`, `name`, `namespace` | debug_session_cluster_binding_reconciler.go |
| warn | `Failed to update DebugSessionTemplate status` | `error`, `template` | debug_session_template_reconciler.go |
| warn | `Failed to update DenyPolicy status` | `error`, `policy` | deny_policy_reconciler.go |
| warn | `Failed to update IdentityProvider status on conversion failure` | `conversionError`, `name`, `updateError` | identity_provider_loader.go |
| warn | `Failed to update escalation status with success state` | `error`, `escalation` | escalation_reconciler.go |
| warn | `Failed to update escalation status with validation errors` | `error`, `escalation` | escalation_reconciler.go |
| warn | `Health check timeout` |  | mail_provider_reconciler.go |
| warn | `IdentityProvider failed structural validation, skipping reconciliation` | `errors`, `name` | identity_provider_reconciler.go |
| warn | `IdentityProvider not found - controller will start with limited functionality` | `error`, `note` | identity_provider_loader.go |
| warn | `MailProvider failed structural validation, skipping reconciliation` | `errors` | mail_provider_reconciler.go |
| warn | `MailProvider has DisableTLS enabled (insecure for production)` | `provider` | mail_provider_reconciler.go |
| warn | `MailProvider has InsecureSkipVerify enabled (insecure for production)` | `provider` | mail_provider_reconciler.go |
| warn | `Multiple default MailProviders found` | `count` | mail_provider_loader.go |
| warn | `No IdentityProvider found for issuer` | `issuer` | identity_provider_loader.go |
| warn | `No IdentityProvider resources found - session/escalation features will be limited until one is created` |  | identity_provider_loader.go |
| warn | `No Keycloak client secret configured` |  | identity_provider_loader.go |
| warn | `No default MailProvider found` |  | mail_provider_loader.go |
| warn | `SMTP authentication failed` | `error` | mail_provider_reconciler.go |
| warn | `SMTP client creation failed` | `error` | mail_provider_reconciler.go |
| warn | `SMTP connection failed` | `error` | mail_provider_reconciler.go |
| warn | `Skipping binding with invalid cluster selector during watch mapping` | `binding`, `error`, `namespace` | debug_session_cluster_binding_reconciler.go |
| warn | `Skipping binding with invalid template selector during watch mapping` | `binding`, `error`, `namespace` | debug_session_cluster_binding_reconciler.go |
| warn | `Unknown group sync provider configured` | `provider` | identity_provider_loader.go |
| warn | `group sync provider health check failed` | `error`, `name`, `provider`, `reason` | identity_provider_reconciler.go |
| error | `Failed to add finalizer to ClusterConfig` | `cluster`, `error` | cluster_config_reconciler.go |
| error | `Failed to convert MailProvider` | `error`, `name` | mail_provider_loader.go |
| error | `Failed to convert MailProvider to runtime config` | `error`, `name` | mail_provider_loader.go |
| error | `Failed to get ClusterConfig` | `error` | cluster_config_reconciler.go |
| error | `Failed to get IdentityProvider` | `error`, `name` | identity_provider_loader.go |
| error | `Failed to get MailProvider` | `error`, `name` | mail_provider_loader.go, mail_provider_reconciler.go |
| error | `Failed to list AuditConfigs` | `error` | audit_config_reconciler.go |
| error | `Failed to list IdentityProvider resources` | `error` | identity_provider_loader.go |
| error | `Failed to list IdentityProvider resources during validation` | `error` | identity_provider_loader.go |
| error | `Failed to list MailProvider resources` | `error` | mail_provider_loader.go |
| error | `Failed to load Keycloak client secret` | `error` | identity_provider_loader.go |
| error | `Failed to load SMTP password from secret` | `error`, `name` | mail_provider_loader.go |
| error | `Failed to re-fetch IdentityProvider for status update` | `error`, `name` | identity_provider_reconciler.go |
| error | `Failed to re-fetch MailProvider for status update` | `error`, `mailprovider` | mail_provider_reconciler.go |
| error | `Failed to record audit reload failure` | `error`, `name` | audit_config_reconciler.go |
| error | `Failed to reload audit configuration with aggregated configs` | `configCount`, `error` | audit_config_reconciler.go |
| error | `Failed to remove finalizer from ClusterConfig` | `cluster`, `error` | cluster_config_reconciler.go |
| error | `Failed to terminate BreakglassSessions for cluster` | `cluster`, `error` | cluster_config_reconciler.go |
| error | `Failed to terminate DebugSessions for cluster` | `cluster`, `error` | cluster_config_reconciler.go |
| error | `Failed to update AuditConfig status` | `error`, `name` | audit_config_reconciler.go |
| error | `Failed to update MailProvider status after validation failure` | `error` | mail_provider_reconciler.go |
| error | `Failed to update status` | `error`, `mailprovider` | mail_provider_reconciler.go |
| error | `IdentityProviderRefs validation failed - providers not found or disabled` | `missing` | identity_provider_loader.go |
| error | `No IdentityProvider resources found - this is a required configuration` |  | identity_provider_loader.go |
| error | `No enabled IdentityProvider resources found - IdentityProvider configuration is MANDATORY` |  | identity_provider_loader.go |
| error | `Some IdentityProviders were skipped due to conversion errors - users may be unable to authenticate with these providers` | `count`, `skipped_idps` | identity_provider_loader.go |
| error | `failed to fetch identity provider` | `error`, `name` | identity_provider_reconciler.go |
| error | `failed to get enabled identity providers` | `error` | identity_provider_reconciler.go |
| error | `failed to get escalation IDP mapping` | `error` | escalation_reconciler.go |
| error | `failed to list escalations for IDP mapping` | `error` | escalation_reconciler.go |
| error | `failed to list identity providers` | `error` | identity_provider_reconciler.go |
| error | `failed to reload identity provider` | `error`, `name` | identity_provider_reconciler.go |
| error | `failed to update IdentityProvider status after successful reload (will retry)` | `error`, `name` | identity_provider_reconciler.go |
| error | `failed to update error status on IdentityProvider (will retry via exponential backoff)` | `error`, `name` | identity_provider_reconciler.go |
| error | `failed to update identity provider status after reload failure` | `error`, `name` | identity_provider_reconciler.go |
| error | `failed to update identity provider status after validation failure` | `error`, `name` | identity_provider_reconciler.go |
| error | `onReload callback failed` | `error` | escalation_reconciler.go |

#### `pkg/indexer`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Registered field index` | `field` | indexer.go |
| info | `All field indexes registered successfully` | `count` | indexer.go |
| warn | `Field indexer not available from manager` |  | indexer.go |

#### `pkg/leaderelection`

| Level | Message | Fields | File |
|---|---|---|---|
| info | `I became the leader` | `identity`† | leaderelection.go |
| info | `Leader election stopped; retrying leadership acquisition` | `id`, `identity`†, `namespace` | leaderelection.go |
| info | `Lost leadership` |  | leaderelection.go |
| info | `New leader elected` | `identity`† | leaderelection.go |
| info | `Starting leader election` | `id`, `identity`†, `namespace` | leaderelection.go |
| info | `This replica acquired leadership, signaling background loops` |  | leaderelection.go |
| error | `Failed to create LeaderElector` | `error` | leaderelection.go |

#### `pkg/mail`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Email queued for sending` | `id`, `receivers`, `subjectLength`† | queue.go |
| debug | `Preparing to send mail` | `recipientCount`†, `subjectLength`† | mail.go |
| info | `Attempting final send for pending item before shutdown` | `attempt`, `id` | queue.go |
| info | `Initializing mail queue` | `initialBackoffMs`, `maxAttempts`, `maxQueueSize`, `maxRetries` | queue.go |
| info | `Initializing mail sender from MailProvider` | `disableTLS`, `host`, `port`, `provider` | mail.go |
| info | `Loading mail provider` | `host`, `port`, `provider` | service.go |
| info | `Mail queue initialized and started` | `provider`, `queueSize`, `retryBackoffMs`, `retryCount` | mail.go, service.go |
| info | `Mail queue stopped gracefully` |  | queue.go |
| info | `Mail queue worker shutting down` |  | queue.go |
| info | `Mail queue worker started` |  | queue.go |
| info | `Mail sent successfully` | `recipientCount`† | mail.go |
| info | `Processing pending items on shutdown` | `count` | queue.go |
| info | `Processing queued email` | `attempt`, `id`, `maxAttempts`, `receivers` | queue.go |
| info | `Queued email sent successfully` | `attempt`, `id`, `receivers`, `subjectLength`† | queue.go |
| info | `Stopping existing mail queue for reload` |  | service.go |
| info | `Stopping mail queue` |  | queue.go |
| info | `Stopping mail service` |  | service.go |
| info | `Using default mail provider from cluster` | `host`, `port`, `provider` | mail.go |
| warn | `Email send failed, scheduling retry` | `attempt`, `error`, `id`, `nextRetry`, `retryIn` | queue.go |
| warn | `Error stopping mail queue during reload` | `error` | service.go |
| warn | `InsecureSkipVerify is enabled for mail TLS connection - not recommended for production` |  | mail.go |
| warn | `Mail queue not initialized, rejecting email` | `recipients`†, `sessionID` | service.go |
| warn | `Mail queue shutdown timeout, some items may not have been processed` |  | queue.go |
| warn | `No default mail provider found - mail notifications disabled` | `error` | service.go |
| error | `Cannot enqueue email: empty receivers list` | `id`, `recipientCount`†, `subjectLength`† | queue.go |
| error | `Cannot enqueue, queue is shutting down` | `id` | queue.go |
| error | `Email send failed after all retries` | `attempts`, `error`, `id`, `recipientCount`†, `subjectLength`† | queue.go |
| error | `Failed to send mail` | `error` | mail.go |
| error | `Mail queue is full, dropping message` | `id`, `queueSize`, `receivers` | queue.go |
| error | `Send called with no receivers` | `subjectLength`† | mail.go |
| error | `mail queue worker exceeded max consecutive panic recoveries, stopping queue` | `maxRecoveries` | queue.go |
| error | `panic in mail queue worker recovered` | `consecutivePanics`, `panic` | queue.go |

#### `pkg/policy`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Blocked factor exempted by escalation override` | `factor`, `pod` | deny.go |
| debug | `Pod exempt from security evaluation` | `namespace`, `pod` | deny.go |
| debug | `Pod security overrides not applicable: namespace not in scope` | `namespace`, `namespaceScope`, `pod` | deny.go |
| info | `Impersonation denied by DenyPolicy` | `cluster`, `identity`†, `identityResource`†, `mode`, `policy`, `ruleIndex`, `verb`, `verbKind` | impersonation.go |
| info | `Pod access allowed via escalation override` | `factors`, `maxAllowed`, `namespace`, `pod`, `score` | deny.go |
| warn | `Failed to parse reason template` | `error`, `template` | deny.go |
| warn | `Failed to render reason template` | `error` | deny.go |
| warn | `High-risk pod access allowed (warn threshold)` | `cluster`, `factors`, `namespace`, `pod`, `reason`, `score` | deny.go |
| warn | `Pod security evaluation skipped: pod spec unavailable (fail-open)` | `cluster`, `name`, `namespace` | deny.go |

#### `pkg/reconciler`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Setting up AuditConfig reconciler` |  | reconciler.go |
| debug | `Setting up BreakglassEscalation reconciler` |  | reconciler.go |
| debug | `Setting up ClusterConfig reconciler` |  | reconciler.go |
| debug | `Setting up DebugPodTemplate reconciler` |  | reconciler.go |
| debug | `Setting up DebugSession reconciler` |  | reconciler.go |
| debug | `Setting up DebugSessionClusterBinding reconciler` |  | reconciler.go |
| debug | `Setting up DebugSessionTemplate reconciler` |  | reconciler.go |
| debug | `Setting up DenyPolicy reconciler` |  | reconciler.go |
| debug | `Setting up IdentityProvider reconciler` |  | reconciler.go |
| debug | `Setting up MailProvider reconciler` |  | reconciler.go |
| info | `AuditConfigs reloaded (aggregated)` | `configs`, `totalSinks` | reconciler.go |
| info | `Health check handlers registered` |  | reconciler.go |
| info | `Initializing metrics certificate watcher using provided certificates` | `metrics-cert-key`, `metrics-cert-name`, `metrics-cert-path` | reconciler.go |
| info | `MailProvider changed, reloading mail service` | `provider` | reconciler.go |
| info | `No enabled AuditConfigs found - audit logging stopped` |  | reconciler.go |
| info | `Reconcilers disabled via --enable-controllers=false` |  | reconciler.go |
| info | `Starting controller-runtime reconciler manager (no leader election at manager level)` |  | reconciler.go |
| info | `Successfully registered AuditConfig reconciler` | `resyncPeriod` | reconciler.go |
| info | `Successfully registered BreakglassEscalation reconciler` | `resyncPeriod` | reconciler.go |
| info | `Successfully registered ClusterConfig reconciler` |  | reconciler.go |
| info | `Successfully registered DebugPodTemplate reconciler` |  | reconciler.go |
| info | `Successfully registered DebugSession reconciler` |  | reconciler.go |
| info | `Successfully registered DebugSessionArtifact reconciler` |  | reconciler.go |
| info | `Successfully registered DebugSessionClusterBinding reconciler` |  | reconciler.go |
| info | `Successfully registered DebugSessionTemplate reconciler` |  | reconciler.go |
| info | `Successfully registered DenyPolicy reconciler` |  | reconciler.go |
| info | `Successfully registered HotfixRecord reconciler` |  | reconciler.go |
| info | `Successfully registered IdentityProvider reconciler` | `resyncPeriod` | reconciler.go |
| info | `Successfully registered MailProvider reconciler` |  | reconciler.go |
| info | `Updated EscalationManager resolver after IdentityProvider change` |  | reconciler.go |
| warn | `AuditConfig changed but audit service is nil - skipping reload` |  | reconciler.go |
| warn | `Failed to load IdentityProvider config for resolver update` | `error` | reconciler.go |
| warn | `Failed to reload mail service after MailProvider change` | `error` | reconciler.go |
| error | `AuditConfig reconciliation error` | `error` | reconciler.go |
| error | `BreakglassEscalation reconciliation error` | `error` | reconciler.go |
| error | `Failed to reload audit service` | `error` | reconciler.go |
| error | `IdentityProvider reconciliation error` | `error` | reconciler.go |

#### `pkg/system`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Request token groups` | `groups`† | logging.go |

#### `pkg/telemetry`

| Level | Message | Fields | File |
|---|---|---|---|
| info | `OTel OTLP exporter initialized` | `endpoint`, `insecure` | telemetry.go |
| info | `OTel stdout exporter initialized` |  | telemetry.go |
| info | `OTel tracing enabled with no exporter` | `note` | telemetry.go |
| info | `OpenTelemetry tracing initialized` | `exporter`, `samplingRate`, `serviceName` | telemetry.go |
| info | `Shutting down OpenTelemetry TracerProvider` |  | telemetry.go |
| warn | `OTel sampling rate < 0, clamping to 1.0 (sample everything)` | `provided` | telemetry.go |
| warn | `OTel sampling rate > 1.0, clamping to 1.0 (sample everything)` | `provided` | telemetry.go |
| warn | `OpenTelemetry internal error` | `error` | telemetry.go |

#### `pkg/utils`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Object unchanged, skipping SSA apply` | `kind`, `name`, `namespace` | patchhelper.go |
| debug | `Unstructured object unchanged, skipping SSA apply` | `kind`, `name`, `namespace` | patchhelper.go |
| warn | `Invalid … in spec; falling back to default` | `default`, `error`, `value` | duration_helpers.go |
| warn | `Non-positive … in spec; falling back to default` | `default`, `parsedDuration`, `value` | duration_helpers.go |
| warn | `SSA apply conflict` | `error`, `kind`, `name`, `namespace` | patchhelper.go |

#### `pkg/webhook`

| Level | Message | Fields | File |
|---|---|---|---|
| debug | `Authorization decision` | `allowed`, `reason`, `sessionCount`, `source` | authorize_helpers.go |
| debug | `Authorization handler completed successfully` |  | authorize_helpers.go |
| debug | `Authorized via breakglass session group on target cluster` | `impersonationGroup`†, `session`, `sessionGroup`† | authorize_helpers.go |
| debug | `Available escalation paths for user` | `escalationCount` | authorize_helpers.go |
| debug | `Creating SubjectAccessReview for session impersonation` | `group`†, `session` | controller.go |
| debug | `Debug session check skipped: no client available` |  | controller.go |
| debug | `Debug session discovery candidate disappeared before live fence` | `error`, `session` | controller.go |
| debug | `Debug session found but operation not allowed` | `operation`, `pod`, `session` | controller.go |
| debug | `Debug session participant role cannot perform pod operation` | `operation`, `role`, `session`, `user`† | controller.go |
| debug | `Debug session skipped because it is expired, idle, or missing expiry` | `expiresAt`, `session` | controller.go |
| debug | `Direct debug-session pod operation denied because recording is required` | `operation`, `session` | controller.go |
| debug | `Escalation lookup groups` | `cluster`, `sarGroupCount`†, `sessionGroupCount`†, `totalUniqueGroupCount`† | authorize_helpers.go |
| debug | `Escalation paths available` | `count` | authorize_helpers.go |
| debug | `Escalations filtered by requestor IDP` | `afterFilter`, `beforeFilter`, `issuer` | authorize_helpers.go |
| debug | `Extracted issuer from SAR for session matching` | `issuer` | authorize_helpers.go |
| debug | `Extracting IDP hint from issuer` | `issuer` | controller.go |
| debug | `Failed SAR create error details` | `error`, `group`†, `hasNonResourceAttributes`, `hasResourceAttributes` | controller.go |
| debug | `Failed to fetch namespace labels for DenyPolicy evaluation` | `error`, `namespace` | authorize_helpers.go |
| debug | `Failed to fetch namespace labels for impersonation DenyPolicy evaluation` | `error`, `namespace` | authorize_impersonation.go |
| debug | `Failed to lookup escalation for PodSecurityOverrides` | `error`, `escalation`, `session` | controller.go |
| debug | `Fetched pod for security evaluation` | `namespace`, `pod` | authorize_helpers.go |
| debug | `Flushed session activity` | `requeued`, `sessions` | activity_tracker.go |
| debug | `Found PodSecurityOverrides from escalation` | `escalation`, `exemptFactors`, `maxAllowedScore`, `session` | controller.go |
| debug | `Global denyEval matched` | `action`, `policy` | authorize_helpers.go |
| debug | `Ignoring PodSecurityOverrides for owner reference with mismatched UID` | `escalation`, `escalationUID`, `ownerUID`, `session` | controller.go |
| debug | `Ignoring PodSecurityOverrides without configured additional approval` | `escalation`, `session` | controller.go |
| debug | `Impersonation groups to try` | `groupCount`†, `session` | controller.go |
| debug | `Invoking RBAC canDoFn` | `cluster`, `groupCount`†, `resourceAttributes` | authorize_helpers.go |
| debug | `No escalation allowed groups found; falling back to session granted group for prefix detection` | `session`, `sessionGroup`† | controller.go |
| debug | `No escalation paths for user` | `username`† | authorize_helpers.go |
| debug | `Parsed webhook bind address` | `bindAddress`, `host`, `port` | manager.go |
| debug | `Processing authorization request for cluster` | `cluster` | authorize_helpers.go |
| debug | `RBAC check result` | `allowed`, `groupCount`† | authorize_helpers.go |
| debug | `Received SubjectAccessReview` |  | authorize_helpers.go |
| debug | `Request allowed: IDP in AllowedIdentityProvidersForRequests` | `escalation`, `idp` | controller.go |
| debug | `Request denied: IDP not in allowed request providers` | `allowedIDPs`, `escalation`, `idp` | controller.go |
| debug | `Request from unknown or disabled IDP issuer` | `escalation`, `issuer` | controller.go |
| debug | `Request issuer matches multiple enabled IdentityProviders; denying request` | `first`, `issuer`, `second` | controller.go |
| debug | `Request missing issuer information required for multi-IDP validation` | `escalation` | controller.go |
| debug | `Retrieved group-specific escalations` | `escalationsCount` | authorize_helpers.go |
| debug | `Retrieved target group escalations` | `groupEscalationsCount`† | authorize_helpers.go |
| debug | `Retrieved user groups for cluster` | `groupCount`†, `idpMismatches`, `sessions`, `tenant` | authorize_helpers.go |
| debug | `Retrieved user groups from active sessions` | `activeUserGroupCount`† | authorize_helpers.go |
| debug | `Returning SubjectAccessReview response (raw)` | `body` | authorize_helpers.go |
| debug | `SAR phase completed` | `duration_ms`, `phase` | phase_tracker.go |
| debug | `Sending JSON response via c.JSON` |  | authorize_helpers.go |
| debug | `Session SAR response` | `allowed`, `group`†, `reason`, `session` | controller.go |
| debug | `Session denyEval matched` | `action`, `policy`, `session` | authorize_helpers.go |
| debug | `Starting webhook registration for %s` |  | manager.go |
| debug | `Starting webhook server setup` |  | manager.go |
| debug | `SubjectAccessReview request received` | `bodySize` | authorize_helpers.go |
| debug | `Total available escalation paths` | `totalEscalations` | authorize_helpers.go |
| debug | `User not authorized through regular RBAC, checking for breakglass escalations` |  | authorize_helpers.go |
| debug | `Using live debug session discovery after empty cache result` | `count` | controller.go |
| debug | `Webhook controller routes registered successfully` |  | controller.go |
| debug | `failed to fetch namespace labels for audit event filtering` | `cluster`, `error`, `namespace` | controller.go |
| debug | `failed to lookup escalation for session ownerRef` | `error`, `ownerRef`, `session` | controller.go |
| debug | `final cluster configuration fence denied session access` | `cluster`, `error` | controller.go |
| debug | `final session access fence could not read session` | `error`, `session` | controller.go |
| debug | `handleAuthorize entered` | `cluster` | authorize_helpers.go |
| info | (dynamic) | `cluster`, `impersonationConstraint`, `mode`, `requestor`, `requestorUID`, `source`, `verb` | authorize_impersonation.go |
| info | `Active sessions present but unable to validate them against target cluster` | `error`, `sessionCount`, `sessionDetails` | authorize_helpers.go |
| info | `Cert-controller will generate certs in %q` |  | manager.go |
| info | `Configuring separate metrics server for webhooks` | `address`, `secure` | manager.go |
| info | `Debug session authorizing pod operation (bypassing deny policies)` | `namespace`, `operation`, `pod`, `session` | authorize_helpers.go |
| info | `Debug session pod operation allowed` | `operation`, `pod`, `role`, `session`, `user`† | controller.go |
| info | `Failed to get REST config for standard RBAC check; using legacy fallback` | `error` | authorize_helpers.go |
| info | `Final accepted impersonated group` | `cluster`, `impersonationGroup`†, `session`, `sessionGroup`†, `username`† | authorize_helpers.go |
| info | `Impersonation DENIED` | `cluster`, `mode`, `reason`, `requestor`, `requestorUID`, `source`, `verb`, `verbKind` | authorize_impersonation.go |
| info | `Initializing webhook certificate watcher using provided certificates` | `webhook-cert-key`, `webhook-cert-name`, `webhook-cert-path` | manager.go |
| info | `Initializing webhook metrics certificate watcher using generated certificates` | `path`, `webhooks-metrics-cert-key`, `webhooks-metrics-cert-name` | manager.go |
| info | `Initializing webhook metrics certificate watcher using provided certificates` | `webhooks-metrics-cert-key`, `webhooks-metrics-cert-name`, `webhooks-metrics-cert-path` | manager.go |
| info | `No webhook certificate path provided - cert-controller will generate certs in default directory %q` |  | manager.go |
| info | `Processing authorization` | `groupsRequestedCount`†, `username`† | authorize_helpers.go |
| info | `Pruned orphaned activity tracker entries` | `pruned`, `remaining` | activity_tracker.go |
| info | `Registering webhook controller routes` | `path` | controller.go |
| info | `Request denied by global/cluster DenyPolicy` | `activeSessions`, `apiGroup`†, `cluster`, `namespace`, `policy`, `resource`, `resourceName`, `subresource`, `tenant`, `username`†, `verb` | authorize_helpers.go |
| info | `Request denied by session-scoped DenyPolicy` | `apiGroup`†, `cluster`, `namespace`, `policy`, `resource`, `resourceName`, `session`, `sessionGroup`†, `subresource`, `username`†, `verb` | authorize_helpers.go |
| info | `SAR processing timing summary` | `cluster`, `timings_ms` | phase_tracker.go |
| info | `SAR request DENIED - summary` | `details`, `finalReason` | authorize_helpers.go |
| info | `Starting webhook manager` | `bindAddress` | manager.go |
| info | `SubjectAccessReview concerns impersonation` | `cluster`, `extraKey`, `identityName`†, `identityNamespace`†, `identityResource`†, `mode`, `requestor`, `requestorUID`, `verb`, `verbKind` | authorize_impersonation.go |
| info | `SubjectAccessReview contains no resource or non-resource attributes` |  | authorize_helpers.go |
| info | `SubjectAccessReview processed` | `allowed`, `cluster`, `reason`, `response`, `username`† | authorize_helpers.go |
| info | `SubjectAccessReview requested action` | `action`, `apiGroup`†, `name`, `namespace`, `resource`, `subresource`, `verb` | authorize_helpers.go |
| info | `SubjectAccessReview requested non-resource action` | `action`, `path`, `verb` | authorize_helpers.go |
| info | `Successfully registered %s webhook` |  | manager.go |
| info | `User authorized through regular RBAC permissions` |  | authorize_helpers.go |
| info | `User has valid sessions but from different identity provider` | `currentIssuer`, `sessionIDPs`, `sessionsWithMismatch` | authorize_helpers.go |
| info | `Validating webhooks disabled via --enable-validating-webhooks=false` |  | manager.go |
| info | `Webhook health check handlers registered` |  | manager.go |
| info | `Webhook metrics will use default metrics endpoint; to use separate metrics, set --webhooks-metrics-bind-address` |  | manager.go |
| info | `Webhook server created successfully` |  | manager.go |
| info | `webhook server exited normally (this should not happen during normal operation)` |  | manager.go |
| warn | `ActivityTracker at capacity, evicting oldest entry to make room` | `evicted`, `maxEntries`, `newSession` | activity_tracker.go |
| warn | `Cluster not registered for Breakglass` | `cluster` | authorize_helpers.go |
| warn | `Effective issuer index unavailable; using compatibility lookup` | `error` | controller.go |
| warn | `Failed to fetch pod for security evaluation` | `error`, `namespace`, `pod` | authorize_helpers.go |
| warn | `Failed to list IdentityProviders for IDP hint` | `error` | controller.go |
| warn | `Failed to list debug sessions for pod operation check` | `error` | controller.go |
| warn | `Failed to list debug sessions through live reader for pod operation check` | `error` | controller.go |
| warn | `Failed to parse webhook port from bind address; using default` | `bindAddress`, `defaultPort`, `error` | manager.go |
| warn | `Failed to update session activity` | `error`, `retries`, `session` | activity_tracker.go |
| warn | Legacy (unconstrained) impersonation in use; the API server does not apply the constrained restrictions to this path and any blanket `impersonate` grant defeats configured constraints | `cluster`, `identityName`†, `identityResource`†, `requestor` | authorize_impersonation.go |
| warn | `RBAC check failed (infrastructure unavailable or forbidden); treating as denied and falling through to session-based authorization` | `error` | authorize_helpers.go |
| warn | `Shutdown context expired waiting for flush goroutine` | `error` | activity_tracker.go |
| warn | `SubjectAccessReview body too large` | `error` | authorize_helpers.go |
| warn | `Unable to load target cluster rest.Config for SAR; skipping session SAR checks` | `error` | authorize_helpers.go |
| warn | `Unrecognised impersonation verb allowed to proceed because denyUnrecognisedVerbs is disabled on this ClusterConfig; constrained impersonation may be granted without breakglass evaluation` | `cluster`, `verb` | authorize_impersonation.go |
| warn | `session SAR error` | `error`, `group`† | controller.go |
| error | `Discarding activity entry after max retries` | `count`, `retries`, `session` | activity_tracker.go |
| error | `Failed to count escalations for deny response` | `error` | authorize_helpers.go |
| error | `Failed to decode SubjectAccessReview body` | `bodySize`, `error` | authorize_helpers.go |
| error | `Failed to list IdentityProviders for request validation - denying request (fail-closed)` | `error` | controller.go |
| error | `Failed to load ClusterConfig for SAR validation` | `error` | authorize_helpers.go |
| error | `Failed to marshal SubjectAccessReview response for debug logging` | `error` | authorize_helpers.go |
| error | `Failed to read request body for SubjectAccessReview` | `error` | authorize_helpers.go |
| error | `Failed to retrieve group escalations` | `error` | authorize_helpers.go |
| error | `Failed to retrieve target group escalations` | `error` | authorize_helpers.go |
| error | `Failed to retrieve user groups for cluster` | `error` | authorize_helpers.go |
| error | `Impersonation DenyPolicy evaluation failed; denying fail-closed` | `cluster`, `error`, `scope` | authorize_impersonation.go |
| error | `RBAC canDoFn error` | `error` | authorize_helpers.go |
| error | `deny evaluation error` | `action`, `error` | authorize_helpers.go |
| error | `deny evaluation error for session` | `action`, `error`, `session` | authorize_helpers.go |
| error | `deny policy evaluation failed closed` | `action`, `error`, `scope` | authorize_helpers.go |
| error | `failed creating clientset for session SAR` | `error` | controller.go |

<!-- END GENERATED -->
