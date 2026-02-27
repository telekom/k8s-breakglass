<!-- SPDX-FileCopyrightText: 2025 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# OpenTelemetry Tracing

The breakglass controller supports [OpenTelemetry](https://opentelemetry.io/) distributed tracing.
When enabled, every HTTP request handled by the Gin server produces a trace span, and you can correlate
authorization decisions, session lifecycle events, and API calls across services.

## Quick Start

```bash
# Enable with CLI flags
breakglass-controller \
  --otel-enabled \
  --otel-exporter=otlp \
  --otel-endpoint=otel-collector:4317 \
  --otel-insecure
```

Or via environment variables:

```bash
OTEL_ENABLED=true
OTEL_EXPORTER=otlp
OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector:4317
OTEL_INSECURE=true
OTEL_SAMPLING_RATE=0.1
```

Or via `config.yaml`:

```yaml
telemetry:
  enabled: true
  exporter: otlp          # otlp | stdout | none
  endpoint: otel-collector:4317
  insecure: false
  samplingRate: 0.1        # 0.0–1.0 (1.0 = sample everything)
```

## Configuration Reference

| CLI Flag | Env Var | Config Key | Default | Description |
|---|---|---|---|---|
| `--otel-enabled` | `OTEL_ENABLED` | `telemetry.enabled` | `false` | Enable tracing |
| `--otel-exporter` | `OTEL_EXPORTER` | `telemetry.exporter` | `otlp` | Exporter type |
| `--otel-endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | `telemetry.endpoint` | `localhost:4317` | Collector address |
| `--otel-insecure` | `OTEL_INSECURE` | `telemetry.insecure` | `false` | Disable TLS |
| `--otel-sampling-rate` | `OTEL_SAMPLING_RATE` | `telemetry.samplingRate` | `1.0` | Sampling probability |

**Precedence:** CLI flags > environment variables > config file.
For boolean flags (`--otel-enabled`, `--otel-insecure`), setting any source to
`true` enables the feature (logical OR). To guarantee TLS is required, ensure
all three sources leave `insecure` as `false`.

## Exporters

### OTLP (default)
Sends spans via gRPC to an OpenTelemetry Collector.

```yaml
telemetry:
  enabled: true
  exporter: otlp
  endpoint: otel-collector.monitoring:4317
  insecure: false
```

### Stdout
Writes spans as pretty-printed JSON to stdout. Useful for development/debugging.

```yaml
telemetry:
  enabled: true
  exporter: stdout
```

### None
Creates real spans in-process but does not export them. Useful for integration tests
that want to assert span attributes without an external collector.

```yaml
telemetry:
  enabled: true
  exporter: none
```

## Sampling

The `samplingRate` controls the probability of tracing a request:

| Value | Behaviour |
|---|---|
| `1.0` | Sample every request (development default) |
| `0.1` | Sample ~10% of requests (recommended for production) |
| `0.01` | Sample ~1% of requests (high-traffic production) |

The sampler is `ParentBased(TraceIDRatioBased(rate))`, meaning child spans
inherit the parent's sampling decision — ensuring complete traces when sampled.

## Deployment Examples

### With an OpenTelemetry Collector sidecar

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: breakglass-controller
          env:
            - name: OTEL_ENABLED
              value: "true"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "localhost:4317"
            - name: OTEL_INSECURE
              value: "true"
            - name: OTEL_SAMPLING_RATE
              value: "0.1"
        - name: otel-collector
          image: otel/opentelemetry-collector:latest
          ports:
            - containerPort: 4317
```

### With Grafana Tempo

```yaml
telemetry:
  enabled: true
  exporter: otlp
  endpoint: tempo.monitoring:4317
  insecure: true
  samplingRate: 0.1
```

### With Jaeger via OTLP

```yaml
telemetry:
  enabled: true
  exporter: otlp
  endpoint: jaeger-collector.monitoring:4317
  insecure: true
```

## Span Hierarchy

When tracing is enabled, the otelgin middleware creates a root span for every HTTP request:

```
HTTP GET /api/v1/sessions
├── k8s-breakglass (otelgin root span)
│   ├── attributes: http.method, http.route, http.status_code, ...
```

Future instrumentation will add child spans for:
- Authorization webhook decisions (`breakglass.authorize`)
- Session lifecycle events (`breakglass.session.create`)
- Cluster communication (`breakglass.cluster.sync`)

## Context Propagation

The controller propagates W3C `traceparent` and `baggage` headers automatically.
Upstream services (e.g. ingress controllers, API gateways) that set these headers
will have their trace context carried through the breakglass controller.

## Graceful Shutdown

On `SIGTERM`/`SIGINT`, the controller flushes all pending spans to the collector
before exiting. The flush timeout is 5 seconds (hardcoded in the telemetry
package), but the actual deadline is bounded by the controller's overall shutdown
budget — if the shutdown context expires sooner, span export may be truncated.

## Disabling Tracing

When `telemetry.enabled` is `false` (the default), a no-op TracerProvider is installed.
The otelgin middleware remains registered but becomes a near-zero-cost pass-through
since no spans are recorded or exported.
