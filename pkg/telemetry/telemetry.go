// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package telemetry provides OpenTelemetry tracing initialization and lifecycle
// management for the breakglass controller.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"
)

// Options configures the OpenTelemetry TracerProvider.
type Options struct {
	// Enabled controls whether tracing is active. When false, a no-op
	// TracerProvider is installed and the shutdown function is a no-op.
	Enabled bool

	// ServiceName is the service.name resource attribute.
	// Default: "k8s-breakglass"
	ServiceName string

	// ServiceVersion is the service.version resource attribute.
	ServiceVersion string

	// Exporter selects the trace exporter: "otlp" (default), "stdout", or "none".
	Exporter string

	// Endpoint is the OTLP collector endpoint (e.g. "otel-collector:4317").
	// Ignored when Exporter is not "otlp".
	Endpoint string

	// Insecure disables TLS for the OTLP gRPC connection.
	Insecure bool

	// SamplingRate is the probability of sampling a trace (0.0-1.0).
	// Default: 1.0 (sample everything) - adjust for production.
	SamplingRate float64

	// Logger is used for internal diagnostics during initialization.
	Logger *zap.SugaredLogger
}

// ShutdownFunc gracefully shuts down the TracerProvider, flushing pending spans.
type ShutdownFunc func(ctx context.Context) error

// Init initialises the global OpenTelemetry TracerProvider and propagator.
// It returns the TracerProvider (for creating named tracers) and a shutdown
// function that must be called during graceful shutdown.
//
// When opts.Enabled is false a no-op provider is installed; the returned
// ShutdownFunc is safe to call and always returns nil.
func Init(ctx context.Context, opts Options) (trace.TracerProvider, ShutdownFunc, error) {
	if !opts.Enabled {
		tp := noop.NewTracerProvider()
		otel.SetTracerProvider(tp)
		return tp, func(context.Context) error { return nil }, nil
	}

	// Defaults
	if opts.ServiceName == "" {
		opts.ServiceName = "k8s-breakglass"
	}

	log := opts.Logger
	if log == nil {
		log = zap.NewNop().Sugar()
	}

	if opts.SamplingRate < 0 {
		log.Warnw("OTel sampling rate < 0, clamping to 1.0 (sample everything)", "provided", opts.SamplingRate)
		opts.SamplingRate = 1.0
	}
	if opts.SamplingRate > 1.0 {
		log.Warnw("OTel sampling rate > 1.0, clamping to 1.0 (sample everything)", "provided", opts.SamplingRate)
		opts.SamplingRate = 1.0
	}

	// Build resource with service attributes.
	// Use NewSchemaless to avoid schema URL conflicts with resource.Default().
	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			attribute.String("service.name", opts.ServiceName),
			attribute.String("service.version", opts.ServiceVersion),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating OTel resource: %w", err)
	}

	// Build exporter
	var exporter sdktrace.SpanExporter
	switch opts.Exporter {
	case "otlp", "":
		grpcOpts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(opts.Endpoint),
		}
		if opts.Insecure {
			grpcOpts = append(grpcOpts, otlptracegrpc.WithInsecure())
		}
		exporter, err = otlptracegrpc.New(ctx, grpcOpts...)
		if err != nil {
			return nil, nil, fmt.Errorf("creating OTLP gRPC exporter: %w", err)
		}
		log.Infow("OTel OTLP exporter initialized", "endpoint", opts.Endpoint, "insecure", opts.Insecure)

	case "stdout":
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, nil, fmt.Errorf("creating stdout exporter: %w", err)
		}
		log.Infow("OTel stdout exporter initialized")

	case "none":
		// No exporter - useful for testing with a real provider but no export
		log.Infow("OTel tracing enabled with no exporter", "note", "spans are created but not exported")

	default:
		return nil, nil, fmt.Errorf("unknown OTel exporter %q: supported values are otlp, stdout, none", opts.Exporter)
	}

	// Build TracerProvider
	tpOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(
			sdktrace.TraceIDRatioBased(opts.SamplingRate),
		)),
	}
	if exporter != nil {
		tpOpts = append(tpOpts, sdktrace.WithBatcher(exporter))
	}

	tp := sdktrace.NewTracerProvider(tpOpts...)

	// Install as global provider and propagator
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	// Route OTel internal errors (e.g., OTLP export failures) through
	// the structured logger instead of the default stderr handler.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		log.Warnw("OpenTelemetry internal error", "error", err)
	}))

	log.Infow("OpenTelemetry tracing initialized",
		"serviceName", opts.ServiceName,
		"exporter", opts.Exporter,
		"samplingRate", opts.SamplingRate,
	)

	shutdown := func(ctx context.Context) error {
		log.Infow("Shutting down OpenTelemetry TracerProvider")
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return tp.Shutdown(shutdownCtx)
	}

	return tp, shutdown, nil
}
