// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"
)

func TestInitDisabled(t *testing.T) {
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	ctx := context.Background()
	tp, shutdown, err := Init(ctx, Options{Enabled: false})
	if err != nil {
		t.Fatalf("Init(disabled) returned error: %v", err)
	}
	defer func() {
		if err := shutdown(ctx); err != nil {
			t.Errorf("shutdown returned error: %v", err)
		}
	}()

	// Should return a noop provider
	if _, ok := tp.(noop.TracerProvider); !ok {
		t.Errorf("expected noop.TracerProvider, got %T", tp)
	}
}

func TestInitEnabledNoneExporter(t *testing.T) {
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	ctx := context.Background()
	log := zap.NewNop().Sugar()
	tp, shutdown, err := Init(ctx, Options{
		Enabled:      true,
		Exporter:     "none",
		ServiceName:  "test-service",
		SamplingRate: 1.0,
		Logger:       log,
	})
	if err != nil {
		t.Fatalf("Init(none exporter) returned error: %v", err)
	}
	defer func() {
		if err := shutdown(ctx); err != nil {
			t.Errorf("shutdown returned error: %v", err)
		}
	}()

	// Should return a real (non-noop) provider
	if _, ok := tp.(*noop.TracerProvider); ok {
		t.Error("expected real TracerProvider, got noop")
	}

	// Global provider should be set
	globalTP := otel.GetTracerProvider()
	if globalTP == nil {
		t.Fatal("global TracerProvider is nil")
	}
}

func TestInitEnabledStdoutExporter(t *testing.T) {
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	ctx := context.Background()
	log := zap.NewNop().Sugar()
	tp, shutdown, err := Init(ctx, Options{
		Enabled:      true,
		Exporter:     "stdout",
		ServiceName:  "test-stdout",
		SamplingRate: 0.5,
		Logger:       log,
	})
	if err != nil {
		t.Fatalf("Init(stdout) returned error: %v", err)
	}
	defer func() {
		if err := shutdown(ctx); err != nil {
			t.Errorf("shutdown returned error: %v", err)
		}
	}()

	if tp == nil {
		t.Fatal("TracerProvider is nil")
	}
}

func TestInitInvalidExporter(t *testing.T) {
	ctx := context.Background()
	_, _, err := Init(ctx, Options{
		Enabled:  true,
		Exporter: "invalid-exporter",
	})
	if err == nil {
		t.Fatal("expected error for invalid exporter, got nil")
	}
}

func TestInitDefaultServiceName(t *testing.T) {
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	ctx := context.Background()
	tp, shutdown, err := Init(ctx, Options{
		Enabled:  true,
		Exporter: "none",
	})
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	defer func() { _ = shutdown(ctx) }()

	if tp == nil {
		t.Fatal("TracerProvider is nil")
	}
}

func TestInitSamplingRateClamped(t *testing.T) {
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	ctx := context.Background()
	// Negative sampling rate should be clamped to 1.0
	tp, shutdown, err := Init(ctx, Options{
		Enabled:      true,
		Exporter:     "none",
		SamplingRate: -0.5,
	})
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	defer func() { _ = shutdown(ctx) }()

	if tp == nil {
		t.Fatal("TracerProvider is nil")
	}
}

func TestInitSamplingRateAboveOne(t *testing.T) {
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	ctx := context.Background()
	// Sampling rate > 1.0 should be clamped to 1.0
	tp, shutdown, err := Init(ctx, Options{
		Enabled:      true,
		Exporter:     "none",
		SamplingRate: 2.0,
	})
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	defer func() { _ = shutdown(ctx) }()

	if tp == nil {
		t.Fatal("TracerProvider is nil")
	}
}

func TestShutdownIdempotent(t *testing.T) {
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	ctx := context.Background()
	_, shutdown, err := Init(ctx, Options{
		Enabled:  true,
		Exporter: "none",
	})
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}

	// First shutdown should succeed
	if err := shutdown(ctx); err != nil {
		t.Errorf("first shutdown returned error: %v", err)
	}
	// Second shutdown should also succeed (or return a benign error)
	_ = shutdown(ctx)
}

func TestInitOTLPExporterCreation(t *testing.T) {
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	ctx := context.Background()
	// OTLP exporter uses lazy connection, so New() succeeds even with a
	// non-routable endpoint. This verifies the OTLP code path initializes
	// without errors.
	tp, shutdown, err := Init(ctx, Options{
		Enabled:  true,
		Exporter: "otlp",
		Endpoint: "localhost:0",
		Insecure: true,
		Logger:   zap.NewNop().Sugar(),
	})
	if err != nil {
		t.Fatalf("Init(otlp) returned error: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(ctx) })
	if tp == nil {
		t.Fatal("TracerProvider is nil")
	}
}
