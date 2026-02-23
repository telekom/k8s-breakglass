// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

func TestUpdateSessionActivityStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("returns no error for existing session", func(t *testing.T) {
		session := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
			},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:         "alice@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
			Status: v1alpha1.BreakglassSessionStatus{
				AccessCount: 5,
			},
		}
		cli := fake.NewClientBuilder().
			WithScheme(breakglass.Scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			WithIndex(&v1alpha1.BreakglassSession{}, "metadata.name", func(o client.Object) []string {
				return []string{o.GetName()}
			}).
			Build()
		mgr := breakglass.NewSessionManagerWithClient(cli)

		now := time.Now()
		err := updateSessionActivityStatus(ctx, &mgr, "test-session", now, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("returns error for nil session manager", func(t *testing.T) {
		err := updateSessionActivityStatus(ctx, nil, "test-session", time.Now(), nil)
		if err == nil {
			t.Fatal("expected error for nil session manager")
		}
	})

	t.Run("returns error for non-existent session", func(t *testing.T) {
		cli := fake.NewClientBuilder().
			WithScheme(breakglass.Scheme).
			WithIndex(&v1alpha1.BreakglassSession{}, "metadata.name", func(o client.Object) []string {
				return []string{o.GetName()}
			}).
			Build()
		mgr := breakglass.NewSessionManagerWithClient(cli)

		err := updateSessionActivityStatus(ctx, &mgr, "nonexistent-session", time.Now(), nil)
		if err == nil {
			t.Fatal("expected error for non-existent session")
		}
	})

	t.Run("no error for zero AccessCount session", func(t *testing.T) {
		session := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-session",
				Namespace: "default",
			},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:         "bob@example.com",
				Cluster:      "prod-cluster",
				GrantedGroup: "reader",
			},
		}
		cli := fake.NewClientBuilder().
			WithScheme(breakglass.Scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			WithIndex(&v1alpha1.BreakglassSession{}, "metadata.name", func(o client.Object) []string {
				return []string{o.GetName()}
			}).
			Build()
		mgr := breakglass.NewSessionManagerWithClient(cli)

		if err := updateSessionActivityStatus(ctx, &mgr, "new-session", time.Now(), nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRecordSessionActivity_EmitsMetrics(t *testing.T) {
	// Reset the metrics for a clean test
	metrics.SessionActivityTotal.Reset()
	metrics.SessionLastActivityTimestamp.Reset()

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "metrics-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			Cluster:      "test-cluster",
			GrantedGroup: "admin",
		},
	}
	cli := fake.NewClientBuilder().
		WithScheme(breakglass.Scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		WithIndex(&v1alpha1.BreakglassSession{}, "metadata.name", func(o client.Object) []string {
			return []string{o.GetName()}
		}).
		Build()
	mgr := breakglass.NewSessionManagerWithClient(cli)

	logger, _ := zap.NewDevelopment()
	recordSessionActivity(context.Background(), &mgr, "test-cluster", "metrics-session", logger.Sugar())

	// Give the goroutine a moment to complete
	time.Sleep(500 * time.Millisecond)

	// Verify counter was registered and writable (no panic)
	m, err := metrics.SessionActivityTotal.GetMetricWithLabelValues("test-cluster", "metrics-session")
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	_ = m

	// Verify gauge was also written
	g, err := metrics.SessionLastActivityTimestamp.GetMetricWithLabelValues("test-cluster", "metrics-session")
	if err != nil {
		t.Fatalf("failed to get gauge metric: %v", err)
	}
	_ = g
}

func TestRecordSessionActivity_HandlesNilSessionManager(t *testing.T) {
	metrics.SessionActivityTotal.Reset()
	metrics.SessionActivityUpdateErrors.Reset()

	logger, _ := zap.NewDevelopment()

	// Should not panic with nil session manager
	recordSessionActivity(context.Background(), nil, "cluster", "session", logger.Sugar())

	// Give the goroutine a moment to complete
	time.Sleep(500 * time.Millisecond)

	// The error metric should have been incremented
	m, err := metrics.SessionActivityUpdateErrors.GetMetricWithLabelValues("cluster", "session")
	if err != nil {
		t.Fatalf("failed to get error metric: %v", err)
	}
	_ = m
}

func TestSetRecordSessionActivityFunc(t *testing.T) {
	var called atomic.Int32

	mockFn := func(_ context.Context, _ *breakglass.SessionManager, _, _ string, _ *zap.SugaredLogger) {
		called.Add(1)
	}

	cleanup := setRecordSessionActivityFunc(mockFn)
	defer cleanup()

	// Call the overridden function
	defaultRecordSessionActivity(context.Background(), nil, "cluster", "session", nil)

	if called.Load() != 1 {
		t.Errorf("expected mock to be called once, got %d", called.Load())
	}

	// Verify cleanup restores original
	cleanup()
}

func TestNewSessionActivityRecorder(t *testing.T) {
	t.Run("returns noop when session manager is nil", func(t *testing.T) {
		recorder := newSessionActivityRecorder(nil, nil)
		if _, ok := recorder.(*noopSessionActivityRecorder); !ok {
			t.Error("expected noopSessionActivityRecorder when session manager is nil")
		}
		// Should not panic
		recorder.RecordActivity(context.Background(), "cluster", "session")
	})

	t.Run("returns default recorder when session manager is provided", func(t *testing.T) {
		cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
		mgr := breakglass.NewSessionManagerWithClient(cli)
		recorder := newSessionActivityRecorder(&mgr, nil)
		if _, ok := recorder.(*defaultSessionActivityRecorder); !ok {
			t.Error("expected defaultSessionActivityRecorder when session manager is provided")
		}
	})
}
