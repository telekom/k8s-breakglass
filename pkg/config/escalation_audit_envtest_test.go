// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/audit/audittest"
)

// TestEscalationAuditEnvtest runs the escalation and AuditConfig reconcilers
// against a real API server: without any AuditConfig auditing becomes
// disabled and nothing is recorded or retried; with one, creating, updating
// and deleting an escalation emits .../1, .../2 and .../deleted in order,
// including generations that the work queue coalesces.
func TestEscalationAuditEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	environment := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0"})
	require.NoError(t, err)

	var mu sync.Mutex
	var ids []string
	audit.ObserveEmitted(func(event *audit.Event) {
		audittest.Record(event)
		if strings.HasPrefix(string(event.Type), "escalation.") {
			mu.Lock()
			ids = append(ids, event.ID)
			mu.Unlock()
		}
	})
	t.Cleanup(func() { audit.ObserveEmitted(audittest.Record) })
	emitted := func(uid string) []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, id := range ids {
			if strings.HasPrefix(id, "escalation/"+uid+"/") {
				out = append(out, strings.TrimPrefix(id, "escalation/"+uid+"/"))
			}
		}
		return out
	}

	log := zap.NewNop().Sugar()
	svc := audit.NewService(mgr.GetClient(), nil, zap.NewNop(), "audit-envtest")
	auditConfigs := NewAuditConfigReconciler(mgr.GetClient(), log, nil,
		func(ctx context.Context, configs []*breakglassv1alpha1.AuditConfig, unavailable bool) error {
			return svc.ReloadMultipleWithAvailability(ctx, configs, unavailable)
		}, nil, time.Minute)
	require.NoError(t, auditConfigs.SetupWithManager(mgr))
	// Each reconcile reads the escalation slowly, so changes made meanwhile
	// coalesce into one reconcile that sees only the newest generation: only
	// the watch hooks can audit the generations in between.
	slowReads := slowEscalationReads{Client: mgr.GetClient()}
	escalations := NewEscalationReconciler(slowReads, log, nil, nil, nil, time.Minute).WithAuditEmitter(svc)
	svc.BeforeClose(escalations.DrainAudit)
	require.NoError(t, escalations.SetupWithManager(mgr))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		require.NoError(t, svc.Close())
		cancel()
		require.NoError(t, <-done)
	})
	apiClient, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	require.NoError(t, apiClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "audit-envtest"}}))

	newEscalation := func(name string) *breakglassv1alpha1.BreakglassEscalation {
		return &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "audit-envtest"},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "platform-admin", MaxValidFor: "1h",
				Allowed:   breakglassv1alpha1.BreakglassEscalationAllowed{Clusters: []string{"cluster"}, Groups: []string{"users"}},
				Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
			},
		}
	}
	updateGroup := func(esc *breakglassv1alpha1.BreakglassEscalation, group string) {
		t.Helper()
		patch := client.MergeFrom(esc.DeepCopy())
		esc.Spec.EscalatedGroup = group
		require.NoError(t, apiClient.Patch(ctx, esc, patch))
	}

	// No AuditConfig: the startup sync disables auditing; nothing is recorded
	// and nothing waits for a retry.
	require.Eventually(t, func() bool { return svc.ConfigurationState() == audit.ConfigurationDisabled },
		30*time.Second, 50*time.Millisecond, "the initial sync disables auditing without any AuditConfig")
	quiet := newEscalation("while-disabled")
	require.NoError(t, apiClient.Create(ctx, quiet))
	updateGroup(quiet, "platform-admin-2")
	require.Never(t, func() bool {
		escalations.auditor.mu.Lock()
		defer escalations.auditor.mu.Unlock()
		return len(escalations.auditor.pending) > 0 || len(emitted(string(quiet.UID))) > 0
	}, 2*time.Second, 50*time.Millisecond, "disabled auditing records nothing")

	// With an AuditConfig the pipeline becomes ready.
	require.NoError(t, apiClient.Create(ctx, &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-envtest"},
		Spec: breakglassv1alpha1.AuditConfigSpec{Enabled: true, Sinks: []breakglassv1alpha1.AuditSinkConfig{{
			Name: "log", Type: breakglassv1alpha1.AuditSinkTypeLog,
		}}},
	}))
	require.Eventually(t, func() bool { return svc.ConfigurationState() == audit.ConfigurationReady },
		30*time.Second, 50*time.Millisecond)

	// Create, then update several times in a row without waiting, so the
	// work queue coalesces reconciles: every generation is still audited.
	esc := newEscalation("audited")
	require.NoError(t, apiClient.Create(ctx, esc))
	updateGroup(esc, "platform-admin-2")
	updateGroup(esc, "platform-admin-3")
	uid := string(esc.UID)
	require.Eventually(t, func() bool { return len(emitted(uid)) >= 3 }, 30*time.Second, 50*time.Millisecond)
	require.Equal(t, []string{"1", "2", "3"}, emitted(uid))

	require.NoError(t, apiClient.Delete(ctx, esc))
	require.Eventually(t, func() bool { return len(emitted(uid)) >= 4 }, 30*time.Second, 50*time.Millisecond)
	require.Equal(t, []string{"1", "2", "3", "deleted"}, emitted(uid), "in order, each once")
}

type slowEscalationReads struct{ client.Client }

func (c slowEscalationReads) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*breakglassv1alpha1.BreakglassEscalation); ok {
		time.Sleep(time.Second)
	}
	return c.Client.Get(ctx, key, obj, opts...)
}
