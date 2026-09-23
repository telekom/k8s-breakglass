// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestValidationAuditUsesSharedLivePolicy(t *testing.T) {
	for _, mode := range []string{"disabled", "enabled", "unavailable", "captured disabled"} {
		t.Run(mode, func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "invalid", Namespace: "ns", UID: "uid"}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: "policy"}}
			template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{Audit: &breakglassv1alpha1.DebugSessionAuditConfig{Enabled: mode != "disabled"}}}
			if mode == "captured disabled" {
				session.Status.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{Audit: &breakglassv1alpha1.DebugSessionAuditConfig{Enabled: false}}
			}
			hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(session, template).WithStatusSubresource(session).Build()
			reader := interceptor.NewClient(hub, interceptor.Funcs{Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*breakglassv1alpha1.DebugSessionTemplate); ok && mode == "unavailable" {
					return context.DeadlineExceeded
				}
				return cl.Get(ctx, key, obj, opts...)
			}})
			sink := &cleanupAuditCaptureSink{}
			manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
			controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithAPIReader(reader).WithAuditManager(manager)
			for range 2 {
				_, err := controller.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(session)})
				require.NoError(t, err)
			}
			require.NoError(t, manager.Close())
			require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(session), session))
			require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, session.Status.State)
			if mode == "enabled" {
				require.Len(t, sink.Events(), 1)
				require.Equal(t, audit.EventDebugSessionValidationFailed, sink.Events()[0].Type)
			} else {
				require.Empty(t, sink.Events())
			}
		})
	}
}

func TestCleanupEvidenceDeduplicatesReportedIdentityAndBoundsAllocations(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{}
	prefix := strings.Repeat("x", maxCleanupIdentityLength)
	for _, name := range []string{prefix + "one", prefix + "two", "different"} {
		session.Status.DeployedResources = append(session.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{Kind: "Pod", Name: name})
	}
	identities := cleanupResidualIdentities(session)
	require.Len(t, identities, 2)
	require.Len(t, identities[0], maxCleanupIdentityLength)
	require.Equal(t, "Pod/different", identities[1])
	session.Status.DeployedResources = nil
	for i := range 1000 {
		session.Status.DeployedResources = append(session.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{Kind: "Pod", Name: fmt.Sprint(i)})
	}
	small := session.DeepCopy()
	small.Status.DeployedResources = small.Status.DeployedResources[:maxCleanupResidualIdentities]
	smallAllocations := testing.AllocsPerRun(10, func() { require.Len(t, cleanupResidualIdentities(small), maxCleanupResidualIdentities) })
	largeAllocations := testing.AllocsPerRun(10, func() { require.Len(t, cleanupResidualIdentities(session), maxCleanupResidualIdentities) })
	require.LessOrEqual(t, largeAllocations, smallAllocations+1, "inventory beyond the report bound must not grow evidence allocations")
}
