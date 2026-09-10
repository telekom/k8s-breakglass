// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestActiveAccountingRetriesFreshGlobalCountAndPreservesMetadata(t *testing.T) {
	ctx := context.Background()
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "global-accounting", UID: "template-uid"}}
	first := newTestDebugSession("first", template.Name, "one", "user")
	second := newTestDebugSession("second", template.Name, "two", "user")
	for _, ds := range []*breakglassv1alpha1.DebugSession{first, second} {
		ds.Status.State = breakglassv1alpha1.DebugSessionStateActive
	}
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(template, first, second).WithStatusSubresource(template, first, second).Build()
	writes := 0
	writer := interceptor.NewClient(hub, interceptor.Funcs{SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
		if _, ok := obj.(*breakglassv1alpha1.DebugSessionTemplate); ok {
			writes++
			if writes == 1 {
				live := &breakglassv1alpha1.DebugSessionTemplate{}
				require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(template), live))
				at := metav1.NewTime(time.Now().Add(time.Hour))
				live.Status.LastUsedAt = &at
				require.NoError(t, hub.Status().Update(ctx, live))
				require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(second), second))
				second.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
				require.NoError(t, hub.Status().Update(ctx, second))
			}
		}
		return cl.Status().Patch(ctx, obj, p, opts...)
	}})
	c := NewDebugSessionController(zap.NewNop().Sugar(), writer, nil).WithAPIReader(hub)
	require.NoError(t, c.reconcileActiveAccounting(ctx, first, true))
	require.Equal(t, 2, writes)
	live := &breakglassv1alpha1.DebugSessionTemplate{}
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(template), live))
	require.EqualValues(t, 1, live.Status.ActiveSessionCount)
	require.True(t, live.Status.LastUsedAt.After(time.Now()))
	require.Equal(t, float64(1), testutil.ToFloat64(metrics.DebugSessionsActive.WithLabelValues("one", template.Name)))
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(second), second))
	second.Status.State = breakglassv1alpha1.DebugSessionStateActive
	require.NoError(t, hub.Status().Update(ctx, second))
	require.NoError(t, c.reconcileActiveAccounting(ctx, first, false))
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(template), live))
	require.EqualValues(t, 2, live.Status.ActiveSessionCount)
	require.Equal(t, float64(1), testutil.ToFloat64(metrics.DebugSessionsActive.WithLabelValues("one", template.Name)))
	t.Cleanup(func() { metrics.DebugSessionsActive.DeleteLabelValues("one", template.Name) })
}

func TestActiveReconciliationRepairsFailedAccountingWithoutChangingSession(t *testing.T) {
	ctx := context.Background()
	c, ds, template, _ := newDeploymentFenceFixture(t)
	hub, ok := c.client.(client.WithWatch)
	require.True(t, ok)
	fail := true
	c.client = interceptor.NewClient(hub, interceptor.Funcs{SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
		if _, ok := obj.(*breakglassv1alpha1.DebugSessionTemplate); ok && fail {
			return fmt.Errorf("injected accounting outage")
		}
		return cl.Status().Patch(ctx, obj, p, opts...)
	}})
	c.WithAPIReader(hub)
	_, err := c.activateSession(ctx, ds, template, nil)
	require.ErrorContains(t, err, "injected accounting outage")
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(ds), ds))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State)
	fail = false
	_, err = c.handleActive(ctx, ds)
	require.NoError(t, err)
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(template), template))
	require.EqualValues(t, 1, template.Status.ActiveSessionCount)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State)
	t.Cleanup(func() { metrics.DebugSessionsActive.DeleteLabelValues(ds.Spec.Cluster, template.Name) })
}

func TestTerminalAccountingRepairsUsageAfterActivationWriteFailure(t *testing.T) {
	ctx := context.Background()
	started := metav1.NewTime(time.Now().Add(-time.Minute).Truncate(time.Second))
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{ObjectMeta: metav1.ObjectMeta{Name: "usage-pod"}}
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "usage-session"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplate.Name}}}
	ds := newTestDebugSession("used", template.Name, "one", "user")
	ds.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
	ds.Status.StartsAt = &started
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(template, podTemplate, ds).WithStatusSubresource(template, podTemplate, ds).Build()
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithAPIReader(hub)
	_, err := c.handleCleanup(ctx, ds)
	require.NoError(t, err)
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(template), template))
	require.True(t, template.Status.LastUsedAt.Equal(&started))
	require.Zero(t, template.Status.ActiveSessionCount)
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(podTemplate), podTemplate))
	require.Contains(t, podTemplate.Status.UsedBy, template.Name)
	t.Cleanup(func() { metrics.DebugSessionsActive.DeleteLabelValues("one", template.Name) })
}
