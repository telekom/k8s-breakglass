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
	reader := interceptor.NewClient(hub, interceptor.Funcs{List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		options := &client.ListOptions{}
		for _, option := range opts {
			option.ApplyToList(options)
		}
		require.Equal(t, "spec.templateRef="+template.Name, options.AsListOptions().FieldSelector)
		require.EqualValues(t, 500, options.AsListOptions().Limit)
		return cl.List(ctx, list, opts...)
	}})
	c := NewDebugSessionController(zap.NewNop().Sugar(), writer, nil).WithAPIReader(reader)
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

func TestActiveAccountingConflictDoesNotRetainClearedPodTemplate(t *testing.T) {
	ctx := context.Background()
	pod := &breakglassv1alpha1.DebugPodTemplate{ObjectMeta: metav1.ObjectMeta{Name: "old-pod-template"}}
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "rotating-template", UID: "template-uid"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{Name: pod.Name}}}
	ds := newTestDebugSession("rotating-session", template.Name, "cluster", "user")
	ds.Status.State = breakglassv1alpha1.DebugSessionStateActive
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(template, pod, ds).WithStatusSubresource(template, pod, ds).Build()
	attempts := 0
	writer := interceptor.NewClient(hub, interceptor.Funcs{SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
		if _, ok := obj.(*breakglassv1alpha1.DebugSessionTemplate); ok {
			attempts++
			if attempts == 1 {
				live := &breakglassv1alpha1.DebugSessionTemplate{}
				require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(template), live))
				live.Spec.PodTemplateRef = nil
				require.NoError(t, hub.Update(ctx, live))
			}
		}
		return cl.Status().Patch(ctx, obj, patch, opts...)
	}})
	c := NewDebugSessionController(zap.NewNop().Sugar(), writer, nil).WithAPIReader(hub)
	require.NoError(t, c.reconcileActiveAccounting(ctx, ds, true))
	require.Equal(t, 2, attempts, "real resource-version conflict must retry")
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(pod), pod))
	require.Empty(t, pod.Status.UsedBy, "failed attempt must not retain its old pod-template target")
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(template), template))
	require.EqualValues(t, 1, template.Status.ActiveSessionCount)
	t.Cleanup(func() { metrics.DebugSessionsActive.DeleteLabelValues(ds.Spec.Cluster, template.Name) })
}

func TestPeriodicAccountingCoalescesButTransitionsAndFailuresRepair(t *testing.T) {
	ctx := t.Context()
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "coalesced"}}
	first := newTestDebugSession("first", template.Name, "one", "user")
	second := newTestDebugSession("second", template.Name, "two", "user")
	first.Status.State = breakglassv1alpha1.DebugSessionStateActive
	second.Status.State = breakglassv1alpha1.DebugSessionStateActive
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(template, first, second).WithStatusSubresource(template, first, second).Build()
	lists, patches := 0, 0
	fail := true
	wrapped := interceptor.NewClient(hub, interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			lists++
			if fail {
				return fmt.Errorf("accounting unavailable")
			}
			return cl.List(ctx, list, opts...)
		},
		SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			patches++
			return cl.Status().Patch(ctx, obj, patch, opts...)
		},
	})
	c := NewDebugSessionController(zap.NewNop().Sugar(), wrapped, nil).WithAPIReader(wrapped)
	require.ErrorContains(t, c.reconcilePeriodicActiveAccounting(ctx, first), "accounting unavailable")
	fail = false
	require.NoError(t, c.reconcilePeriodicActiveAccounting(ctx, first))
	require.NoError(t, c.reconcilePeriodicActiveAccounting(ctx, second))
	require.Equal(t, 2, lists, "failed repair must retry, successful template repair must coalesce")
	require.Equal(t, 1, patches)
	for _, cluster := range []string{"one", "two"} {
		require.Equal(t, float64(1), testutil.ToFloat64(metrics.DebugSessionsActive.WithLabelValues(cluster, template.Name)))
		t.Cleanup(func() { metrics.DebugSessionsActive.DeleteLabelValues(cluster, template.Name) })
	}
	second.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
	require.NoError(t, hub.Status().Update(ctx, second))
	require.NoError(t, c.reconcileActiveAccounting(ctx, second, false))
	require.Equal(t, 3, lists, "terminal transition bypasses periodic throttle")
	require.Equal(t, float64(0), testutil.ToFloat64(metrics.DebugSessionsActive.WithLabelValues("two", template.Name)))
	c.accountingLast[template.Name] = time.Now().Add(-DefaultDebugSessionRequeue)
	require.NoError(t, c.reconcilePeriodicActiveAccounting(ctx, first))
	require.Equal(t, 4, lists, "next interval repairs again")
	require.Equal(t, 2, patches, "unchanged aggregate must not write")
	fail = true
	require.ErrorContains(t, c.reconcileActiveAccounting(ctx, second, false), "accounting unavailable")
	fail = false
	require.NoError(t, c.reconcilePeriodicActiveAccounting(ctx, first))
	require.Equal(t, 6, lists, "transition failure must invalidate a recent successful periodic repair")
}

func TestAccountingOptionalPodTemplateFailureDoesNotBlockAndRepairs(t *testing.T) {
	ctx := t.Context()
	pod := &breakglassv1alpha1.DebugPodTemplate{ObjectMeta: metav1.ObjectMeta{Name: "missing-usage"}}
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "optional-usage"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{Name: pod.Name}}}
	ds := newTestDebugSession("used", template.Name, "one", "user")
	ds.Status.State = breakglassv1alpha1.DebugSessionStateActive
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(template, ds).WithStatusSubresource(template, ds, pod).Build()
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithAPIReader(hub)
	require.NoError(t, c.reconcilePeriodicActiveAccounting(ctx, ds), "missing optional pod template must not block lifecycle")
	require.NoError(t, hub.Create(ctx, pod))
	c.accountingLast[template.Name] = time.Now().Add(-DefaultDebugSessionRequeue)
	require.NoError(t, c.reconcilePeriodicActiveAccounting(ctx, ds))
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(pod), pod))
	require.Contains(t, pod.Status.UsedBy, template.Name)
	t.Cleanup(func() { metrics.DebugSessionsActive.DeleteLabelValues("one", template.Name) })
}

func TestPeriodicAccountingDoesNotSerializeDifferentTemplates(t *testing.T) {
	ctx := t.Context()
	first := newTestDebugSession("first", "blocked-template", "one", "user")
	second := newTestDebugSession("second", "other-template", "two", "user")
	first.Status.State = breakglassv1alpha1.DebugSessionStateActive
	second.Status.State = breakglassv1alpha1.DebugSessionStateActive
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(first, second).Build()
	entered, release := make(chan struct{}), make(chan struct{})
	reader := interceptor.NewClient(hub, interceptor.Funcs{List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		options := (&client.ListOptions{}).ApplyOptions(opts)
		if options.AsListOptions().FieldSelector == "spec.templateRef=blocked-template" {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return cl.List(ctx, list, opts...)
	}})
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithAPIReader(reader)
	done := make(chan error, 1)
	go func() { done <- c.reconcilePeriodicActiveAccounting(ctx, first) }()
	<-entered
	other := make(chan error, 1)
	go func() { other <- c.reconcilePeriodicActiveAccounting(ctx, second) }()
	select {
	case err := <-other:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("unrelated template blocked behind network I/O")
	}
	close(release)
	require.NoError(t, <-done)
	for _, ds := range []*breakglassv1alpha1.DebugSession{first, second} {
		t.Cleanup(func() { metrics.DebugSessionsActive.DeleteLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef) })
	}
}
