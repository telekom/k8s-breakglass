// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// appliedHotfix runs plan and apply on all workers and returns the record.
func appliedHotfix(t *testing.T, f *hotfixFixture) *breakglassv1alpha1.HotfixRecord {
	t.Helper()
	plan := f.planned(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"}))
	apply := f.drive(t, f.session(t, "apply-1", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "plan-1", PlanHash: plan.Status.Hotfix.PlanHash}))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, apply.Status.State, apply.Status.Message)
	record := &breakglassv1alpha1.HotfixRecord{}
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: apply.Status.Hotfix.RecordName}, record))
	return record
}

func recordNodeState(record *breakglassv1alpha1.HotfixRecord, name string) breakglassv1alpha1.HotfixNodeState {
	for _, node := range record.Status.Nodes {
		if node.Name == name {
			return node.State
		}
	}
	return ""
}

func TestHotfixRecordDriftExpiryAndMetrics(t *testing.T) {
	f := newHotfixFixture(t, 3, 0)
	record := appliedHotfix(t, f)
	r := NewHotfixRecordReconciler(zap.NewNop().Sugar(), f.hub, f.c.ccProvider)
	r.targetClientFactory = func(*rest.Config) (client.Client, error) { return f.spoke, nil }
	labels := hotfixRecordLabels(record)
	t.Cleanup(func() { deleteHotfixRecordSeries(record.Namespace + "/" + record.Name) })

	// worker-01 loses its mark; a new worker joins the selection.
	node := &corev1.Node{}
	require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "worker-01"}, node))
	delete(node.Annotations, hotfixAnnotationKey(record.Name))
	require.NoError(t, f.spoke.Update(t.Context(), node))
	require.NoError(t, f.spoke.Create(t.Context(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-new", Labels: map[string]string{"pool": "w"}}}))

	r.now = func() time.Time { return record.Spec.ExpiresAt.Add(-24 * time.Hour) }
	result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(record)})
	require.NoError(t, err)
	require.Equal(t, hotfixRecordResync, result.RequeueAfter)
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(record), record))
	require.Equal(t, breakglassv1alpha1.HotfixNodeApplied, recordNodeState(record, "worker-00"))
	require.Equal(t, breakglassv1alpha1.HotfixNodeReverted, recordNodeState(record, "worker-01"))
	require.Equal(t, breakglassv1alpha1.HotfixNodeUncovered, recordNodeState(record, "worker-new"))
	for _, condition := range []breakglassv1alpha1.HotfixRecordConditionType{breakglassv1alpha1.HotfixRecordConditionReverted,
		breakglassv1alpha1.HotfixRecordConditionUncovered, breakglassv1alpha1.HotfixRecordConditionExpiring, breakglassv1alpha1.HotfixRecordConditionActive} {
		require.True(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(condition)), condition)
	}
	require.False(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionExpired)))
	require.Equal(t, float64(1), testutil.ToFloat64(metrics.HotfixActive.WithLabelValues(labels...)))
	require.Equal(t, float64(1), testutil.ToFloat64(metrics.HotfixRevertedNodes.WithLabelValues(labels...)))
	require.Equal(t, float64(1), testutil.ToFloat64(metrics.HotfixUncoveredNodes.WithLabelValues(labels...)))
	require.Equal(t, float64(record.Spec.ExpiresAt.Unix()), testutil.ToFloat64(metrics.HotfixExpiresTimestamp.WithLabelValues(labels...)))

	// The mark comes back and the new node leaves the selection: both resolve.
	require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "worker-01"}, node))
	if node.Annotations == nil {
		node.Annotations = map[string]string{}
	}
	node.Annotations[hotfixAnnotationKey(record.Name)] = record.Namespace + "/" + record.Name + "@x"
	require.NoError(t, f.spoke.Update(t.Context(), node))
	require.NoError(t, f.spoke.Delete(t.Context(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-new"}}))
	r.now = func() time.Time { return record.Spec.ExpiresAt.Add(time.Hour) }
	_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(record)})
	require.NoError(t, err)
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(record), record))
	require.Equal(t, breakglassv1alpha1.HotfixNodeApplied, recordNodeState(record, "worker-01"))
	require.Empty(t, recordNodeState(record, "worker-new"))
	require.True(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionExpired)), "expiry alerts only")
	require.False(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionExpiring)))
	require.False(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionUncovered)))
	require.Equal(t, breakglassv1alpha1.HotfixNodeApplied, recordNodeState(record, "worker-02"), "expiry never rolls back")
}

func TestHotfixReconfirmAndClose(t *testing.T) {
	f := newHotfixFixture(t, 2, 0)
	record := appliedHotfix(t, f)
	before := record.Spec.ExpiresAt

	reconfirm := f.drive(t, f.session(t, "reconfirm-1", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageReconfirm, RecordName: record.Name, Lifetime: "30d"}))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, reconfirm.Status.State, reconfirm.Status.Message)
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(record), record))
	require.True(t, record.Spec.ExpiresAt.After(before.Time))
	require.Equal(t, breakglassv1alpha1.HotfixStageReconfirm, record.Spec.Sessions[len(record.Spec.Sessions)-1].Stage)

	closeSession := f.drive(t, f.session(t, "close-1", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageClose, RecordName: record.Name}))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, closeSession.Status.State, closeSession.Status.Message)
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(record), record))
	require.True(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionClosed)))
	require.False(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionActive)))
	node := &corev1.Node{}
	require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "worker-00"}, node))
	require.NotContains(t, node.Annotations, hotfixAnnotationKey(record.Name))

	// A closed record refuses further stages, at request time and at run time.
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "rb", Namespace: "default"},
		Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "default/spoke", TemplateRef: "hotfix",
			Hotfix: &breakglassv1alpha1.DebugSessionHotfixRequest{Stage: breakglassv1alpha1.HotfixStageRollback, RecordName: record.Name}}}
	require.ErrorContains(t, validateHotfixReferences(t.Context(), f.hub, f.tmpl, session), "closed")
	rollback := f.drive(t, f.session(t, "rollback-1", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageRollback, RecordName: record.Name}))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, rollback.Status.State)
	require.Contains(t, rollback.Status.Message, "closed")

	r := NewHotfixRecordReconciler(zap.NewNop().Sugar(), f.hub, f.c.ccProvider)
	labels := hotfixRecordLabels(record)
	metrics.HotfixActive.WithLabelValues(labels...).Set(1)
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(record)})
	require.NoError(t, err)
	require.False(t, metrics.HotfixActive.DeleteLabelValues(labels...), "closed records drop their series")
}

func TestHotfixRecordRequeueBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	expires := now.Add(hotfixExpiringWindow + time.Minute)
	require.Equal(t, time.Minute, hotfixRecordRequeue(now, expires))
	require.Equal(t, 2*time.Minute, hotfixRecordRequeue(now, now.Add(2*time.Minute)))
	require.Equal(t, hotfixRecordResync, hotfixRecordRequeue(now, now.Add(10*24*time.Hour)))
}

func TestHotfixRecordNodeTransitions(t *testing.T) {
	f := newHotfixFixture(t, 4, 0)
	record := appliedHotfix(t, f)
	r := NewHotfixRecordReconciler(zap.NewNop().Sugar(), f.hub, f.c.ccProvider)
	r.targetClientFactory = func(*rest.Config) (client.Client, error) { return f.spoke, nil }
	t.Cleanup(func() { deleteHotfixRecordSeries(record.Namespace + "/" + record.Name) })

	// worker-00 leaves the selection but keeps the hotfix; worker-01 is
	// replaced; worker-02 is removed.
	node := &corev1.Node{}
	require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "worker-00"}, node))
	node.Labels = map[string]string{"pool": "other"}
	require.NoError(t, f.spoke.Update(t.Context(), node))
	require.NoError(t, f.spoke.Delete(t.Context(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-01"}}))
	require.NoError(t, f.spoke.Create(t.Context(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-01", Labels: map[string]string{"pool": "w"}}}))
	require.NoError(t, f.spoke.Delete(t.Context(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-02"}}))

	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(record)})
	require.NoError(t, err)
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(record), record))
	require.Equal(t, breakglassv1alpha1.HotfixNodeApplied, recordNodeState(record, "worker-00"), "a relabelled node still carries the hotfix")
	require.Equal(t, breakglassv1alpha1.HotfixNodeUncovered, recordNodeState(record, "worker-01"), "a replaced node needs the hotfix again")
	require.Empty(t, recordNodeState(record, "worker-02"), "a removed node leaves the record")
	require.Equal(t, breakglassv1alpha1.HotfixNodeApplied, recordNodeState(record, "worker-03"))
	require.False(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionReverted)))

	// A steady state writes nothing.
	version := record.ResourceVersion
	_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(record)})
	require.NoError(t, err)
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(record), record))
	require.Equal(t, version, record.ResourceVersion)

	// Deleting the record drops its series.
	require.NoError(t, f.hub.Delete(t.Context(), record))
	_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(record)})
	require.NoError(t, err)
	require.False(t, metrics.HotfixActive.DeleteLabelValues(hotfixRecordLabels(record)...))
}

func TestHotfixRecordDriftPausesDuringApply(t *testing.T) {
	f := newHotfixFixture(t, 2, 0)
	ds := startApply(t, f, 2)
	record := &breakglassv1alpha1.HotfixRecord{}
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: ds.Status.Hotfix.RecordName}, record))
	r := NewHotfixRecordReconciler(zap.NewNop().Sugar(), f.hub, f.c.ccProvider)
	r.targetClientFactory = func(*rest.Config) (client.Client, error) { return f.spoke, nil }
	t.Cleanup(func() { deleteHotfixRecordSeries(record.Namespace + "/" + record.Name) })
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(record)})
	require.NoError(t, err)
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(record), record))
	require.Empty(t, record.Status.Nodes, "no node is uncovered while the apply runs")
}

func TestHotfixCloseWithRemovedNodeAndRetry(t *testing.T) {
	for name, prelisted := range map[string]bool{"removed node": false, "retry after the session entry": true} {
		t.Run(name, func(t *testing.T) {
			f := newHotfixFixture(t, 2, 0)
			record := appliedHotfix(t, f)
			require.NoError(t, f.spoke.Delete(t.Context(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-00"}}))
			ds := f.session(t, "close-1", &breakglassv1alpha1.DebugSessionHotfixRequest{Stage: breakglassv1alpha1.HotfixStageClose, RecordName: record.Name})
			if prelisted {
				// A previous attempt listed the session but did not set Closed.
				base := record.DeepCopy()
				record.Spec.Sessions = append(record.Spec.Sessions, breakglassv1alpha1.HotfixRecordSession{Stage: breakglassv1alpha1.HotfixStageClose,
					Name: ds.Name, UID: string(ds.UID), RequestedBy: "requester", ApprovedBy: "approver", At: metav1.Now()})
				require.NoError(t, f.hub.Patch(t.Context(), record, client.MergeFrom(base)))
			}
			ds = f.drive(t, ds)
			require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, ds.Status.State, ds.Status.Message)
			require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(record), record))
			require.True(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionClosed)))
			require.Len(t, record.Spec.Sessions, 3, "the close session is listed once")
		})
	}
}

func TestHotfixRecordDriftPausesDuringClose(t *testing.T) {
	f := newHotfixFixture(t, 2, 0)
	record := appliedHotfix(t, f)
	ds := f.session(t, "close-1", &breakglassv1alpha1.DebugSessionHotfixRequest{Stage: breakglassv1alpha1.HotfixStageClose, RecordName: record.Name})
	// The close session listed itself and removed the annotations, Closed is not set yet.
	base := record.DeepCopy()
	record.Spec.Sessions = append(record.Spec.Sessions, breakglassv1alpha1.HotfixRecordSession{Stage: breakglassv1alpha1.HotfixStageClose,
		Name: ds.Name, UID: string(ds.UID), RequestedBy: "requester", ApprovedBy: "approver", At: metav1.Now()})
	require.NoError(t, f.hub.Patch(t.Context(), record, client.MergeFrom(base)))
	for _, name := range []string{"worker-00", "worker-01"} {
		node := &corev1.Node{}
		require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: name}, node))
		delete(node.Annotations, hotfixAnnotationKey(record.Name))
		require.NoError(t, f.spoke.Update(t.Context(), node))
	}
	r := NewHotfixRecordReconciler(zap.NewNop().Sugar(), f.hub, f.c.ccProvider)
	r.targetClientFactory = func(*rest.Config) (client.Client, error) { return f.spoke, nil }
	t.Cleanup(func() { deleteHotfixRecordSeries(record.Namespace + "/" + record.Name) })
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(record)})
	require.NoError(t, err)
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(record), record))
	require.Equal(t, breakglassv1alpha1.HotfixNodeApplied, recordNodeState(record, "worker-00"), "a running close is not drift")
}
