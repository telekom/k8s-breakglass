// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var policyExceptionGVK = schema.GroupVersionKind{Group: "policies.kyverno.io", Version: "v1", Kind: "PolicyException"}

func policyExceptionNoMatch() error {
	return &meta.NoKindMatchError{GroupKind: policyExceptionGVK.GroupKind(), SearchedVersions: []string{"v1"}}
}

// unservedTarget is a target whose RESTMapper does not know PolicyException
// and whose reads and deletes of it fail as a real client would: with NoMatch
// before any request reaches the API server.
func unservedTarget(t *testing.T, funcs interceptor.Funcs) client.Client {
	t.Helper()
	isPolicyException := func(obj client.Object) bool {
		return obj.GetObjectKind().GroupVersionKind() == policyExceptionGVK
	}
	get, del, create := funcs.Get, funcs.Delete, funcs.Create
	funcs.Get = func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if isPolicyException(obj) {
			return policyExceptionNoMatch()
		}
		if get != nil {
			return get(ctx, cl, key, obj, opts...)
		}
		return cl.Get(ctx, key, obj, opts...)
	}
	funcs.Delete = func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
		if isPolicyException(obj) {
			return policyExceptionNoMatch()
		}
		if del != nil {
			return del(ctx, cl, obj, opts...)
		}
		return cl.Delete(ctx, obj, opts...)
	}
	funcs.Create = func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if isPolicyException(obj) {
			return policyExceptionNoMatch()
		}
		if create != nil {
			return create(ctx, cl, obj, opts...)
		}
		return cl.Create(ctx, obj, opts...)
	}
	funcs.List = func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if list.GetObjectKind().GroupVersionKind() == policyExceptionGVK.GroupVersion().WithKind("PolicyExceptionList") {
			return policyExceptionNoMatch()
		}
		return cl.List(ctx, list, opts...)
	}
	return fake.NewClientBuilder().WithScheme(Scheme).WithInterceptorFuncs(funcs).Build()
}

func TestIsKindNotServedError(t *testing.T) {
	gv := schema.GroupVersion{Group: "policies.kyverno.io", Version: "v1"}
	notFound := apierrors.NewNotFound(schema.GroupResource{Group: gv.Group}, gv.String())
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"nil":            {nil, false},
		"generic":        {errors.New("connection refused"), false},
		"not found":      {notFound, false},
		"no kind match":  {policyExceptionNoMatch(), true},
		"wrapped match":  {fmt.Errorf("get: %w", policyExceptionNoMatch()), true},
		"no resource":    {&meta.NoResourceMatchError{PartialResource: gv.WithResource("policyexceptions")}, true},
		"discovery 404":  {&apiutil.ErrResourceDiscoveryFailed{gv: notFound}, true},
		"discovery 503":  {&apiutil.ErrResourceDiscoveryFailed{gv: notFound, {Group: "other", Version: "v1"}: apierrors.NewServiceUnavailable("down")}, false},
		"discovery none": {&apiutil.ErrResourceDiscoveryFailed{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, isKindNotServedError(tc.err))
		})
	}
}

func unresolvedPolicyExceptionSession() *breakglassv1alpha1.DebugSession {
	return &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "unserved", Namespace: "ns", UID: "session-uid"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "mgmt"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateFailed,
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{
				Name: "policy-exception", Category: "policy-exceptions",
				APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException",
				Namespace: "breakglass-debug", ResourceName: "unserved-exception",
				Created: true, CreateOperationID: "op-1",
			}},
		},
	}
}

func TestUnservedKindCreateIsDefinitiveRejection(t *testing.T) {
	session := unresolvedPolicyExceptionSession()
	session.Status.AuxiliaryResourceStatuses = nil
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(policyExceptionGVK)
	obj.SetName("exception")
	obj.SetNamespace("breakglass-debug")
	err := applyOrRecoverAuxiliaryResource(context.Background(), unservedTarget(t, interceptor.Funcs{}), obj, session, "policy-exception")
	var rejected *auxiliaryCreateRejectedError
	require.ErrorAs(t, err, &rejected)

	tracked := obj.DeepCopy()
	err = recoverTrackedCreateResult(context.Background(), unservedTarget(t, interceptor.Funcs{}), tracked, session, policyExceptionNoMatch())
	assert.True(t, isTrackedCreateRejected(err))
}

func TestPreflightAuxiliaryKinds(t *testing.T) {
	session := unresolvedPolicyExceptionSession()
	session.Status = breakglassv1alpha1.DebugSessionStatus{}
	exception := breakglassv1alpha1.AuxiliaryResource{
		Name: "policy-exception", Category: "policy-exceptions",
		TemplateString: "apiVersion: policies.kyverno.io/v1\nkind: PolicyException\nmetadata:\n  name: {{ .session.name }}\n",
	}
	configMap := breakglassv1alpha1.AuxiliaryResource{Name: "config", Category: "config", TemplateString: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: config\n"}
	spec := func(resources ...breakglassv1alpha1.AuxiliaryResource) *breakglassv1alpha1.DebugSessionTemplateSpec {
		return &breakglassv1alpha1.DebugSessionTemplateSpec{AuxiliaryResources: resources, RequiredAuxiliaryResourceCategories: []string{"policy-exceptions", "config"}}
	}
	target := unservedTarget(t, interceptor.Funcs{})

	err := newTestAuxiliaryResourceManager().PreflightAuxiliaryKinds(context.Background(), session, spec(configMap, exception), nil, target, "breakglass-debug")
	require.ErrorIs(t, err, errAuxiliaryKindNotServed)
	assert.Contains(t, err.Error(), `auxiliary resource "policy-exception" requires policies.kyverno.io/v1 PolicyException, which target cluster "mgmt" does not serve`)

	require.NoError(t, newTestAuxiliaryResourceManager().PreflightAuxiliaryKinds(context.Background(), session, spec(configMap), nil, target, "breakglass-debug"))

	optional := exception
	optional.FailurePolicy = breakglassv1alpha1.AuxiliaryResourceFailurePolicyIgnore
	require.NoError(t, newTestAuxiliaryResourceManager().PreflightAuxiliaryKinds(context.Background(), session, spec(optional), nil, target, "breakglass-debug"),
		"optional resources fail definitively at create and follow their policy")

	disabled := newTestAuxiliaryResourceManager()
	disabled.disableUnservedKindHandling = true
	require.NoError(t, disabled.PreflightAuxiliaryKinds(context.Background(), session, spec(exception), nil, target, "breakglass-debug"))
}

func TestActivationFailsBeforeTargetWriteWhenRequiredKindIsNotServed(t *testing.T) {
	c, ds, template, _ := newDeploymentFenceFixture(t)
	c.auxiliaryMgr = newTestAuxiliaryResourceManager()
	writes := 0
	target := unservedTarget(t, interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			writes++
			return cl.Create(ctx, obj, opts...)
		},
	})
	c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return target, nil }
	template.Spec.RequiredAuxiliaryResourceCategories = []string{"policy-exceptions"}
	template.Spec.AuxiliaryResources = []breakglassv1alpha1.AuxiliaryResource{{
		Name: "policy-exception", Category: "policy-exceptions", CreateBefore: ptrBool(true),
		TemplateString: "apiVersion: policies.kyverno.io/v1\nkind: PolicyException\nmetadata:\n  name: {{ .session.name }}\n",
	}}
	err := c.deployDebugResources(context.Background(), ds, template)
	require.ErrorIs(t, err, errAuxiliaryKindNotServed)
	assert.Zero(t, writes, "preflight must fail before any target write")
	assert.Empty(t, ds.Status.AuxiliaryResourceStatuses)
	assert.Empty(t, ds.Status.DeployedResources)
}

func TestCleanupRetryAfterBacksOffExponentially(t *testing.T) {
	failing := func(since time.Duration) *breakglassv1alpha1.DebugSession {
		ds := &breakglassv1alpha1.DebugSession{}
		ds.SetCondition(metav1.Condition{Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue, Reason: "CleanupFailed", LastTransitionTime: metav1.NewTime(time.Now().Add(-since))})
		return ds
	}
	c := NewDebugSessionController(zap.NewNop().Sugar(), nil, nil)
	assert.Equal(t, ExpiredSessionRequeue, c.cleanupRetryAfter(&breakglassv1alpha1.DebugSession{}))
	assert.Equal(t, ExpiredSessionRequeue, c.cleanupRetryAfter(failing(time.Second)))
	assert.InDelta(t, float64(time.Minute), float64(c.cleanupRetryAfter(failing(time.Minute))), float64(time.Second))
	assert.Equal(t, MaxCleanupRetryBackoff, c.cleanupRetryAfter(failing(time.Hour)))
	assert.Equal(t, ExpiredSessionRequeue, c.WithCleanupBackoff(false).cleanupRetryAfter(failing(time.Hour)))
}

func TestCleanupFailedAuditIsEmittedOncePerResidualSet(t *testing.T) {
	run := func(t *testing.T, backoff bool) int {
		session := &breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "audit-dedup", Namespace: "ns", UID: "uid"},
			Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster"},
			Status: breakglassv1alpha1.DebugSessionStatus{
				State:             breakglassv1alpha1.DebugSessionStateTerminated,
				DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "target", Name: "residual", UID: "residual-uid"}},
			},
		}
		hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(session).WithStatusSubresource(session).Build()
		sink := &cleanupAuditCaptureSink{}
		auditManager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 16, WorkerCount: 1}, zap.NewNop())
		// No cluster provider: every attempt fails with the same residual.
		c := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithAuditManager(auditManager).WithCleanupBackoff(backoff)
		for range 3 {
			require.Error(t, c.cleanupResources(context.Background(), session))
		}
		// A new residual is a distinct failure and is reported again.
		require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(session), session))
		session.Status.DeployedResources = append(session.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "target", Name: "second", UID: "second-uid"})
		require.NoError(t, hub.Status().Update(context.Background(), session))
		require.Error(t, c.cleanupResources(context.Background(), session))
		require.NoError(t, auditManager.Close())
		failed := 0
		for _, event := range sink.Events() {
			if event.Type == audit.EventDebugSessionCleanupFailed {
				failed++
			}
		}
		return failed
	}
	assert.Equal(t, 2, run(t, true), "one event per distinct residual set")
	assert.Equal(t, 4, run(t, false), "opt-out restores one event per failed attempt")
}

func TestCleanupBackoffCannotBeBypassedByWatchEvents(t *testing.T) {
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{UID: "uid"}}
	ds.SetCondition(metav1.Condition{Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue, Reason: "CleanupFailed", LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Minute))})
	c := NewDebugSessionController(zap.NewNop().Sugar(), nil, nil)
	assert.Zero(t, c.cleanupBackoffRemaining(ds), "the first attempt runs at once")
	retryAfter := c.recordCleanupFailure(ds)
	remaining := c.cleanupBackoffRemaining(ds)
	assert.Greater(t, remaining, time.Duration(0), "an early reconcile waits for the recorded deadline")
	assert.LessOrEqual(t, remaining, retryAfter)

	recovered := ds.DeepCopy()
	recovered.Status.Conditions = nil
	assert.Zero(t, c.cleanupBackoffRemaining(recovered), "recovery clears the deadline")

	disabled := NewDebugSessionController(zap.NewNop().Sugar(), nil, nil).WithCleanupBackoff(false)
	disabled.recordCleanupFailure(ds)
	assert.Zero(t, disabled.cleanupBackoffRemaining(ds))
}

func TestCleanupResidualDigestSeesChangesBeyondMessageBounds(t *testing.T) {
	ds := &breakglassv1alpha1.DebugSession{}
	for i := range 40 {
		ds.Status.DeployedResources = append(ds.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
			APIVersion: "v1", Kind: "ConfigMap", Namespace: "target", Name: fmt.Sprintf("residual-with-a-long-name-%02d", i), UID: fmt.Sprintf("uid-%02d", i),
		})
	}
	before := boundedCleanupConditionMessage(ds)
	require.Len(t, before, maxCleanupConditionMessage, "message is truncated")
	ds.Status.DeployedResources = ds.Status.DeployedResources[:39]
	after := boundedCleanupConditionMessage(ds)
	assert.NotEqual(t, residualSetDigestFromMessage(before), residualSetDigestFromMessage(after), "a change past the 16-identity report and message limit is a distinct set")
	assert.Equal(t, cleanupResidualSetDigest(ds), residualSetDigestFromMessage(after))
	assert.Empty(t, residualSetDigestFromMessage("Cleanup failed; residual resources: legacy"))
}

func TestCleanupBackoffDeadlineIsReleasedWhenSessionIsDeleted(t *testing.T) {
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "gone", Namespace: "ns", UID: "uid"}}
	ds.SetCondition(metav1.Condition{Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue, Reason: "CleanupFailed", LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Minute))})
	hub := fake.NewClientBuilder().WithScheme(Scheme).Build()
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	c.recordCleanupFailure(ds)
	_, tracked := c.cleanupNotBefore.Load(client.ObjectKeyFromObject(ds))
	require.True(t, tracked)

	_, err := c.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ds)})
	require.NoError(t, err)
	_, tracked = c.cleanupNotBefore.Load(client.ObjectKeyFromObject(ds))
	assert.False(t, tracked, "a deleted session must not keep its backoff deadline")

	c.recordCleanupFailure(ds)
	recreated := ds.DeepCopy()
	recreated.UID = "new-uid"
	assert.Zero(t, c.cleanupBackoffRemaining(recreated), "a recreated session does not inherit the deadline")
}

func TestCleanupNeverRetiresResidualsOnDiscoveryAbsence(t *testing.T) {
	// A NoMatch proves nothing about stored objects: a deregistered
	// APIService keeps them, and an unresolved intent may be a committed
	// create whose response was lost. Every entry stays a residual.
	session := unresolvedPolicyExceptionSession()
	session.Status.AuxiliaryResourceStatuses = append(session.Status.AuxiliaryResourceStatuses, breakglassv1alpha1.AuxiliaryResourceStatus{
		Name: "recorded", Category: "policy-exceptions", APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException",
		Namespace: "breakglass-debug", ResourceName: "recorded", Created: true, UID: "recorded-uid",
	})
	require.Error(t, newTestAuxiliaryResourceManager().CleanupAuxiliaryResources(context.Background(), session, unservedTarget(t, interceptor.Funcs{})))
	for _, status := range session.Status.AuxiliaryResourceStatuses {
		assert.False(t, status.Deleted, status.ResourceName)
	}
}

func acknowledgedSession(t *testing.T, ids ...CleanupAcknowledgedIdentity) *breakglassv1alpha1.DebugSession {
	t.Helper()
	ds := unresolvedPolicyExceptionSession()
	ds.Status.AuxiliaryResourceStatuses[0].AdditionalResources = []breakglassv1alpha1.AdditionalResourceRef{
		{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", ResourceName: "child", UID: "child-uid"},
	}
	ds.Status.PodTemplateResourceStatuses = []breakglassv1alpha1.PodTemplateResourceStatus{
		{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", ResourceName: "pod-template", Created: true, UID: "pt-uid"},
	}
	ds.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{
		{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "deployed", UID: "deployed-uid", Source: "debug-extra"},
		{APIVersion: "v1", Kind: "ConfigMap", Namespace: "breakglass-debug", Name: "other", UID: "other-uid", Source: "debug-extra"},
	}
	setCleanupCondition(ds)
	require.True(t, cleanupConditionFailed(ds))
	raw, err := json.Marshal(ids)
	require.NoError(t, err)
	ds.Annotations = map[string]string{CleanupAcknowledgedAbsentAnnotation: string(raw)}
	return ds
}

var acknowledgedPolicyExceptions = []CleanupAcknowledgedIdentity{
	{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "unserved-exception"},
	{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "child", UID: "child-uid"},
	{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "pod-template", UID: "pt-uid"},
	{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "deployed", UID: "deployed-uid"},
}

func TestApplyCleanupAcknowledgementRetiresExactlyTheListedResiduals(t *testing.T) {
	ds := acknowledgedSession(t, acknowledgedPolicyExceptions...)
	retired, err := applyCleanupAcknowledgement(ds)
	require.NoError(t, err)
	assert.Len(t, retired, 4)
	aux := ds.Status.AuxiliaryResourceStatuses[0]
	assert.True(t, aux.Deleted)
	assert.Contains(t, aux.Error, CleanupAcknowledgedAbsentAnnotation)
	assert.True(t, aux.AdditionalResources[0].Deleted)
	assert.Empty(t, ds.Status.PodTemplateResourceStatuses)
	require.Len(t, ds.Status.DeployedResources, 1, "an unlisted residual is kept")
	assert.Equal(t, "other", ds.Status.DeployedResources[0].Name)

	again, err := applyCleanupAcknowledgement(ds)
	require.NoError(t, err)
	assert.Empty(t, again, "re-applying an already applied acknowledgement is a no-op")
}

func TestApplyCleanupAcknowledgementRejectsUnmatchedOrInvalidEntries(t *testing.T) {
	wrongUID := append([]CleanupAcknowledgedIdentity(nil), acknowledgedPolicyExceptions...)
	wrongUID[3].UID = "another-uid"
	for name, annotation := range map[string]string{
		"wrong uid":      "",
		"invalid json":   "{",
		"missing fields": `[{"kind":"PolicyException"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			ds := acknowledgedSession(t, wrongUID...)
			if annotation != "" {
				ds.Annotations[CleanupAcknowledgedAbsentAnnotation] = annotation
			}
			before := ds.Status.DeepCopy()
			retired, err := applyCleanupAcknowledgement(ds)
			require.Error(t, err)
			assert.Empty(t, retired)
			assert.Equal(t, *before, ds.Status, "nothing is retired unless every entry matches")
		})
	}
	t.Run("not failing", func(t *testing.T) {
		ds := acknowledgedSession(t, acknowledgedPolicyExceptions...)
		ds.Status.Conditions = nil
		retired, err := applyCleanupAcknowledgement(ds)
		require.NoError(t, err)
		assert.Empty(t, retired, "an acknowledgement applies only after cleanup has failed")
	})
}

func TestCleanupAcknowledgementCompletesCleanupAndIsAudited(t *testing.T) {
	ds := acknowledgedSession(t, acknowledgedPolicyExceptions...)
	ds.Status.DeployedResources = ds.Status.DeployedResources[:1]
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(ds).WithStatusSubresource(ds).Build()
	sink := &cleanupAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 16, WorkerCount: 1}, zap.NewNop())
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithAuditManager(manager)
	require.NoError(t, c.cleanupResources(context.Background(), ds))
	require.NoError(t, manager.Close())

	condition := ds.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "CleanupAcknowledged", condition.Reason)
	var acknowledged, recovered int
	for _, event := range sink.Events() {
		switch event.Type {
		case audit.EventDebugSessionCleanupAcknowledged:
			acknowledged++
			assert.Len(t, event.Details["retired"], 4)
		case audit.EventDebugSessionCleanupRecovered:
			recovered++
		}
	}
	assert.Equal(t, 1, acknowledged)
	assert.Equal(t, 1, recovered)
}

func TestNewAcknowledgementBypassesCleanupBackoff(t *testing.T) {
	ds := acknowledgedSession(t)
	ds.Annotations = nil
	c := NewDebugSessionController(zap.NewNop().Sugar(), nil, nil)
	c.recordCleanupFailure(ds)
	require.Greater(t, c.cleanupBackoffRemaining(ds), time.Duration(0))
	ds.Annotations = map[string]string{CleanupAcknowledgedAbsentAnnotation: "[]"}
	assert.Zero(t, c.cleanupBackoffRemaining(ds), "a changed acknowledgement is acted on at once")
}
