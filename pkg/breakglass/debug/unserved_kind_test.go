// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	"k8s.io/client-go/discovery"
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
	return confirmedAbsent(fake.NewClientBuilder().WithScheme(Scheme).WithInterceptorFuncs(funcs).Build())
}

// confirmedAbsent stands in for withKindDiscovery on a target whose
// discovery documents do not list the kind.
func confirmedAbsent(target client.Client) client.Client {
	return &discoveryConfirmedClient{Client: target, confirm: func(context.Context, schema.GroupKind) (bool, error) { return true, nil }}
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

func TestTargetKindNotServedRequiresVersionAgnosticProof(t *testing.T) {
	raw := fake.NewClientBuilder().WithScheme(Scheme).Build()
	assert.False(t, targetKindNotServed(context.Background(), raw, "policies.kyverno.io/v1", "PolicyException", policyExceptionNoMatch()),
		"fail closed: a RESTMapper NoMatch without discovery confirmation is never absence")
	empty := confirmedAbsent(raw)
	assert.True(t, targetKindNotServed(context.Background(), empty, "policies.kyverno.io/v1", "PolicyException", policyExceptionNoMatch()))
	assert.False(t, targetKindNotServed(context.Background(), empty, "policies.kyverno.io/v1", "PolicyException", nil), "no operation error is no proof")
	assert.False(t, targetKindNotServed(context.Background(), empty, "policies.kyverno.io/v1", "PolicyException", errors.New("timeout")))
	assert.False(t, targetKindNotServed(context.Background(), nil, "policies.kyverno.io/v1", "PolicyException", policyExceptionNoMatch()))
	assert.False(t, targetKindNotServed(context.Background(), empty, "a/b/c", "PolicyException", policyExceptionNoMatch()))

	// The kind is still served at another version: objects may exist there.
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Group: "policies.kyverno.io", Version: "v2"}})
	mapper.Add(schema.GroupVersionKind{Group: "policies.kyverno.io", Version: "v2", Kind: "PolicyException"}, meta.RESTScopeNamespace)
	otherVersion := confirmedAbsent(fake.NewClientBuilder().WithScheme(Scheme).WithRESTMapper(mapper).Build())
	assert.False(t, targetKindNotServed(context.Background(), otherVersion, "policies.kyverno.io/v1", "PolicyException", policyExceptionNoMatch()))
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

func TestCleanupAuxiliaryResourcesTreatsUnservedKindAsAbsent(t *testing.T) {
	t.Run("unresolved intent", func(t *testing.T) {
		session := unresolvedPolicyExceptionSession()
		require.NoError(t, newTestAuxiliaryResourceManager().CleanupAuxiliaryResources(context.Background(), session, unservedTarget(t, interceptor.Funcs{})))
		status := session.Status.AuxiliaryResourceStatuses[0]
		assert.True(t, status.Deleted)
		assert.NotNil(t, status.DeletedAt)
		assert.Contains(t, status.Error, "does not serve policies.kyverno.io/v1 PolicyException")
		assert.False(t, auxiliaryStatusHasCleanupResidual(session, status))
	})
	t.Run("recorded objects are retained (APIService deregistration)", func(t *testing.T) {
		// A deregistered APIService vanishes from discovery but its extension
		// server keeps the stored objects; re-registration exposes them again.
		// Only the never-resolved create is retired.
		session := unresolvedPolicyExceptionSession()
		session.Status.AuxiliaryResourceStatuses[0].UID = "recorded-uid"
		session.Status.AuxiliaryResourceStatuses[0].AdditionalResources = []breakglassv1alpha1.AdditionalResourceRef{
			{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", ResourceName: "child", UID: "child-uid"},
			{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", ResourceName: "unresolved-child", CreateOperationID: "op-2"},
		}
		require.Error(t, newTestAuxiliaryResourceManager().CleanupAuxiliaryResources(context.Background(), session, unservedTarget(t, interceptor.Funcs{})))
		status := session.Status.AuxiliaryResourceStatuses[0]
		assert.False(t, status.Deleted, "a recorded UID stays a residual")
		assert.True(t, auxiliaryStatusHasCleanupResidual(session, status))
		assert.False(t, status.AdditionalResources[0].Deleted, "a recorded child stays a residual")
		assert.True(t, status.AdditionalResources[1].Deleted, "an unresolved child create is retired")
		assert.Contains(t, status.AdditionalResources[1].Error, "does not serve")
	})
	t.Run("opt-out keeps retrying", func(t *testing.T) {
		session := unresolvedPolicyExceptionSession()
		mgr := newTestAuxiliaryResourceManager()
		mgr.disableUnservedKindHandling = true
		require.Error(t, mgr.CleanupAuxiliaryResources(context.Background(), session, unservedTarget(t, interceptor.Funcs{})))
		assert.False(t, session.Status.AuxiliaryResourceStatuses[0].Deleted)
	})
	t.Run("transient failure keeps retrying", func(t *testing.T) {
		session := unresolvedPolicyExceptionSession()
		session.Status.AuxiliaryResourceStatuses[0].UID = "recorded-uid"
		target := fake.NewClientBuilder().WithScheme(Scheme).WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return apierrors.NewServiceUnavailable("apiserver unavailable")
			},
		}).Build()
		require.Error(t, newTestAuxiliaryResourceManager().CleanupAuxiliaryResources(context.Background(), session, target))
		assert.False(t, session.Status.AuxiliaryResourceStatuses[0].Deleted)
	})
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

func TestLegacyDiscoveryKindAbsent(t *testing.T) {
	groups := `{"kind":"APIGroupList","groups":[{"name":"policies.kyverno.io","versions":[{"groupVersion":"policies.kyverno.io/v1","version":"v1"}]}]}`
	for name, tc := range map[string]struct {
		apis, version string
		status        int
		want          bool
		wantErr       bool
	}{
		"group absent":           {apis: `{"kind":"APIGroupList","groups":[]}`, want: true},
		"kind served":            {apis: groups, version: `{"kind":"APIResourceList","resources":[{"name":"policyexceptions","kind":"PolicyException"}]}`},
		"other kind only":        {apis: groups, version: `{"kind":"APIResourceList","resources":[{"name":"policies","kind":"Policy"}]}`, want: true},
		"unavailable APIService": {apis: groups, status: http.StatusServiceUnavailable, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/apis":
					_, _ = w.Write([]byte(tc.apis))
				case "/apis/policies.kyverno.io/v1":
					if tc.status != 0 {
						w.WriteHeader(tc.status)
						return
					}
					_, _ = w.Write([]byte(tc.version))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()
			dc, err := discovery.NewDiscoveryClientForConfig(&rest.Config{Host: srv.URL})
			require.NoError(t, err)
			absent, err := legacyDiscoveryKindAbsent(context.Background(), dc.RESTClient(), policyExceptionGVK.GroupKind())
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, absent)
		})
	}
	absent, err := legacyDiscoveryKindAbsent(context.Background(), nil, schema.GroupKind{Kind: "ConfigMap"})
	require.NoError(t, err)
	assert.False(t, absent, "the core group is always served")
}

func TestTargetKindNotServedHonoursDiscoveryConfirmation(t *testing.T) {
	empty := fake.NewClientBuilder().WithScheme(Scheme).Build()
	for name, tc := range map[string]struct {
		absent bool
		err    error
		want   bool
	}{
		"confirmed absent":      {absent: true, want: true},
		"stale APIService":      {absent: false},
		"discovery unreachable": {err: errors.New("dial tcp: i/o timeout")},
	} {
		t.Run(name, func(t *testing.T) {
			target := &discoveryConfirmedClient{Client: empty, confirm: func(context.Context, schema.GroupKind) (bool, error) { return tc.absent, tc.err }}
			assert.Equal(t, tc.want, targetKindNotServed(context.Background(), target, "policies.kyverno.io/v1", "PolicyException", policyExceptionNoMatch()))
		})
	}
}

func TestCleanupPodTemplateAndDeployedResourcesRetireOnlyUnresolvedIntents(t *testing.T) {
	pe := func(name, uid, op string) breakglassv1alpha1.PodTemplateResourceStatus {
		return breakglassv1alpha1.PodTemplateResourceStatus{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", ResourceName: name, Created: true, UID: uid, CreateOperationID: op}
	}
	ds := unresolvedPolicyExceptionSession()
	ds.Status.AuxiliaryResourceStatuses = nil
	ds.Status.PodTemplateResourceStatuses = []breakglassv1alpha1.PodTemplateResourceStatus{pe("unresolved", "", "op"), pe("recorded", "recorded-uid", "")}
	ds.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{
		{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "deployed", UID: "deployed-uid", Source: "debug-extra"},
	}
	c := NewDebugSessionController(zap.NewNop().Sugar(), nil, nil)
	target := unservedTarget(t, interceptor.Funcs{})
	require.Error(t, c.cleanupPodTemplateResources(context.Background(), ds, target))
	require.Len(t, ds.Status.PodTemplateResourceStatuses, 1, "the unresolved intent is retired")
	assert.Equal(t, "recorded", ds.Status.PodTemplateResourceStatuses[0].ResourceName, "a recorded object survives discovery absence")
	require.Error(t, c.cleanupDeployedResources(context.Background(), ds, target, false, false))
	assert.Len(t, ds.Status.DeployedResources, 1, "a recorded deployed object survives discovery absence")

	// Opt-out keeps the unresolved intent too.
	optOut := unresolvedPolicyExceptionSession()
	optOut.Status.AuxiliaryResourceStatuses = nil
	optOut.Status.PodTemplateResourceStatuses = []breakglassv1alpha1.PodTemplateResourceStatus{pe("unresolved", "", "op")}
	require.Error(t, c.WithUnservedKindHandling(false).cleanupPodTemplateResources(context.Background(), optOut, target))
	assert.Len(t, optOut.Status.PodTemplateResourceStatuses, 1)
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

func TestCleanupDeployedUnresolvedIntentOfUnservedKind(t *testing.T) {
	ds := unresolvedPolicyExceptionSession()
	ds.Status.AuxiliaryResourceStatuses = nil
	ds.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "intent", CreateOperationID: "op", Source: "debug-extra"}}
	require.True(t, hasUnresolvedCleanupIntent(ds), "deployed intents route cleanup to the target")
	c := NewDebugSessionController(zap.NewNop().Sugar(), nil, nil)
	require.NoError(t, c.cleanupDeployedResources(context.Background(), ds, unservedTarget(t, interceptor.Funcs{}), false, false))
	assert.Empty(t, ds.Status.DeployedResources)
}

func TestPrivilegedTargetClientsConfirmKindAbsence(t *testing.T) {
	c, ds, _, _ := newDeploymentFenceFixture(t)
	raw := fake.NewClientBuilder().WithScheme(Scheme).Build()
	c.targetClientFactory = func(*rest.Config) (client.Client, error) { return raw, nil }

	maintenance, _, release, err := c.maintenanceClient(context.Background(), ds)
	require.NoError(t, err)
	release()
	_, ok := maintenance.(kindAbsenceConfirmer)
	assert.True(t, ok, "node-maintenance cleanup must confirm absence via discovery")

	hotfix, _, _, release, err := c.hotfixClient(context.Background(), ds)
	require.NoError(t, err)
	release()
	_, ok = hotfix.(kindAbsenceConfirmer)
	assert.True(t, ok, "hotfix release must confirm absence via discovery")

	// With an unreachable discovery endpoint (the fixture spoke is
	// https://spoke.invalid) a NoMatch is never treated as absence, so the
	// auxiliary entry stays a retryable residual on both paths.
	for name, target := range map[string]client.Client{"maintenance": maintenance, "hotfix": hotfix} {
		session := unresolvedPolicyExceptionSession()
		require.Error(t, newTestAuxiliaryResourceManager().CleanupAuxiliaryResources(context.Background(), session, target), name)
		assert.False(t, session.Status.AuxiliaryResourceStatuses[0].Deleted, name)
	}
	assert.Same(t, maintenance, withKindDiscovery(maintenance, &rest.Config{}), "wrapping is idempotent")
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
