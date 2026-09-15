/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package debug

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

const unresolvedBindingNamespace = "breakglass"

func unresolvedBindingScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, breakglassv1alpha1.AddToScheme(s))
	return s
}

// approvalRequiredTemplate has approvers configured, so a session created against it
// MUST NOT activate without approval.
func approvalRequiredTemplate(name string) *breakglassv1alpha1.DebugSessionTemplate {
	return &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Groups: []string{"sre-leads"},
			},
		},
	}
}

// noApproverTemplate has no approvers at all: this is the template shape that makes
// the fail-open reachable, because losing the binding leaves nothing requiring approval.
func noApproverTemplate(name string) *breakglassv1alpha1.DebugSessionTemplate {
	return &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       breakglassv1alpha1.DebugSessionTemplateSpec{},
	}
}

func sessionWithBindingRef(name, templateRef, clusterName, bindingName string) *breakglassv1alpha1.DebugSession {
	ds := newTestDebugSession(name, templateRef, clusterName, "oncall@example.com")
	ds.Spec.BindingRef = &breakglassv1alpha1.BindingReference{
		Name:      bindingName,
		Namespace: unresolvedBindingNamespace,
	}
	return ds
}

// TestHandlePending_UnresolvableBindingRefDoesNotActivateWithoutApproval pins the
// fail-open defect.
//
// Setup reproduces the exact dangerous combination:
//   - the DebugSession names an explicit bindingRef
//   - the template has NO approvers, so approval can only come from the binding
//   - the binding lookup fails with a TRANSIENT error (not NotFound)
//
// Before the fix the error was only log.Warnw'd, flow fell through to
// findBindingForSession (which returns nil,nil when nothing matches), requiresApproval
// then saw a nil binding and an approver-less template and returned false — and the
// session was ACTIVATED with no approval at all.
func TestHandlePending_UnresolvableBindingRefDoesNotActivateWithoutApproval(t *testing.T) {
	scheme := unresolvedBindingScheme(t)
	template := noApproverTemplate("no-approver-template")
	ds := sessionWithBindingRef("fail-open-probe", template.Name, "spoke-a", "gated-binding")

	// The binding EXISTS and requires approval, but the API read fails transiently.
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "gated-binding", Namespace: unresolvedBindingNamespace},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Clusters: []string{"spoke-a"},
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Groups: []string{"sre-leads"},
			},
		},
	}

	transient := apierrors.NewInternalError(errors.New("etcdserver: request timed out"))
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ds, template, binding).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c ctrlclient.WithWatch, key ctrlclient.ObjectKey,
				obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
				if _, ok := obj.(*breakglassv1alpha1.DebugSessionClusterBinding); ok {
					return transient
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	c := &DebugSessionController{
		log:        zap.NewNop().Sugar(),
		client:     fakeClient,
		ccProvider: cluster.NewClientProvider(fakeClient, zap.NewNop().Sugar()),
	}

	res, err := c.handlePending(context.Background(), ds)

	// The reconcile must surface the error so controller-runtime retries with backoff.
	require.Error(t, err, "an unresolvable bindingRef must not be silently ignored")
	assert.Contains(t, err.Error(), "resolve bindingRef")
	assert.Contains(t, err.Error(), "gated-binding")
	assert.ErrorIs(t, err, transient, "the underlying cause must be wrapped, not swallowed")
	assert.Zero(t, res.RequeueAfter, "returning an error defers requeue timing to controller-runtime")

	// Crucially: the session must NOT have been activated.
	assert.NotEqual(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State,
		"session activated despite an unresolvable approval-carrying binding (fail-open)")

	// And it must NOT have been driven into the terminal Failed state either — that would
	// be a new lockout path for what may be a two-second apiserver blip.
	assert.NotEqual(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State,
		"a transient lookup error must not terminally fail an emergency-access session")

	// Nothing was persisted, so the object on the API server is untouched and the next
	// reconcile re-evaluates from scratch.
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(),
		ctrlclient.ObjectKeyFromObject(ds), &stored))
	assert.Empty(t, stored.Status.State)
	assert.Nil(t, stored.Status.Approval)
}

// TestHandlePending_NotFoundBindingRefIsAlsoIndeterminate covers a mistyped or deleted
// ref. It is still indeterminate rather than "no binding": we cannot know whether the
// binding that was supposed to gate this session required approval.
func TestHandlePending_NotFoundBindingRefIsAlsoIndeterminate(t *testing.T) {
	scheme := unresolvedBindingScheme(t)
	template := noApproverTemplate("no-approver-template")
	ds := sessionWithBindingRef("missing-ref", template.Name, "spoke-a", "typo-binding")

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ds, template).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	c := &DebugSessionController{
		log:        zap.NewNop().Sugar(),
		client:     fakeClient,
		ccProvider: cluster.NewClientProvider(fakeClient, zap.NewNop().Sugar()),
	}

	_, err := c.handlePending(context.Background(), ds)
	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(errors.Unwrap(err)) || apierrors.IsNotFound(err),
		"NotFound cause must be preserved for callers and logs")
	assert.NotEqual(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State)
	assert.NotEqual(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State)
}

// TestHandlePendingApproval_UnresolvableBindingRefDoesNotActivate covers the second
// site. Approval has already been granted here, but the binding can only NARROW
// AllowedPodOperations, so activating without it would grant a strictly wider set of
// pod operations than the approver actually saw.
func TestHandlePendingApproval_UnresolvableBindingRefDoesNotActivate(t *testing.T) {
	scheme := unresolvedBindingScheme(t)
	template := approvalRequiredTemplate("gated-template")
	ds := sessionWithBindingRef("approved-session", template.Name, "spoke-a", "narrowing-binding")
	ds.Status.State = breakglassv1alpha1.DebugSessionStatePendingApproval
	approvedAt := metav1.Now()
	ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{
		Required:   true,
		ApprovedAt: &approvedAt,
		ApprovedBy: "sre-lead@example.com",
	}

	transient := apierrors.NewTooManyRequests("client rate limiter", 1)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ds, template).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c ctrlclient.WithWatch, key ctrlclient.ObjectKey,
				obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
				if _, ok := obj.(*breakglassv1alpha1.DebugSessionClusterBinding); ok {
					return transient
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	c := &DebugSessionController{
		log:        zap.NewNop().Sugar(),
		client:     fakeClient,
		ccProvider: cluster.NewClientProvider(fakeClient, zap.NewNop().Sugar()),
	}

	_, err := c.handlePendingApproval(context.Background(), ds)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve bindingRef")
	assert.ErrorIs(t, err, transient)

	// State is left as PendingApproval — retryable, non-terminal, no access granted.
	assert.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, ds.Status.State,
		"an unresolvable binding must leave the session retryable, not activate or fail it")
	// The approval itself is preserved, so no re-approval is needed once the ref resolves.
	require.NotNil(t, ds.Status.Approval)
	assert.NotNil(t, ds.Status.Approval.ApprovedAt)
}

// TestHandlePending_NoBindingRefStillAutoDiscovers is the backwards-compatibility
// guarantee: sessions with NO bindingRef are completely unaffected — auto-discovery
// still runs, and an approver-less template still auto-approves exactly as before.
// The new behaviour is scoped strictly to "explicit bindingRef that failed to resolve".
func TestHandlePending_NoBindingRefStillAutoDiscovers(t *testing.T) {
	scheme := unresolvedBindingScheme(t)
	template := noApproverTemplate("no-approver-template")
	// No BindingRef at all.
	ds := newTestDebugSession("no-ref-session", template.Name, "spoke-a", "oncall@example.com")

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ds, template).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	c := &DebugSessionController{
		log:        zap.NewNop().Sugar(),
		client:     fakeClient,
		ccProvider: cluster.NewClientProvider(fakeClient, zap.NewNop().Sugar()),
	}

	_, err := c.handlePending(context.Background(), ds)
	// Activation may still fail later for unrelated reasons (no ClusterConfig in this
	// fixture); what matters is that we did NOT stop at binding resolution.
	if err != nil {
		assert.NotContains(t, err.Error(), "resolve bindingRef",
			"a session without a bindingRef must never hit the unresolved-binding path")
	}
	require.NotNil(t, ds.Status.Approval)
	assert.False(t, ds.Status.Approval.Required,
		"approver-less template must still auto-approve, exactly as before")
}

// TestHandlePending_ResolvableBindingRefUnchanged proves the happy path is untouched:
// a bindingRef that resolves and carries approvers still routes to PendingApproval.
func TestHandlePending_ResolvableBindingRefUnchanged(t *testing.T) {
	scheme := unresolvedBindingScheme(t)
	template := noApproverTemplate("no-approver-template")
	ds := sessionWithBindingRef("resolvable", template.Name, "spoke-a", "gated-binding")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "gated-binding", Namespace: unresolvedBindingNamespace},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Clusters: []string{"spoke-a"},
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Groups: []string{"sre-leads"},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ds, template, binding).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	c := &DebugSessionController{
		log:        zap.NewNop().Sugar(),
		client:     fakeClient,
		ccProvider: cluster.NewClientProvider(fakeClient, zap.NewNop().Sugar()),
	}

	res, err := c.handlePending(context.Background(), ds)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, ds.Status.State)
	require.NotNil(t, ds.Status.Approval)
	assert.True(t, ds.Status.Approval.Required)
	assert.Equal(t, DefaultDebugSessionRequeue, res.RequeueAfter)
}

// TestDeferOnUnresolvedBinding_ClassifiesReason checks the reason label that feeds both
// the audit event and the Prometheus metric, so the two failure classes stay
// distinguishable in dashboards.
func TestDeferOnUnresolvedBinding_ClassifiesReason(t *testing.T) {
	scheme := unresolvedBindingScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	c := &DebugSessionController{
		log:        zap.NewNop().Sugar(),
		client:     fakeClient,
		ccProvider: cluster.NewClientProvider(fakeClient, zap.NewNop().Sugar()),
	}

	ds := sessionWithBindingRef("classify", "tmpl", "spoke-classify", "b")

	// The reason label values must be stable snake_case, matching every other
	// label value in this codebase (e.g. "user_rejected", "policy_violation").
	// Human phrases with spaces are awkward in PromQL and invite drift.
	const (
		reasonNotFound     = "binding_not_found"
		reasonLookupFailed = "binding_lookup_failed"
	)
	notFoundBefore := testutil.ToFloat64(
		metrics.DebugSessionBindingUnresolved.WithLabelValues("spoke-classify", reasonNotFound))
	lookupFailedBefore := testutil.ToFloat64(
		metrics.DebugSessionBindingUnresolved.WithLabelValues("spoke-classify", reasonLookupFailed))

	notFound := apierrors.NewNotFound(
		schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "debugsessionclusterbindings"}, "b")
	_, err := c.deferOnUnresolvedBinding(context.Background(), ds, notFound)
	require.Error(t, err)
	assert.ErrorIs(t, err, notFound)
	assert.Equal(t, notFoundBefore+1, testutil.ToFloat64(
		metrics.DebugSessionBindingUnresolved.WithLabelValues("spoke-classify", reasonNotFound)),
		"a NotFound cause must be reported as %q", reasonNotFound)

	transient := apierrors.NewServiceUnavailable("apiserver is restarting")
	_, err = c.deferOnUnresolvedBinding(context.Background(), ds, transient)
	require.Error(t, err)
	assert.ErrorIs(t, err, transient)
	assert.Equal(t, lookupFailedBefore+1, testutil.ToFloat64(
		metrics.DebugSessionBindingUnresolved.WithLabelValues("spoke-classify", reasonLookupFailed)),
		"a transient cause must be reported as %q", reasonLookupFailed)

	// A nil BindingRef must not panic (defensive: the helper is only called when the
	// ref is set, but it must stay safe if that ever changes).
	ds.Spec.BindingRef = nil
	_, err = c.deferOnUnresolvedBinding(context.Background(), ds, transient)
	require.Error(t, err)
}
