// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestSessionAdmissionGlobalScopesAndCrashRecovery(t *testing.T) {
	one := int32(1)
	for _, scope := range []string{"total", "user", "tuple"} {
		t.Run(scope, func(t *testing.T) {
			esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "escalation", Namespace: "one", UID: "escalation-one"}, Spec: breakglassv1alpha1.BreakglassEscalationSpec{SessionLimitsOverride: &breakglassv1alpha1.SessionLimitsOverride{}}}
			if scope == "total" {
				esc.Spec.SessionLimitsOverride.MaxActiveSessionsTotal = &one
			}
			if scope == "user" {
				esc.Spec.SessionLimitsOverride.MaxActiveSessionsPerUser = &one
			}
			secondEsc := esc.DeepCopy()
			secondEsc.Name = "second"
			secondEsc.Namespace = "two"
			secondEsc.UID = "escalation-two"
			candidate := func(name, namespace, user, group string, owner *breakglassv1alpha1.BreakglassEscalation) *breakglassv1alpha1.BreakglassSession {
				return &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: types.UID(name), Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}, OwnerReferences: []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(), Controller: ptrBool(true), Kind: "BreakglassEscalation", Name: owner.Name, UID: owner.UID}}}, Spec: breakglassv1alpha1.BreakglassSessionSpec{User: user, Cluster: "cluster", GrantedGroup: group}}
			}
			a := candidate("first", "one", "user", "admin", esc)
			b := candidate("second", "two", "user", "other", secondEsc)
			if scope == "total" {
				b = candidate("second", "one", "different-user", "admin", esc)
			}
			if scope == "tuple" {
				b.Spec.GrantedGroup = "admin"
			}
			cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).WithObjects(esc, secondEsc, a, b).Build()
			manager := NewSessionManagerWithClientAndReader(cli, cli, WithQuotaNamespace("controller"))
			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(a), a))
			// Crash after committing reservation, before metadata/status publication.
			require.NoError(t, manager.reserveSession(t.Context(), a))
			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(b), b))
			require.ErrorIs(t, manager.reserveSession(t.Context(), b), quotas.ErrFull)
			restarted := NewSessionManagerWithClientAndReader(cli, cli, WithQuotaNamespace("controller"))
			require.NoError(t, restarted.recoverSessionAdmissions(t.Context()))
			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(a), a))
			assert.Equal(t, quotas.Ready, a.Annotations[quotas.AdmissionAnnotation])
			assert.Equal(t, breakglassv1alpha1.SessionStatePending, a.Status.State)
			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(b), b))
			assert.Equal(t, breakglassv1alpha1.SessionStateRejected, b.Status.State)
		})
	}
}

func TestProvisionalSessionCannotGrantAccessOrApproval(t *testing.T) {
	for _, state := range []breakglassv1alpha1.BreakglassSessionState{breakglassv1alpha1.SessionStatePending, breakglassv1alpha1.SessionStateApproved} {
		s := breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}}, Status: breakglassv1alpha1.BreakglassSessionStatus{State: state}}
		assert.False(t, IsSessionValid(s))
		assert.False(t, IsSessionPendingApproval(s))
		assert.False(t, IsSessionAccessActive(s))
		assert.False(t, isSessionTokenValid(s))
	}
}

func TestClockInjectedAuthorizationRejectsPendingQuotaAdmission(t *testing.T) {
	now := time.Now()
	expiresAt := metav1.NewTime(now.Add(time.Hour))
	session := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}},
		Status:     breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateApproved, ExpiresAt: expiresAt},
	}
	assert.False(t, IsSessionAccessActiveAt(session, now))
	assert.False(t, isSessionTokenValidAt(session, now))

	session.Annotations[quotas.AdmissionAnnotation] = quotas.Ready
	assert.True(t, IsSessionAccessActiveAt(session, now))
	assert.True(t, isSessionTokenValidAt(session, now))
}

func TestReservationRejectsTerminalOrRecreatedSession(t *testing.T) {
	s := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "new"}, Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateRejected}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).WithObjects(s).Build()
	sm := NewSessionManagerWithClientAndReader(cli, cli, WithQuotaNamespace("controller"))
	desired := *s
	desired.UID = "old"
	desired.Status.State = breakglassv1alpha1.SessionStateApproved
	require.Error(t, sm.UpdateBreakglassSessionStatus(context.Background(), desired))
	current := &breakglassv1alpha1.BreakglassSession{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(s), current))
	assert.Equal(t, breakglassv1alpha1.SessionStateRejected, current.Status.State)
}

type failInitialQuotaStatusClient struct {
	client.Client
	fail bool
}
type failInitialQuotaStatusWriter struct {
	client.SubResourceWriter
	owner *failInitialQuotaStatusClient
}

func (c *failInitialQuotaStatusClient) Status() client.SubResourceWriter {
	return failInitialQuotaStatusWriter{SubResourceWriter: c.Client.Status(), owner: c}
}
func (w failInitialQuotaStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if w.owner.fail {
		w.owner.fail = false
		return fmt.Errorf("injected initial status failure")
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func TestQuotaReservationSurvivesInitialStatusFailure(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "escalation", Namespace: "ns", UID: "esc"}}
	s := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session", Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}, OwnerReferences: []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(), Controller: ptrBool(true), Kind: "BreakglassEscalation", Name: esc.Name, UID: esc.UID}}}, Spec: breakglassv1alpha1.BreakglassSessionSpec{User: "user", Cluster: "cluster", GrantedGroup: "admin"}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).WithObjects(esc, s).Build()
	faulty := &failInitialQuotaStatusClient{Client: cli, fail: true}
	sm := NewSessionManagerWithClientAndReader(faulty, cli, WithQuotaNamespace("controller"))
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(s), s))
	require.NoError(t, sm.admitSession(t.Context(), s))
	s.Status.State = breakglassv1alpha1.SessionStatePending
	require.ErrorContains(t, sm.UpdateBreakglassSessionStatus(t.Context(), *s), "injected initial status failure")
	require.NoError(t, sm.recoverSessionAdmissions(t.Context()))
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(s), s))
	assert.Equal(t, breakglassv1alpha1.SessionStatePending, s.Status.State)
	assert.Equal(t, quotas.Ready, s.Annotations[quotas.AdmissionAnnotation])
}

func TestQuotaAdmissionCompletionRetriesSameUIDConflict(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "escalation", Namespace: "ns", UID: "esc"}}
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session", Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}, OwnerReferences: []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation", Name: esc.Name, UID: esc.UID, Controller: ptrBool(true)}}},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{User: "user", Cluster: "cluster", GrantedGroup: "admin"},
	}
	injected := false
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		WithObjects(esc, session).WithInterceptorFuncs(interceptor.Funcs{
		Patch: func(ctx context.Context, underlying client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			candidate, ok := obj.(*breakglassv1alpha1.BreakglassSession)
			if !injected && ok && candidate.Annotations[quotas.AdmissionAnnotation] == quotas.Ready {
				injected = true
				var concurrent breakglassv1alpha1.BreakglassSession
				require.NoError(t, underlying.Get(ctx, client.ObjectKeyFromObject(session), &concurrent))
				concurrent.Labels = map[string]string{"concurrent": "update"}
				require.NoError(t, underlying.Update(ctx, &concurrent))
			}
			return underlying.Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	manager := NewSessionManagerWithClientAndReader(cli, cli, WithQuotaNamespace("controller"))
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.NoError(t, manager.admitSession(t.Context(), session))
	var stored breakglassv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), &stored))
	assert.Equal(t, quotas.Ready, stored.Annotations[quotas.AdmissionAnnotation])
	assert.Equal(t, "update", stored.Labels["concurrent"])
	assert.True(t, injected)
}

func TestQuotaAdmissionCompletionRejectsUIDReplacement(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "escalation", Namespace: "ns", UID: "esc"}}
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session", Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{User: "user", Cluster: "cluster", GrantedGroup: "admin"},
	}
	controller := true
	session.OwnerReferences = []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation", Name: esc.Name, UID: esc.UID, Controller: &controller}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(esc, session).WithInterceptorFuncs(interceptor.Funcs{
		Patch: func(ctx context.Context, underlying client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			candidate, ok := obj.(*breakglassv1alpha1.BreakglassSession)
			if ok && candidate.Annotations[quotas.AdmissionAnnotation] == quotas.Ready {
				var replacement breakglassv1alpha1.BreakglassSession
				require.NoError(t, underlying.Get(ctx, client.ObjectKeyFromObject(session), &replacement))
				replacement.UID = "replacement"
				replacement.Labels = map[string]string{"replacement": "true"}
				require.NoError(t, underlying.Update(ctx, &replacement))
			}
			return underlying.Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	manager := NewSessionManagerWithClientAndReader(cli, cli, WithQuotaNamespace("controller"))
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.Error(t, manager.admitSession(t.Context(), session))
	var stored breakglassv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), &stored))
	assert.Equal(t, types.UID("replacement"), stored.UID)
	assert.Equal(t, "true", stored.Labels["replacement"])
	assert.Equal(t, quotas.Pending, stored.Annotations[quotas.AdmissionAnnotation])
}

func TestQuotaAdmissionCompletionRejectsTerminalTransition(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "escalation", Namespace: "ns", UID: "esc"}}
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session", Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{User: "user", Cluster: "cluster", GrantedGroup: "admin"},
	}
	controller := true
	session.OwnerReferences = []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation", Name: esc.Name, UID: esc.UID, Controller: &controller}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).WithObjects(esc, session).WithInterceptorFuncs(interceptor.Funcs{
		Patch: func(ctx context.Context, underlying client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			candidate, ok := obj.(*breakglassv1alpha1.BreakglassSession)
			if ok && candidate.Annotations[quotas.AdmissionAnnotation] == quotas.Ready {
				var terminal breakglassv1alpha1.BreakglassSession
				require.NoError(t, underlying.Get(ctx, client.ObjectKeyFromObject(session), &terminal))
				terminal.Status.State = breakglassv1alpha1.SessionStateRejected
				terminal.Status.ReasonEnded = "concurrent rejection"
				require.NoError(t, underlying.Status().Update(ctx, &terminal))
			}
			return underlying.Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	manager := NewSessionManagerWithClientAndReader(cli, cli, WithQuotaNamespace("controller"))
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.Error(t, manager.admitSession(t.Context(), session))
	var stored breakglassv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), &stored))
	assert.Equal(t, breakglassv1alpha1.SessionStateRejected, stored.Status.State)
	assert.Equal(t, "concurrent rejection", stored.Status.ReasonEnded)
	assert.Equal(t, quotas.Pending, stored.Annotations[quotas.AdmissionAnnotation])
}

func TestDurableQuotaLimitPrecedence(t *testing.T) {
	one, two, three := int32(1), int32(2), int32(3)
	idp := &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "idp"}, Spec: breakglassv1alpha1.IdentityProviderSpec{SessionLimits: &breakglassv1alpha1.SessionLimits{MaxActiveSessionsPerUser: &one, GroupOverrides: []breakglassv1alpha1.SessionLimitGroupOverride{{Group: "platform-*", MaxActiveSessionsPerUser: &two}}}}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(idp).Build()
	sm := NewSessionManagerWithClientAndReader(cli, cli, WithQuotaNamespace("controller"))
	session := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"breakglass.t-caas.telekom.com/quota-user-groups": `["platform-team"]`}}, Spec: breakglassv1alpha1.BreakglassSessionSpec{User: "user", Cluster: "cluster", GrantedGroup: "admin", IdentityProviderName: idp.Name}}
	esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{UID: "esc"}, Spec: breakglassv1alpha1.BreakglassEscalationSpec{SessionLimitsOverride: &breakglassv1alpha1.SessionLimitsOverride{MaxActiveSessionsTotal: &three}}}
	limits, err := sm.sessionQuotaLimits(t.Context(), session, esc)
	require.NoError(t, err)
	assert.Equal(t, two, limits[sessionScope("user", "user")])
	assert.Equal(t, three, limits[sessionScope("escalation", "esc")])
	esc.Spec.SessionLimitsOverride.MaxActiveSessionsPerUser = &three
	limits, err = sm.sessionQuotaLimits(t.Context(), session, esc)
	require.NoError(t, err)
	assert.Equal(t, three, limits[sessionScope("user", "user")])
	esc.Spec.SessionLimitsOverride.Unlimited = true
	limits, err = sm.sessionQuotaLimits(t.Context(), session, esc)
	require.NoError(t, err)
	assert.Equal(t, map[string]int32{sessionScope("tuple", "user", "cluster", "admin"): 1}, limits)
}

func TestQuotaAdmissionPreservesProviderApprovalHistory(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "ns", UID: "esc"}}
	s := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session", Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}, OwnerReferences: []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(), Controller: ptrBool(true), Kind: "BreakglassEscalation", Name: esc.Name, UID: esc.UID}}}, Spec: breakglassv1alpha1.BreakglassSessionSpec{User: "subject-a", Cluster: "cluster", GrantedGroup: "admin", IdentityProviderName: "idp-a", IdentityProviderIssuer: "https://a.example"}, Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending}}
	recordApprover(&s.Status, "same@example.com", "idp-a")
	idp := &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "idp-a"}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(s).WithObjects(esc, idp, s).Build()
	sm := NewSessionManagerWithClientAndReader(cli, cli, WithQuotaNamespace("controller"))
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(s), s))
	originalSpec := s.Spec
	assert.False(t, IsSessionPendingApproval(*s))
	assert.False(t, IsSessionAccessActive(*s))
	// Admission updates metadata without changing the authenticated requester or approvals.
	require.NoError(t, sm.admitSession(t.Context(), s))
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(s), s))
	assert.Equal(t, originalSpec, s.Spec)
	assert.True(t, IsSessionPendingApproval(*s))
	stale := s.DeepCopy()
	recordApprover(&s.Status, "same@example.com", "idp-b")
	require.NoError(t, sm.UpdateBreakglassSessionStatus(t.Context(), *s))
	stale.Status.State = breakglassv1alpha1.SessionStateApproved
	require.True(t, apierrors.IsConflict(sm.UpdateBreakglassSessionStatus(t.Context(), *stale)))
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(s), s))
	assert.Equal(t, originalSpec, s.Spec)
	assert.Equal(t, breakglassv1alpha1.SessionStatePending, s.Status.State)
	assert.Equal(t, []string{"same@example.com", "same@example.com"}, s.Status.Approvers)
	assert.Equal(t, []string{"idp-a", "idp-b"}, s.Status.ApproverIdentityProviders)
	assert.Equal(t, quotas.Ready, s.Annotations[quotas.AdmissionAnnotation])
}

func TestQuotaRequiresUnambiguousControllingEscalation(t *testing.T) {
	valid := metav1.OwnerReference{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation", Name: "esc", UID: "esc", Controller: ptrBool(true)}
	other := valid
	other.Name, other.UID = "other", "other"
	for _, tc := range []struct {
		name   string
		owners []metav1.OwnerReference
		valid  bool
	}{
		{"valid", []metav1.OwnerReference{valid}, true},
		{"unrelated noncontroller", []metav1.OwnerReference{valid, {Kind: "Other", Name: "other", UID: "other"}}, true},
		{"two forward", []metav1.OwnerReference{valid, other}, false},
		{"two reverse", []metav1.OwnerReference{other, valid}, false},
		{"noncontroller", []metav1.OwnerReference{{APIVersion: valid.APIVersion, Kind: valid.Kind, Name: valid.Name, UID: valid.UID}}, false},
		{"wrong API", []metav1.OwnerReference{{APIVersion: "other/v1", Kind: valid.Kind, Name: valid.Name, UID: valid.UID, Controller: ptrBool(true)}}, false},
		{"missing UID", []metav1.OwnerReference{{APIVersion: valid.APIVersion, Kind: valid.Kind, Name: valid.Name, Controller: ptrBool(true)}}, false},
		{"different controller", []metav1.OwnerReference{valid, {Kind: "Other", Name: "other", UID: "other", Controller: ptrBool(true)}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "ns", UID: "esc"}}
			alternative := esc.DeepCopy()
			alternative.Name, alternative.UID = "other", "other"
			alternative.Spec.SessionLimitsOverride = &breakglassv1alpha1.SessionLimitsOverride{MaxActiveSessionsTotal: ptrInt32(0)}
			session := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session", OwnerReferences: tc.owners, Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}}}
			cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(session).WithObjects(esc, alternative, session).Build()
			sm := NewSessionManagerWithClientAndReader(cli, cli, WithQuotaNamespace("controller"))
			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), session))
			entry, err := regularQuotaEntry(session)
			if tc.valid {
				require.NoError(t, err)
				require.Contains(t, entry.Scopes, sessionScope("escalation", "esc"))
				require.NotContains(t, entry.Scopes, sessionScope("escalation", "other"))
				require.NoError(t, sm.admitSession(t.Context(), session))
			} else {
				require.Error(t, err)
				require.Error(t, sm.admitSession(t.Context(), session))
				require.NoError(t, sm.recoverSessionAdmissions(t.Context()))
				require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), session))
				require.Equal(t, quotas.Pending, session.Annotations[quotas.AdmissionAnnotation])
				require.Empty(t, session.Status.State)
			}
		})
	}
}

func TestQuotaRejectsRecreatedEscalation(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "ns", UID: "replacement"}}
	session := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session", Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}, OwnerReferences: []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation", Name: esc.Name, UID: "old", Controller: ptrBool(true)}}}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(esc, session).Build()
	sm := NewSessionManagerWithClientAndReader(cli, cli, WithQuotaNamespace("controller"))
	require.ErrorContains(t, sm.reserveSession(t.Context(), session), "escalation UID changed")
	require.NoError(t, sm.recoverSessionAdmissions(t.Context()))
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.Empty(t, session.Status.State)
}

func TestQuotaMalformedLegacyOwnerRetainsRecordedReservation(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "ns", UID: "esc"}}
	owner := metav1.OwnerReference{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation", Name: esc.Name, UID: esc.UID, Controller: ptrBool(true)}
	legacy := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "ns", UID: "legacy"}, Spec: breakglassv1alpha1.BreakglassSessionSpec{User: "legacy"}, Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending}}
	candidate := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "candidate", Namespace: "ns", UID: "candidate", OwnerReferences: []metav1.OwnerReference{owner}, Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}}, Spec: breakglassv1alpha1.BreakglassSessionSpec{User: "candidate"}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(legacy).WithObjects(esc, legacy, candidate).Build()
	sm := NewSessionManagerWithClientAndReader(cli, cli, WithQuotaNamespace("controller"))
	require.ErrorContains(t, sm.reserveSession(t.Context(), candidate), "legacy session ns/legacy quota owner")
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(legacy), legacy))
	legacy.OwnerReferences = []metav1.OwnerReference{owner}
	require.NoError(t, cli.Update(t.Context(), legacy))
	require.NoError(t, sm.reserveSession(t.Context(), legacy))
	// Later metadata corruption cannot make the already-recorded UID disappear.
	legacy.OwnerReferences = nil
	require.NoError(t, cli.Update(t.Context(), legacy))
	require.NoError(t, sm.reserveSession(t.Context(), candidate))
	list := &corev1.ConfigMapList{}
	require.NoError(t, cli.List(t.Context(), list, client.InNamespace("controller")))
	require.Len(t, list.Items, 1)
	var state struct {
		Entries map[string]quotas.Entry `json:"entries"`
	}
	require.NoError(t, json.Unmarshal([]byte(list.Items[0].Data["ledger"]), &state))
	require.Contains(t, state.Entries, "legacy")
	require.Contains(t, state.Entries, "candidate")
	require.Contains(t, state.Entries["legacy"].Scopes, sessionScope("escalation", string(esc.UID)))
}

type replacedRecoveryEscalationReader struct {
	client.Reader
	reads int
}

func (r *replacedRecoveryEscalationReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := r.Reader.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if escalation, ok := obj.(*breakglassv1alpha1.BreakglassEscalation); ok {
		r.reads++
		if r.reads == 2 {
			escalation.UID = "replacement"
		}
	}
	return nil
}
func TestQuotaRecoveryRechecksEscalationUIDBeforeTimeout(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "ns", UID: "esc"}}
	session := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session", Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}, OwnerReferences: []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation", Name: esc.Name, UID: esc.UID, Controller: ptrBool(true)}}}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(session).WithObjects(esc, session).Build()
	reader := &replacedRecoveryEscalationReader{Reader: cli}
	sm := NewSessionManagerWithClientAndReader(cli, reader, WithQuotaNamespace("controller"))
	require.ErrorContains(t, sm.recoverSessionAdmissions(t.Context()), "resolve recovery escalation: quota escalation UID changed")
	require.Equal(t, 2, reader.reads)
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.Empty(t, session.Status.State)
	require.True(t, session.Status.TimeoutAt.IsZero())
	require.False(t, IsSessionAccessActive(*session))
}

// Only List uses the stale informer; durable reads and writes use the live client.
type staleQuotaPrecheckClient struct {
	client.Client
	cache        client.Reader
	indexedLists int
}

func (c *staleQuotaPrecheckClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	options := &client.ListOptions{}
	for _, opt := range opts {
		opt.ApplyToList(options)
	}
	if options.FieldSelector != nil && !options.FieldSelector.Empty() {
		c.indexedLists++
	}
	return c.cache.List(ctx, list, opts...)
}

type countedQuotaReader struct {
	client.Reader
	lists int
}

func (r *countedQuotaReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	r.lists++
	return r.Reader.List(ctx, list, opts...)
}
func TestIndexedQuotaPrecheckRequiresDurableAdmission(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(fmt.Sprint(durable), func(t *testing.T) {
			esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "ns", UID: "esc"}, Spec: breakglassv1alpha1.BreakglassEscalationSpec{SessionLimitsOverride: &breakglassv1alpha1.SessionLimitsOverride{MaxActiveSessionsTotal: ptrInt32(1), MaxActiveSessionsPerUser: ptrInt32(1)}}}
			owner := metav1.OwnerReference{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation", Name: esc.Name, UID: esc.UID, Controller: ptrBool(true)}
			existing := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "existing", Namespace: "ns", UID: "existing", OwnerReferences: []metav1.OwnerReference{owner}}, Spec: breakglassv1alpha1.BreakglassSessionSpec{User: "user"}, Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending}}
			candidate := existing.DeepCopy()
			candidate.Name, candidate.UID = "candidate", "candidate"
			candidate.Annotations = map[string]string{quotas.AdmissionAnnotation: quotas.Pending}
			candidate.Spec.GrantedGroup = "different"
			live := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(existing).WithObjects(esc, existing, candidate).Build()
			cache := fake.NewClientBuilder().WithScheme(Scheme).
				WithIndex(&breakglassv1alpha1.BreakglassSession{}, "spec.user", func(obj client.Object) []string {
					return []string{obj.(*breakglassv1alpha1.BreakglassSession).Spec.User}
				}).
				WithIndex(&breakglassv1alpha1.BreakglassSession{}, "status.state", func(obj client.Object) []string {
					return []string{string(obj.(*breakglassv1alpha1.BreakglassSession).Status.State)}
				}).Build()
			cached := &staleQuotaPrecheckClient{Client: live, cache: cache}
			reader := &countedQuotaReader{Reader: live}
			sm := NewSessionManagerWithClientAndReader(cached, reader)
			if durable {
				WithQuotaNamespace("controller")(sm)
			}
			wc := &BreakglassSessionController{sessionManager: sm}
			userErr := wc.checkUserSessionCount(t.Context(), "user", 1, "test", zap.NewNop().Sugar())
			totalErr := wc.checkTotalSessionCount(t.Context(), esc, 1, "test", zap.NewNop().Sugar())
			if durable {
				require.NoError(t, userErr)
				require.NoError(t, totalErr)
				require.Equal(t, 4, cached.indexedLists)
				require.Zero(t, reader.lists)
				require.NoError(t, live.Get(t.Context(), client.ObjectKeyFromObject(candidate), candidate))
				require.ErrorIs(t, sm.admitSession(t.Context(), candidate), quotas.ErrFull)
				require.Positive(t, reader.lists)
				require.NoError(t, live.Get(t.Context(), client.ObjectKeyFromObject(candidate), candidate))
				require.Equal(t, breakglassv1alpha1.SessionStateRejected, candidate.Status.State)
				require.False(t, IsSessionAccessActive(*candidate))
			} else {
				require.ErrorContains(t, userErr, "session limit reached")
				require.ErrorContains(t, totalErr, "session limit reached")
				require.Zero(t, cached.indexedLists)
				require.Equal(t, 2, reader.lists)
			}
		})
	}
}
