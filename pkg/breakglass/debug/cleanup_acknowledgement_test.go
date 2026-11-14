// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var acknowledgedPolicyExceptions = []CleanupAcknowledgedIdentity{
	{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "unserved-exception"},
	{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "child", UID: "child-uid"},
	{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "pod-template", UID: "pt-uid"},
	{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "deployed", UID: "deployed-uid"},
}

// failingSession has residuals of every inventory kind plus an unlisted one.
func failingSession(t *testing.T) *breakglassv1alpha1.DebugSession {
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
	return ds
}

func acknowledgement(ds *breakglassv1alpha1.DebugSession, name string, ids ...CleanupAcknowledgedIdentity) *breakglassv1alpha1.DebugSessionCleanupAcknowledgement {
	return &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ds.Namespace, UID: types.UID("uid-" + name)},
		Spec: breakglassv1alpha1.DebugSessionCleanupAcknowledgementSpec{
			SessionName: ds.Name, SessionUID: string(ds.UID), Identities: ids,
			AcknowledgedBy: "operator@example.com", Reason: "CHG-1663: Kyverno CRDs removed",
		},
	}
}

func TestApplyCleanupAcknowledgementRetiresExactlyTheListedResiduals(t *testing.T) {
	ds := failingSession(t)
	record := applyCleanupAcknowledgement(ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...), "")
	assert.True(t, record.Applied)
	assert.Equal(t, "operator@example.com", record.AcknowledgedBy)
	assert.Len(t, record.Retired, 4)
	aux := ds.Status.AuxiliaryResourceStatuses[0]
	assert.True(t, aux.Deleted)
	assert.Equal(t, acknowledgedAbsentReason, aux.Error)
	assert.True(t, aux.AdditionalResources[0].Deleted)
	assert.Empty(t, ds.Status.PodTemplateResourceStatuses)
	require.Len(t, ds.Status.DeployedResources, 1, "an unlisted residual is kept")
	assert.Equal(t, "other", ds.Status.DeployedResources[0].Name)
	require.Len(t, ds.Status.CleanupAcknowledgements, 1)
	assert.True(t, acknowledgementProcessed(ds, "uid-a"))
}

type ackFixture struct {
	ds      *breakglassv1alpha1.DebugSession
	hub     client.Client
	c       *DebugSessionController
	sink    *cleanupAuditCaptureSink
	manager *audit.Manager
}

func newAckFixture(t *testing.T, ds *breakglassv1alpha1.DebugSession, acks ...*breakglassv1alpha1.DebugSessionCleanupAcknowledgement) *ackFixture {
	t.Helper()
	objects := []client.Object{ds}
	for _, ack := range acks {
		objects = append(objects, ack)
	}
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(objects...).
		WithStatusSubresource(ds, &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}).Build()
	sink := &cleanupAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 32, WorkerCount: 1}, zap.NewNop())
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithAuditManager(manager)
	c.acknowledgementWebhookActive = webhookActive
	return &ackFixture{ds: ds, hub: hub, c: c, sink: sink, manager: manager}
}

func (f *ackFixture) events(t *testing.T, eventType audit.EventType) []*audit.Event {
	t.Helper()
	require.NoError(t, f.manager.Close())
	var out []*audit.Event
	for _, event := range f.sink.Events() {
		if event.Type == eventType {
			out = append(out, event)
		}
	}
	return out
}

func TestCleanupAcknowledgementIsAuditedWithTheOperatorAsActor(t *testing.T) {
	ds := failingSession(t)
	ds.Status.DeployedResources = ds.Status.DeployedResources[:1]
	f := newAckFixture(t, ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...))
	_ = f.c.cleanupResources(context.Background(), ds)
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKeyFromObject(ds), ds))
	_ = f.c.cleanupResources(context.Background(), ds) // a second attempt processes nothing again
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKeyFromObject(ds), ds))
	acks := f.events(t, audit.EventDebugSessionCleanupAcknowledged)
	require.Len(t, acks, 1)
	assert.Equal(t, "operator@example.com", acks[0].Actor.User)
	assert.Equal(t, true, acks[0].Details["applied"])
	assert.Equal(t, "CHG-1663: Kyverno CRDs removed", acks[0].Details["reason"])
	assert.Equal(t, "DebugSessionCleanupAcknowledgement", acks[0].Details["source"])
	assert.Equal(t, "a", acks[0].Details["acknowledgement"])
	condition := ds.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "CleanupAcknowledged", condition.Reason, "the reason survives the second reconcile")
}

func TestStaleWriterCannotRestoreAcknowledgedAuxiliaryDeletion(t *testing.T) {
	ds := failingSession(t)
	f := newAckFixture(t, ds)
	baseline := ds.Status.DeepCopy()
	acknowledged, stale := ds.DeepCopy(), ds.DeepCopy()
	applyCleanupAcknowledgement(acknowledged, acknowledgement(ds, "a", acknowledgedPolicyExceptions[0], acknowledgedPolicyExceptions[1]), "")
	require.NoError(t, f.c.patchDebugSessionCleanupStatus(context.Background(), acknowledged, baseline))
	stale.Status.AuxiliaryResourceStatuses[0].Error = "stale retry"
	require.NoError(t, f.c.patchDebugSessionCleanupStatus(context.Background(), stale, baseline))
	persisted := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKeyFromObject(ds), persisted))
	aux := persisted.Status.AuxiliaryResourceStatuses[0]
	assert.True(t, aux.Deleted, "acknowledged primary deletion is monotonic")
	assert.True(t, aux.AdditionalResources[0].Deleted, "acknowledged child deletion is monotonic")
}

// fakeListOnly serves a stale acknowledgement list, as a replica would before
// observing another replica's writes.
type fakeListOnly struct {
	client.Client
	ack *breakglassv1alpha1.DebugSessionCleanupAcknowledgement
}

func (f fakeListOnly) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if l, ok := list.(*breakglassv1alpha1.DebugSessionCleanupAcknowledgementList); ok {
		l.Items = []breakglassv1alpha1.DebugSessionCleanupAcknowledgement{*f.ack}
		return nil
	}
	return f.Client.List(ctx, list, opts...)
}

func TestCleanupAcknowledgementRefusedWithoutValidatingWebhook(t *testing.T) {
	ds := failingSession(t)
	f := newAckFixture(t, ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...))
	f.c.acknowledgementWebhookActive = f.c.cleanupAcknowledgementWebhookActive // no configuration in the fake hub
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	status := acknowledgementPhase(t, f, "a")
	assert.Equal(t, breakglassv1alpha1.CleanupAcknowledgementRejected, status.Phase)
	assert.Contains(t, status.Message, "validating webhook")
	assert.False(t, ds.Status.AuxiliaryResourceStatuses[0].Deleted, "an unverifiable acknowledgement retires nothing")
	acks := f.events(t, audit.EventDebugSessionCleanupAcknowledged)
	require.Len(t, acks, 1)
	assert.Equal(t, false, acks[0].Details["applied"])
}

func TestCleanupAcknowledgementWebhookActive(t *testing.T) {
	installed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fail, ignore := admissionregistrationv1.Fail, admissionregistrationv1.Ignore
	config := func(mutate func(*admissionregistrationv1.ValidatingWebhook)) *admissionregistrationv1.ValidatingWebhookConfiguration {
		webhook := admissionregistrationv1.ValidatingWebhook{Name: cleanupAcknowledgementWebhookName, FailurePolicy: &fail, Rules: []admissionregistrationv1.RuleWithOperations{{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
			Rule: admissionregistrationv1.Rule{APIGroups: []string{breakglassv1alpha1.GroupVersion.Group}, APIVersions: []string{"v1alpha1"},
				Resources: []string{"debugsessioncleanupacknowledgements"}},
		}}}
		if mutate != nil {
			mutate(&webhook)
		}
		return &admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-validating-webhook-configuration", CreationTimestamp: metav1.NewTime(installed)},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{webhook}}
	}
	for name, tc := range map[string]struct {
		objects []client.Object
		want    bool
	}{
		"none":          {},
		"active":        {objects: []client.Object{config(nil)}, want: true},
		"ignore policy": {objects: []client.Object{config(func(w *admissionregistrationv1.ValidatingWebhook) { w.FailurePolicy = &ignore })}},
		"update only": {objects: []client.Object{config(func(w *admissionregistrationv1.ValidatingWebhook) {
			w.Rules[0].Operations = []admissionregistrationv1.OperationType{admissionregistrationv1.Update}
		})}},
		"other version": {objects: []client.Object{config(func(w *admissionregistrationv1.ValidatingWebhook) { w.Rules[0].APIVersions = []string{"v1beta1"} })}},
		"object selector": {objects: []client.Object{config(func(w *admissionregistrationv1.ValidatingWebhook) {
			w.ObjectSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"x": "y"}}
		})}},
		"cluster scope": {objects: []client.Object{config(func(w *admissionregistrationv1.ValidatingWebhook) {
			scope := admissionregistrationv1.ClusterScope
			w.Rules[0].Scope = &scope
		})}},
		"namespaced scope": {objects: []client.Object{config(func(w *admissionregistrationv1.ValidatingWebhook) {
			scope := admissionregistrationv1.NamespacedScope
			w.Rules[0].Scope = &scope
		})}, want: true},
		"wrong name": {objects: []client.Object{config(func(w *admissionregistrationv1.ValidatingWebhook) { w.Name = "other.validation.example.com" })}},
		"namespace selector": {objects: []client.Object{config(func(w *admissionregistrationv1.ValidatingWebhook) {
			w.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"x": "y"}}
		})}},
		"ignore on a second entry": {objects: []client.Object{func() client.Object {
			c := config(func(w *admissionregistrationv1.ValidatingWebhook) { w.FailurePolicy = &ignore })
			c.Name = "second"
			return c
		}()}},
		"no server-set creation time": {objects: []client.Object{func() client.Object {
			c := config(nil)
			c.CreationTimestamp = metav1.Time{}
			return c
		}()}},
		"match condition": {objects: []client.Object{config(func(w *admissionregistrationv1.ValidatingWebhook) {
			w.MatchConditions = []admissionregistrationv1.MatchCondition{{Name: "skip", Expression: "false"}}
		})}},
	} {
		t.Run(name, func(t *testing.T) {
			hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(tc.objects...).Build()
			active, since, err := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).cleanupAcknowledgementWebhookActive(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.want, active)
			if active {
				assert.Equal(t, installed, since.UTC())
			}
		})
	}
}

func TestPartialAcknowledgementReportsTheRemainingResidualSet(t *testing.T) {
	ds := failingSession(t) // residuals include the unlisted "other"
	f := newAckFixture(t, ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...))
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	require.True(t, cleanupConditionFailed(ds))
	failed := f.events(t, audit.EventDebugSessionCleanupFailed)
	require.Len(t, failed, 1, "the remaining residual set is reported once")
	assert.Equal(t, []string{"breakglass-debug/v1/ConfigMap/other (uid=other-uid)"}, failed[0].Details["residuals"])
}

func TestCleanupAcknowledgementPrecedesModeSpecificCleanup(t *testing.T) {
	ds := failingSession(t)
	ds.Status.NodeMaintenance = &breakglassv1alpha1.NodeMaintenanceStatus{OperationID: "op"}
	f := newAckFixture(t, ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...))
	require.Error(t, f.c.cleanupResources(context.Background(), ds), "maintenance cleanup cannot run without a cluster provider")
	persisted := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKeyFromObject(ds), persisted))
	require.Len(t, persisted.Status.CleanupAcknowledgements, 1)
	assert.True(t, persisted.Status.CleanupAcknowledgements[0].Applied)
	assert.True(t, persisted.Status.AuxiliaryResourceStatuses[0].Deleted, "the acknowledged residual is retired before maintenance cleanup")
}

func TestCleanupAcknowledgementDoesNotBypassBackoff(t *testing.T) {
	ds := failingSession(t)
	c := NewDebugSessionController(zap.NewNop().Sugar(), nil, nil)
	c.recordCleanupFailure(ds)
	assert.Greater(t, c.cleanupBackoffRemaining(ds), time.Duration(0), "only an applied acknowledgement clears the deadline")
}

func asUser(user string) context.Context {
	return admission.NewContextWithRequest(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UserInfo: authenticationv1.UserInfo{Username: user},
	}})
}

func TestCleanupAcknowledgementWebhookVerifiesTheActor(t *testing.T) {
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	validator := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
	_, err := validator.ValidateCreate(asUser("operator@example.com"), ack)
	require.NoError(t, err)
	_, err = validator.ValidateCreate(asUser("requester@example.com"), ack)
	require.Error(t, err, "acknowledgedBy must name the creating user")
	_, err = validator.ValidateCreate(context.Background(), ack)
	require.Error(t, err, "no admission request")
}

func TestCleanupProceedsWhenAcknowledgementCRDIsMissing(t *testing.T) {
	ds := failingSession(t)
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(ds).WithStatusSubresource(ds).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*breakglassv1alpha1.DebugSessionCleanupAcknowledgementList); ok {
				return &meta.NoKindMatchError{GroupKind: breakglassv1alpha1.GroupVersion.WithKind("DebugSessionCleanupAcknowledgement").GroupKind()}
			}
			return cl.List(ctx, list, opts...)
		},
	}).Build()
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	require.NoError(t, c.processCleanupAcknowledgement(context.Background(), ds), "a missing optional CRD must not block cleanup")
	assert.Empty(t, ds.Status.CleanupAcknowledgements)
}

func TestFourEyesRejectsSessionParties(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*breakglassv1alpha1.DebugSession)
		by     string
	}{
		"requester": {mutate: func(ds *breakglassv1alpha1.DebugSession) { ds.Spec.RequestedBy = "operator@example.com" }},
		"approver": {mutate: func(ds *breakglassv1alpha1.DebugSession) {
			ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{ApprovedBy: "Operator@example.com"}
		}},
		"participant": {mutate: func(ds *breakglassv1alpha1.DebugSession) {
			ds.Status.Participants = []breakglassv1alpha1.DebugSessionParticipant{{User: "x", Email: "operator@example.com"}}
		}},
		"prefixed hub username vs unprefixed requester": {
			mutate: func(ds *breakglassv1alpha1.DebugSession) { ds.Spec.RequestedBy = "operator@example.com" },
			by:     "oidc:operator@example.com",
		},
		"prefixed hub username vs spoke-prefixed approver": {
			mutate: func(ds *breakglassv1alpha1.DebugSession) {
				ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{ApprovedBy: "spoke:operator@example.com"}
			},
			by: "oidc:operator@example.com",
		},
	} {
		t.Run(name, func(t *testing.T) {
			ds := failingSession(t)
			tc.mutate(ds)
			ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
			if tc.by != "" {
				ack.Spec.AcknowledgedBy = tc.by
			}
			record := applyCleanupAcknowledgement(ds, ack, "")
			assert.False(t, record.Applied)
			assert.Contains(t, record.Message, "four-eyes")
			assert.False(t, ds.Status.AuxiliaryResourceStatuses[0].Deleted)
		})
	}
}

func TestFourEyesComparesEveryRecordedApproverIdentity(t *testing.T) {
	// The approver's username claim is "alice" while the hub authenticates
	// them as "oidc:alice@example.com" (their email claim).
	ds := failingSession(t)
	ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{ApprovedBy: "alice", ApprovedByIdentities: []string{"alice", "alice@example.com", "oidc:alice-k8s"}}
	for _, by := range []string{"oidc:alice@example.com", "alice@example.com", "oidc:alice-k8s", "alice-k8s"} {
		ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
		ack.Spec.AcknowledgedBy = by
		record := decideCleanupAcknowledgement(ds, ack, "", false)
		assert.False(t, record.Applied, by)
		assert.Contains(t, record.Message, "four-eyes", by)
	}
	assert.True(t, decideCleanupAcknowledgement(ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...), "", false).Applied, "an unrelated operator may acknowledge")
}

func TestFourEyesFailsClosedForLegacyApprovals(t *testing.T) {
	ds := failingSession(t)
	ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{ApprovedBy: "alice"}
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	record := decideCleanupAcknowledgement(ds, ack, "", false)
	assert.False(t, record.Applied)
	assert.Contains(t, record.Message, "approvedByIdentities")
	assert.True(t, decideCleanupAcknowledgement(ds, ack, "", true).Applied, "the transitional opt-out compares approvedBy alone")
	ack.Spec.AcknowledgedBy = "oidc:alice"
	assert.False(t, decideCleanupAcknowledgement(ds, ack, "", true).Applied, "approvedBy is still compared")
	ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{Required: false}
	assert.True(t, decideCleanupAcknowledgement(ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...), "", false).Applied, "a session without an approver is unaffected")
}

func TestFourEyesDoesNotRejectAnUnrelatedPrefixedUser(t *testing.T) {
	ds := failingSession(t)
	ds.Spec.RequestedBy = "requester@example.com"
	assert.False(t, sessionPartyMatches(ds, "oidc:operator@example.com"))
}

func TestApplyCleanupAcknowledgementRejectsWithoutRetiring(t *testing.T) {
	wrongUID := append([]CleanupAcknowledgedIdentity(nil), acknowledgedPolicyExceptions...)
	wrongUID[3].UID = "another-uid"
	for name, tc := range map[string]struct {
		mutate  func(*breakglassv1alpha1.DebugSession, *breakglassv1alpha1.DebugSessionCleanupAcknowledgement)
		refusal string
	}{
		"wrong uid": {mutate: func(_ *breakglassv1alpha1.DebugSession, a *breakglassv1alpha1.DebugSessionCleanupAcknowledgement) {
			a.Spec.Identities = wrongUID
		}},
		"other session": {mutate: func(_ *breakglassv1alpha1.DebugSession, a *breakglassv1alpha1.DebugSessionCleanupAcknowledgement) {
			a.Spec.SessionUID = "recreated"
		}},
		"not failing": {mutate: func(ds *breakglassv1alpha1.DebugSession, _ *breakglassv1alpha1.DebugSessionCleanupAcknowledgement) {
			ds.Status.Conditions = nil
		}},
		"refused": {refusal: "webhook inactive"},
		"display-string collision": {mutate: func(_ *breakglassv1alpha1.DebugSession, a *breakglassv1alpha1.DebugSessionCleanupAcknowledgement) {
			// "deployed (uid=deployed-uid)" without a UID renders like the
			// residual "deployed" with UID "deployed-uid".
			collision := acknowledgedPolicyExceptions[3]
			collision.Name, collision.UID = collision.Name+" (uid="+collision.UID+")", ""
			require.Equal(t, acknowledgedPolicyExceptions[3].String(), collision.String())
			a.Spec.Identities = []CleanupAcknowledgedIdentity{collision}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			ds := failingSession(t)
			ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
			if tc.mutate != nil {
				tc.mutate(ds, ack)
			}
			before := ds.Status.DeepCopy()
			record := applyCleanupAcknowledgement(ds, ack, tc.refusal)
			assert.False(t, record.Applied)
			assert.NotEmpty(t, record.Message)
			assert.Equal(t, *before, ds.Status, "a rejection leaves the session unchanged")
		})
	}
}

func acknowledgementPhase(t *testing.T, f *ackFixture, name string) breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus {
	t.Helper()
	ack := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKey{Namespace: f.ds.Namespace, Name: name}, ack))
	return ack.Status
}

func TestRejectedAcknowledgementIsRecordedOnTheObjectAndNotReplayed(t *testing.T) {
	ds := failingSession(t)
	ds.Status.Conditions = nil // premature: cleanup is not failing
	f := newAckFixture(t, ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...))
	for range 3 {
		require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	}
	status := acknowledgementPhase(t, f, "a")
	assert.Equal(t, breakglassv1alpha1.CleanupAcknowledgementRejected, status.Phase)
	assert.Contains(t, status.Message, "not failing")
	assert.Empty(t, ds.Status.CleanupAcknowledgements, "rejections are not recorded on the session")
	assert.Len(t, f.events(t, audit.EventDebugSessionCleanupAcknowledged), 1, "a final outcome is never processed or audited again")
}

func TestAppliedAcknowledgementAtCapacityStillRetiresAndIsAuditedOnce(t *testing.T) {
	// A full record list never blocks cleanup: the decision is Applied, the
	// retirement happens, and the provenance stays on the acknowledgement.
	ds := failingSession(t)
	fillRecords(ds, maxCleanupAcknowledgementRecords)
	f := newAckFixture(t, ds, acknowledgement(ds, "a", allResidualsOfFailingSession...))
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	status := acknowledgementPhase(t, f, "a")
	assert.Equal(t, breakglassv1alpha1.CleanupAcknowledgementApplied, status.Phase)
	assert.NotNil(t, status.CompletedAt)
	assert.Len(t, ds.Status.CleanupAcknowledgements, maxCleanupAcknowledgementRecords, "applied provenance is never dropped")
	assert.False(t, cleanupConditionFailed(ds))
	assert.Len(t, f.events(t, audit.EventDebugSessionCleanupAcknowledged), 1)
}

func TestRejectedAcknowledgementKeepsEarlierRetirementProvenance(t *testing.T) {
	ds := failingSession(t)
	ds.Status.DeployedResources = ds.Status.DeployedResources[:1]
	require.True(t, applyCleanupAcknowledgement(ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...), "").Applied)
	setCleanupCondition(ds)
	rejected := applyCleanupAcknowledgement(ds, acknowledgement(ds, "b", CleanupAcknowledgedIdentity{APIVersion: "v1", Kind: "ConfigMap", Name: "unknown"}), "")
	assert.False(t, rejected.Applied)
	require.Len(t, ds.Status.CleanupAcknowledgements, 1)
	setCleanupCondition(ds)
	assert.Equal(t, "CleanupAcknowledged", ds.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed)).Reason)
}

func TestConcurrentReplicasProcessAnAcknowledgementOnce(t *testing.T) {
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	f := newAckFixture(t, ds, ack)
	// Both replicas list the same unclaimed object before either claims it.
	stale := ack.DeepCopy()
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKeyFromObject(ack), stale))
	first := NewDebugSessionController(zap.NewNop().Sugar(), f.hub, nil).WithAuditManager(f.manager).WithAPIReader(fakeListOnly{f.hub, stale.DeepCopy()})
	second := NewDebugSessionController(zap.NewNop().Sugar(), f.hub, nil).WithAuditManager(f.manager).WithAPIReader(fakeListOnly{f.hub, stale.DeepCopy()})
	first.acknowledgementWebhookActive, second.acknowledgementWebhookActive = webhookActive, webhookActive
	require.NoError(t, first.processCleanupAcknowledgement(context.Background(), ds.DeepCopy()))
	require.NoError(t, second.processCleanupAcknowledgement(context.Background(), ds.DeepCopy()))
	assert.Len(t, f.events(t, audit.EventDebugSessionCleanupAcknowledged), 1, "the losing claim is skipped")
	persisted := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKeyFromObject(ds), persisted))
	assert.Len(t, persisted.Status.CleanupAcknowledgements, 1)
}

func TestInterruptedClaimIsTakenOverAfterTimeout(t *testing.T) {
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	stale := metav1.NewTime(time.Now().Add(-2 * cleanupAcknowledgementClaimTimeout))
	ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementProcessing, ClaimedAt: &stale}
	fresh := acknowledgement(ds, "b", acknowledgedPolicyExceptions[0])
	recent := metav1.Now()
	fresh.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementProcessing, ClaimedAt: &recent}
	f := newAckFixture(t, ds, ack, fresh)
	pending, err := f.c.pendingCleanupAcknowledgements(context.Background(), ds)
	require.NoError(t, err)
	require.Len(t, pending, 1, "a stale claim is taken over; a live claim is left to its replica")
	assert.Equal(t, "a", pending[0].Name)
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	assert.Equal(t, breakglassv1alpha1.CleanupAcknowledgementApplied, acknowledgementPhase(t, f, "a").Phase)
}

func TestDecidedButUncompletedAcknowledgementIsCompletedOnResume(t *testing.T) {
	// A replica recorded Applied on the acknowledgement and stopped before
	// completing it on the session. The next reconcile completes it without
	// deciding or auditing again.
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	decision := decideCleanupAcknowledgement(ds, ack, "", false)
	require.True(t, decision.Applied)
	at := metav1.Now()
	ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{
		Phase: breakglassv1alpha1.CleanupAcknowledgementApplied, ClaimedAt: &at, ProcessedAt: &at, Retired: decision.Retired,
	}
	f := newAckFixture(t, ds, ack)
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	assert.Len(t, ds.Status.CleanupAcknowledgements, 1, "completion is idempotent")
	assert.True(t, ds.Status.AuxiliaryResourceStatuses[0].Deleted)
	assert.Len(t, f.events(t, audit.EventDebugSessionCleanupAcknowledged), 1, "the replica that completes an Applied decision audits it, once")
}

func TestStalledClaimantCannotChangeTheSessionAfterTakeover(t *testing.T) {
	// Replica 1 claims and decides through the controller. Between its claim
	// and decision writes, replica 2 takes over and rejects. Replica 1's
	// decision write must conflict, so it retires nothing.
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	base := newAckFixture(t, ds, ack)
	var replica2 *DebugSessionController
	claims := 0
	hub := interceptor.NewClient(base.hub.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if a, ok := obj.(*breakglassv1alpha1.DebugSessionCleanupAcknowledgement); ok && sub == "status" && a.Status.Phase == breakglassv1alpha1.CleanupAcknowledgementProcessing {
				claims++
				if err := cl.Status().Update(ctx, obj, opts...); err != nil {
					return err
				}
				if claims == 1 {
					// Replica 1 stalls past the claim timeout; replica 2 takes over.
					stale := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
					require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(obj), stale))
					old := metav1.NewTime(time.Now().Add(-2 * cleanupAcknowledgementClaimTimeout))
					stale.Status.ClaimedAt = &old
					require.NoError(t, cl.Status().Update(ctx, stale))
					require.NoError(t, replica2.processCleanupAcknowledgement(ctx, ds.DeepCopy()))
				}
				return nil
			}
			return cl.Status().Update(ctx, obj, opts...)
		},
	})
	replica1 := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithAuditManager(base.manager)
	replica1.acknowledgementWebhookActive = webhookActive
	replica2 = NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithAuditManager(base.manager)
	replica2.acknowledgementWebhookActive = func(context.Context) (bool, time.Time, error) { return false, time.Time{}, nil } // rejects
	require.NoError(t, replica1.processCleanupAcknowledgement(context.Background(), ds.DeepCopy()))

	assert.Equal(t, breakglassv1alpha1.CleanupAcknowledgementRejected, acknowledgementPhase(t, base, "a").Phase)
	persisted := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, base.hub.Get(context.Background(), client.ObjectKeyFromObject(ds), persisted))
	assert.False(t, persisted.Status.AuxiliaryResourceStatuses[0].Deleted, "the stalled claimant retired nothing")
	assert.Empty(t, persisted.Status.CleanupAcknowledgements)
	acks := base.events(t, audit.EventDebugSessionCleanupAcknowledged)
	require.Len(t, acks, 1)
	assert.Equal(t, false, acks[0].Details["applied"])
}

func TestFutureClaimIsTreatedAsStale(t *testing.T) {
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	future := metav1.NewTime(time.Now().Add(24 * time.Hour))
	ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementProcessing, ClaimedAt: &future}
	f := newAckFixture(t, ds, ack)
	pending, err := f.c.pendingCleanupAcknowledgements(context.Background(), ds)
	require.NoError(t, err)
	assert.Len(t, pending, 1, "a forged future claim cannot block the acknowledgement")
	assert.False(t, claimLive(&future, time.Now()))
	skewed := metav1.NewTime(time.Now().Add(10 * time.Second))
	assert.True(t, claimLive(&skewed, time.Now()), "small clock skew is tolerated")
}

func TestRetainedResourcesAreNotAcknowledgeable(t *testing.T) {
	ds := failingSession(t)
	retained := breakglassv1alpha1.AuxiliaryResourceStatus{
		Name: "kept", Category: "kept", APIVersion: "v1", Kind: "ConfigMap", Namespace: "breakglass-debug", ResourceName: "kept", Created: true, UID: "kept-uid",
	}
	ds.Status.AuxiliaryResourceStatuses = append(ds.Status.AuxiliaryResourceStatuses, retained)
	ds.Status.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{Name: "kept", DeleteAfter: ptrBool(false)}}}
	ids := append([]CleanupAcknowledgedIdentity{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "breakglass-debug", Name: "kept", UID: "kept-uid"}}, acknowledgedPolicyExceptions...)
	record := decideCleanupAcknowledgement(ds, acknowledgement(ds, "a", ids...), "", false)
	assert.False(t, record.Applied, "an intentionally retained resource is not a residual")
	assert.Contains(t, record.Message, "kept")
}

func TestPartialBatchesRetireMoreResidualsThanOneAcknowledgementCanList(t *testing.T) {
	// 63 applied records and 257 outstanding residuals: no single
	// acknowledgement can list them all (spec.identities maxItems=256), so
	// batches must be accepted even once the record list fills up.
	ds := failingSession(t)
	fillRecords(ds, maxCleanupAcknowledgementRecords-1)
	for i := range 257 - len(allResidualsOfFailingSession) {
		ds.Status.DeployedResources = append(ds.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
			APIVersion: "v1", Kind: "ConfigMap", Namespace: "breakglass-debug", Name: fmt.Sprintf("cm-%03d", i), UID: fmt.Sprintf("cm-uid-%03d", i), Source: "debug-extra",
		})
	}
	setCleanupCondition(ds)
	ids := slices.SortedFunc(maps.Keys(outstandingCleanupResiduals(ds)), compareIdentities)
	require.Len(t, ids, 257)
	first := acknowledgement(ds, "first", ids[:256]...)
	second := acknowledgement(ds, "second", ids[256:]...)
	second.CreationTimestamp = metav1.NewTime(time.Now().Add(time.Second))
	f := newAckFixture(t, ds, first, second)
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	for _, name := range []string{"first", "second"} {
		status := acknowledgementPhase(t, f, name)
		assert.Equal(t, breakglassv1alpha1.CleanupAcknowledgementApplied, status.Phase, "%s: %s", name, status.Message)
		assert.NotNil(t, status.CompletedAt, name)
	}
	assert.Len(t, ds.Status.CleanupAcknowledgements, maxCleanupAcknowledgementRecords, "never exceeds the CRD bound")
	assert.False(t, cleanupConditionFailed(ds), "cleanup completes once every residual is retired")
}

func TestInterruptedClaimOnCleanSessionRequeues(t *testing.T) {
	for _, state := range []breakglassv1alpha1.DebugSessionState{
		breakglassv1alpha1.DebugSessionStateFailed, breakglassv1alpha1.DebugSessionStateExpired,
		breakglassv1alpha1.DebugSessionStateTerminated, breakglassv1alpha1.DebugSessionStateRejected,
	} {
		t.Run(string(state), func(t *testing.T) {
			ds := failingSession(t)
			ds.Status = breakglassv1alpha1.DebugSessionStatus{State: state}
			ds.Spec.TemplateRef, ds.Spec.RequestedBy = "template", "requester@example.com"
			ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
			recent := metav1.NewTime(time.Now().Add(-30 * time.Second))
			ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementProcessing, ClaimedAt: &recent}
			f := newAckFixture(t, ds, ack)
			result, err := f.c.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ds)})
			require.NoError(t, err)
			assert.Greater(t, result.RequeueAfter, time.Duration(0), "a clean session waits for the claim to expire")
			assert.LessOrEqual(t, result.RequeueAfter, cleanupAcknowledgementClaimTimeout)
		})
	}
}

func fillRecords(ds *breakglassv1alpha1.DebugSession, n int) {
	for i := range n {
		ds.Status.CleanupAcknowledgements = append(ds.Status.CleanupAcknowledgements, breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus{UID: fmt.Sprintf("old-%d", i), Applied: true})
	}
}

var allResidualsOfFailingSession = append([]CleanupAcknowledgedIdentity{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "breakglass-debug", Name: "other", UID: "other-uid"}}, acknowledgedPolicyExceptions...)

func TestTwoCompleteAcknowledgementsForTheLastSlotDoNotWedge(t *testing.T) {
	ds := failingSession(t)
	fillRecords(ds, maxCleanupAcknowledgementRecords-1)
	a := acknowledgement(ds, "a", allResidualsOfFailingSession...)
	b := acknowledgement(ds, "b", allResidualsOfFailingSession...)
	// Both were decided Applied from the same stale snapshot.
	for _, ack := range []*breakglassv1alpha1.DebugSessionCleanupAcknowledgement{a, b} {
		decision := decideCleanupAcknowledgement(ds, ack, "", false)
		require.True(t, decision.Applied)
		at := metav1.Now()
		ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementApplied, ProcessedAt: &at, Retired: decision.Retired}
	}
	f := newAckFixture(t, ds, a, b)
	for range 2 {
		require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	}
	assert.LessOrEqual(t, len(ds.Status.CleanupAcknowledgements), maxCleanupAcknowledgementRecords, "never exceeds the CRD bound")
	assert.False(t, cleanupConditionFailed(ds), "cleanup completes")
	pending, err := f.c.pendingCleanupAcknowledgements(context.Background(), ds)
	require.NoError(t, err)
	assert.Empty(t, pending, "nothing is replayed")
	for _, name := range []string{"a", "b"} {
		assert.NotNil(t, acknowledgementPhase(t, f, name).CompletedAt, "%s is marked Completed", name)
	}
	assert.Len(t, f.events(t, audit.EventDebugSessionCleanupAcknowledged), 2, "each Applied acknowledgement is audited exactly once")
}

func TestAppliedAcknowledgementIsAuditedWhenCleanupGotThereFirst(t *testing.T) {
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions[3])
	decision := decideCleanupAcknowledgement(ds, ack, "", false)
	require.True(t, decision.Applied)
	at := metav1.Now()
	ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementApplied, ProcessedAt: &at, Retired: decision.Retired}
	ds.Status.DeployedResources = ds.Status.DeployedResources[1:] // normal cleanup removed it first
	f := newAckFixture(t, ds, ack)
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	assert.NotNil(t, acknowledgementPhase(t, f, "a").CompletedAt)
	assert.Len(t, f.events(t, audit.EventDebugSessionCleanupAcknowledged), 1)
}

func TestCompletedAcknowledgementWithoutRecordIsNotReplayedAfterStaleReAdd(t *testing.T) {
	ds := failingSession(t)
	fillRecords(ds, maxCleanupAcknowledgementRecords) // no room for a record
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions[3])
	decision := decideCleanupAcknowledgement(func() *breakglassv1alpha1.DebugSession {
		d := ds.DeepCopy()
		d.Status.CleanupAcknowledgements = nil
		return d
	}(), ack, "", false)
	require.True(t, decision.Applied)
	at := metav1.Now()
	ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementApplied, ProcessedAt: &at, Retired: decision.Retired}
	f := newAckFixture(t, ds, ack)
	baseline := ds.DeepCopy() // a stale cleanup writer still lists the residual
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	require.NotNil(t, acknowledgementPhase(t, f, "a").CompletedAt)

	baseline.Status.DeployedResources[1].Name = "other" // unrelated edit
	require.NoError(t, f.c.patchDebugSessionCleanupStatus(context.Background(), baseline, ds.Status.DeepCopy()))
	persisted := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKeyFromObject(ds), persisted))
	for _, ref := range persisted.Status.DeployedResources {
		assert.NotEqual(t, "deployed", ref.Name, "a completed retirement stays retired without a session record")
	}
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), persisted))
	assert.Len(t, f.events(t, audit.EventDebugSessionCleanupAcknowledged), 1, "no replay, no second audit")
}

func TestAcknowledgementDecidedAtCapacityRetiresWithoutRecording(t *testing.T) {
	ds := failingSession(t)
	decided := ds.DeepCopy()
	fillRecords(decided, maxCleanupAcknowledgementRecords-1)
	ack := acknowledgement(ds, "a", allResidualsOfFailingSession...)
	decision := decideCleanupAcknowledgement(decided, ack, "", false)
	require.True(t, decision.Applied)
	at := metav1.Now()
	ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementApplied, ProcessedAt: &at, Retired: decision.Retired}
	fillRecords(ds, maxCleanupAcknowledgementRecords) // the session filled up meanwhile
	f := newAckFixture(t, ds, ack)
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	assert.Len(t, ds.Status.CleanupAcknowledgements, maxCleanupAcknowledgementRecords)
	assert.False(t, cleanupConditionFailed(ds), "the decided retirement still happens")
	assert.Len(t, f.events(t, audit.EventDebugSessionCleanupAcknowledged), 1)
}

func TestTransientCompletionFailureIsStillAuditedOnce(t *testing.T) {
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	base := newAckFixture(t, ds, ack)
	failures := 1
	hub := interceptor.NewClient(base.hub.(client.WithWatch), interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if _, ok := obj.(*breakglassv1alpha1.DebugSession); ok && failures > 0 {
				failures--
				return errors.New("apiserver unavailable")
			}
			return cl.Status().Patch(ctx, obj, patch, opts...)
		},
	})
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithAuditManager(base.manager)
	c.acknowledgementWebhookActive = webhookActive
	require.Error(t, c.processCleanupAcknowledgement(context.Background(), ds), "the completion fails after the decision is recorded")
	require.NoError(t, c.processCleanupAcknowledgement(context.Background(), ds))
	assert.True(t, ds.Status.AuxiliaryResourceStatuses[0].Deleted)
	assert.Len(t, base.events(t, audit.EventDebugSessionCleanupAcknowledged), 1, "the retried completion audits the Applied outcome")
}

func TestAppliedStatusWithoutProcessedAtDoesNotPanic(t *testing.T) {
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementApplied, Retired: acknowledgedPolicyExceptions[:1]}
	f := newAckFixture(t, ds, ack)
	require.NotPanics(t, func() { require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds)) })
}

func TestAppliedAcknowledgementOfAnEarlierSessionIsNotReplayed(t *testing.T) {
	ds := failingSession(t)
	old := acknowledgement(ds, "a", acknowledgedPolicyExceptions[0])
	old.Spec.SessionUID = "previous-session-uid"
	at := metav1.Now()
	old.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementApplied, ProcessedAt: &at, Retired: acknowledgedPolicyExceptions[:1]}
	f := newAckFixture(t, ds, old)
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	assert.False(t, ds.Status.AuxiliaryResourceStatuses[0].Deleted, "a recreated session with the same name is not affected")
	assert.Empty(t, f.events(t, audit.EventDebugSessionCleanupAcknowledged))
}

func TestTransitionIsAuditedWhenCompletionWriteFailsOnce(t *testing.T) {
	// The session patch succeeds, the acknowledgement's completion write
	// fails once; the retry must still audit cleanup_recovered.
	ds := failingSession(t)
	ds.Status.DeployedResources = ds.Status.DeployedResources[:1] // all residuals acknowledgeable
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	base := newAckFixture(t, ds, ack)
	failed := false
	hub := interceptor.NewClient(base.hub.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if a, ok := obj.(*breakglassv1alpha1.DebugSessionCleanupAcknowledgement); ok && a.Status.CompletedAt != nil && !failed {
				failed = true
				return errors.New("apiserver unavailable")
			}
			return cl.Status().Update(ctx, obj, opts...)
		},
	})
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithAuditManager(base.manager)
	c.acknowledgementWebhookActive = webhookActive
	require.Error(t, c.processCleanupAcknowledgement(context.Background(), ds))
	live := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, base.hub.Get(context.Background(), client.ObjectKeyFromObject(ds), live))
	require.False(t, cleanupConditionFailed(live), "the session patch succeeded")
	require.NoError(t, c.processCleanupAcknowledgement(context.Background(), live))
	assert.Len(t, base.events(t, audit.EventDebugSessionCleanupRecovered), 1, "the recovery caused by the acknowledgement is audited")
}

func TestDeletionWaitsForAppliedButUncompletedAcknowledgement(t *testing.T) {
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	at := metav1.Now()
	ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementApplied, ProcessedAt: &at}
	other := acknowledgement(ds, "other-session", acknowledgedPolicyExceptions...)
	other.Spec.SessionUID = "previous"
	other.Status = ack.Status
	f := newAckFixture(t, ds, ack, other)
	wait, err := f.c.unfinishedAcknowledgementRequeue(context.Background(), ds)
	require.NoError(t, err)
	assert.Greater(t, wait, time.Duration(0), "an Applied decision not yet completed keeps the session")

	completed := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKeyFromObject(ack), completed))
	completed.Status.CompletedAt = &at
	require.NoError(t, f.hub.Status().Update(context.Background(), completed))
	wait, err = f.c.unfinishedAcknowledgementRequeue(context.Background(), ds)
	require.NoError(t, err)
	assert.Zero(t, wait, "an acknowledgement of another session instance is ignored")
}

type erroringMapper struct {
	meta.RESTMapper
	err error
}

func (m erroringMapper) RESTMapping(schema.GroupKind, ...string) (*meta.RESTMapping, error) {
	return nil, m.err
}

func TestAcknowledgementCRDServedDisablesTheWatchOnlyOnNoMatch(t *testing.T) {
	gk := breakglassv1alpha1.GroupVersion.WithKind("DebugSessionCleanupAcknowledgement").GroupKind()
	served := meta.NewDefaultRESTMapper([]schema.GroupVersion{breakglassv1alpha1.GroupVersion})
	served.Add(breakglassv1alpha1.GroupVersion.WithKind("DebugSessionCleanupAcknowledgement"), meta.RESTScopeNamespace)
	ok, err := acknowledgementCRDServed(served)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = acknowledgementCRDServed(erroringMapper{err: &meta.NoKindMatchError{GroupKind: gk}})
	require.NoError(t, err)
	assert.False(t, ok, "a CRD that is not served disables the watch")

	_, err = acknowledgementCRDServed(erroringMapper{err: apierrors.NewServiceUnavailable("discovery unavailable")})
	require.Error(t, err, "a temporary discovery failure fails setup instead of silently disabling the watch")
}

func TestAppliedAcknowledgementIsRetainedUntilItsSessionIsGone(t *testing.T) {
	ctx := context.Background()
	ds := failingSession(t)
	fillRecords(ds, maxCleanupAcknowledgementRecords) // retired without a session record
	f := newAckFixture(t, ds, acknowledgement(ds, "a", allResidualsOfFailingSession...))
	require.NoError(t, f.c.processCleanupAcknowledgement(ctx, ds))
	require.False(t, cleanupConditionFailed(ds))

	ack := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
	key := client.ObjectKey{Namespace: ds.Namespace, Name: "a"}
	require.NoError(t, f.hub.Get(ctx, key, ack))
	require.Contains(t, ack.Finalizers, cleanupAcknowledgementFinalizer)

	// Deleting the evidence while the session exists keeps it retired
	// against a stale writer that still lists the residuals.
	require.NoError(t, f.hub.Delete(ctx, ack))
	require.NoError(t, f.hub.Get(ctx, key, ack), "the finalizer holds the object")
	stale := failingSession(t)
	fillRecords(stale, maxCleanupAcknowledgementRecords)
	baseline := stale.Status.DeepCopy()
	stale.ResourceVersion = ds.ResourceVersion
	require.NoError(t, f.c.recordCleanupOutcome(ctx, stale, baseline))
	assert.False(t, cleanupConditionFailed(stale), "a stale writer cannot restore retired residuals")
	_, err := f.c.pendingCleanupAcknowledgements(ctx, ds)
	require.NoError(t, err)
	require.NoError(t, f.hub.Get(ctx, key, ack), "still retained while the session exists")

	// Once the session is gone the acknowledgement is released.
	require.NoError(t, f.hub.Delete(ctx, ds))
	_, err = f.c.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ds)})
	require.NoError(t, err)
	assert.True(t, apierrors.IsNotFound(f.hub.Get(ctx, key, ack)), "released and deleted with its session")
}

func TestRejectedAcknowledgementIsNotRetained(t *testing.T) {
	ds := failingSession(t)
	ds.Status.Conditions = nil
	f := newAckFixture(t, ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...))
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	ack := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKey{Namespace: ds.Namespace, Name: "a"}, ack))
	assert.Equal(t, breakglassv1alpha1.CleanupAcknowledgementRejected, ack.Status.Phase)
	assert.NotContains(t, ack.Finalizers, cleanupAcknowledgementFinalizer)
}

func TestAcknowledgementCreatedBeforeTheWebhookIsRefused(t *testing.T) {
	installed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	changed := installed.Add(time.Hour)
	fail := admissionregistrationv1.Fail
	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "breakglass", CreationTimestamp: metav1.NewTime(installed),
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl", Time: ptr.To(metav1.NewTime(changed))}}},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{Name: cleanupAcknowledgementWebhookName, FailurePolicy: &fail, Rules: []admissionregistrationv1.RuleWithOperations{{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
			Rule:       admissionregistrationv1.Rule{APIGroups: []string{breakglassv1alpha1.GroupVersion.Group}, APIVersions: []string{"*"}, Resources: []string{"debugsessioncleanupacknowledgements"}},
		}}}},
	}
	ds := failingSession(t)
	forged := acknowledgement(ds, "forged", allResidualsOfFailingSession...)
	forged.CreationTimestamp = metav1.NewTime(installed.Add(-time.Hour)) // before the webhook existed
	duringChange := acknowledgement(ds, "during-change", allResidualsOfFailingSession...)
	duringChange.CreationTimestamp = metav1.NewTime(changed.Add(webhookPropagationMargin / 2))
	f := newAckFixture(t, ds, forged, duringChange)
	// The fake client rewrites managedFields; serve the configuration as the
	// API server stores it.
	configs := interceptor.NewClient(fake.NewClientBuilder().WithScheme(Scheme).Build(), interceptor.Funcs{
		List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
			list.(*admissionregistrationv1.ValidatingWebhookConfigurationList).Items = []admissionregistrationv1.ValidatingWebhookConfiguration{*webhookConfig}
			return nil
		},
	})
	f.c.acknowledgementWebhookActive = NewDebugSessionController(zap.NewNop().Sugar(), configs, nil).cleanupAcknowledgementWebhookActive
	_, since, err := f.c.acknowledgementWebhookActive(context.Background())
	require.NoError(t, err)
	require.Equal(t, changed, since.UTC(), "the latest managedFields time counts as the last change")
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	for _, name := range []string{"forged", "during-change"} {
		status := acknowledgementPhase(t, f, name)
		assert.Equal(t, breakglassv1alpha1.CleanupAcknowledgementRejected, status.Phase, name)
		assert.Contains(t, status.Message, "acknowledgedBy is unverified", name)
	}
	assert.True(t, cleanupConditionFailed(ds), "nothing was retired")

	verified := acknowledgement(ds, "verified", allResidualsOfFailingSession...)
	verified.CreationTimestamp = metav1.NewTime(changed.Add(2 * webhookPropagationMargin))
	assert.Empty(t, acknowledgementActorRefusal(verified, true, changed), "created after the webhook took effect")
}

func TestLaggingCacheDoesNotReleaseTheEvidenceOfARecreatedSession(t *testing.T) {
	ctx := context.Background()
	old := failingSession(t)
	recreated := old.DeepCopy()
	recreated.UID = "recreated-uid"
	ack := acknowledgement(recreated, "a", allResidualsOfFailingSession...)
	ack.Finalizers = []string{cleanupAcknowledgementFinalizer}
	at := metav1.Now()
	ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementApplied, ProcessedAt: &at, CompletedAt: &at,
		Retired: allResidualsOfFailingSession}
	live := newAckFixture(t, recreated, ack)
	retained := func() bool {
		got := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
		require.NoError(t, live.hub.Get(ctx, client.ObjectKeyFromObject(ack), got))
		return slices.Contains(got.Finalizers, cleanupAcknowledgementFinalizer)
	}

	// The cache has not seen the recreated session yet: NotFound.
	notYetCached := interceptor.NewClient(live.hub.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*breakglassv1alpha1.DebugSession); ok {
				return apierrors.NewNotFound(breakglassv1alpha1.GroupVersion.WithResource("debugsessions").GroupResource(), key.Name)
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
	c := NewDebugSessionController(zap.NewNop().Sugar(), notYetCached, nil).WithAPIReader(live.hub)
	_, err := c.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(old)})
	require.NoError(t, err)
	assert.True(t, retained(), "a cached NotFound does not release a live session's evidence")

	// The cache still shows the old instance of the reused name.
	_, err = c.pendingCleanupAcknowledgements(ctx, old)
	require.NoError(t, err)
	assert.True(t, retained(), "a stale instance in the cache does not release the new instance's evidence")

	// Once the live session is gone, the acknowledgement is released.
	require.NoError(t, live.hub.Delete(ctx, recreated))
	_, err = c.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(old)})
	require.NoError(t, err)
	assert.False(t, retained())
}

func TestAcknowledgementIsReleasedOnlyWhenTheSessionKindIsDefinitivelyNotServed(t *testing.T) {
	ctx := context.Background()
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", allResidualsOfFailingSession...)
	ack.Finalizers = []string{cleanupAcknowledgementFinalizer}
	at := metav1.Now()
	ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementApplied, ProcessedAt: &at, CompletedAt: &at,
		Retired: allResidualsOfFailingSession}
	f := newAckFixture(t, ds, ack)
	retained := func() bool {
		got := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
		require.NoError(t, f.hub.Get(ctx, client.ObjectKeyFromObject(ack), got))
		return slices.Contains(got.Finalizers, cleanupAcknowledgementFinalizer)
	}
	sessionReadFails := func(sessionErr error) *DebugSessionController {
		reader := interceptor.NewClient(f.hub.(client.WithWatch), interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*breakglassv1alpha1.DebugSession); ok {
					return sessionErr
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		})
		return NewDebugSessionController(zap.NewNop().Sugar(), f.hub, nil).WithAPIReader(reader)
	}
	sessionGV := breakglassv1alpha1.GroupVersion

	// A transient discovery failure proves nothing: the evidence stays.
	transient := &apiutil.ErrResourceDiscoveryFailed{sessionGV: apierrors.NewServiceUnavailable("down")}
	require.Error(t, sessionReadFails(transient).releaseAcknowledgementsOfDeletedSession(ctx, client.ObjectKeyFromObject(ds)))
	assert.True(t, retained(), "a transient discovery failure does not release the evidence")

	// The DebugSession CRD is gone (uninstall): no session can exist.
	noMatch := &meta.NoKindMatchError{GroupKind: sessionGV.WithKind("DebugSession").GroupKind(), SearchedVersions: []string{sessionGV.Version}}
	require.NoError(t, sessionReadFails(noMatch).releaseAcknowledgementsOfDeletedSession(ctx, client.ObjectKeyFromObject(ds)))
	assert.False(t, retained(), "an unserved DebugSession kind releases the retention finalizer")
}

// budgetSession is a failing session padded by pad bytes, with an entry an
// earlier acknowledgement already retired.
func budgetSession(t *testing.T, pad int) *breakglassv1alpha1.DebugSession {
	ds := failingSession(t)
	ds.Status.AuxiliaryResourceStatuses = append(ds.Status.AuxiliaryResourceStatuses,
		breakglassv1alpha1.AuxiliaryResourceStatus{Name: "earlier", Deleted: true, Error: acknowledgedAbsentReason},
		breakglassv1alpha1.AuxiliaryResourceStatus{Name: "padding", Deleted: true, Error: "x" + strings.Repeat("x", pad)})
	return ds
}

func TestCompletionNearTheSizeBudgetStillRetires(t *testing.T) {
	// The size after completing with record and reasons, without padding,
	// locates the exact first-record edge.
	probe := budgetSession(t, 0)
	_, recorded := completeCleanupAcknowledgement(probe, decideCleanupAcknowledgement(probe, acknowledgement(probe, "a", allResidualsOfFailingSession...), "", false))
	require.True(t, recorded)
	edge := cleanupAcknowledgementStatusBudget - serializedSize(probe)

	for name, tc := range map[string]struct {
		pad              int
		recorded, reason bool
	}{
		"record fits exactly":         {pad: edge, recorded: true, reason: true},
		"record one byte over":        {pad: edge + 1, reason: true},
		"reasons do not fit either":   {pad: edge + 4096},
		"record fits with room to go": {pad: edge - 4096, recorded: true, reason: true},
	} {
		t.Run(name, func(t *testing.T) {
			ds := budgetSession(t, tc.pad)
			record := decideCleanupAcknowledgement(ds, acknowledgement(ds, "a", allResidualsOfFailingSession...), "", false)
			require.True(t, record.Applied, record.Message)

			changed, recorded := completeCleanupAcknowledgement(ds, record)
			require.True(t, changed, "an Applied acknowledgement is always completable")
			assert.Empty(t, outstandingCleanupResiduals(ds), "every listed residual is retired")
			assert.True(t, acknowledgementCompleted(ds, record))
			assert.Equal(t, tc.recorded, recorded)
			assert.Equal(t, tc.recorded, acknowledgementProcessed(ds, record.UID), "the record is kept only within the budget")
			if tc.reason {
				assert.LessOrEqual(t, serializedSize(ds), cleanupAcknowledgementStatusBudget)
			}
			for _, entry := range ds.Status.AuxiliaryResourceStatuses {
				switch entry.Name {
				case "earlier":
					assert.Equal(t, acknowledgedAbsentReason, entry.Error, "an earlier acknowledgement keeps its reason")
				case "padding":
				default:
					assert.True(t, entry.Deleted, entry.Name)
					assert.Equal(t, map[bool]string{true: acknowledgedAbsentReason, false: ""}[tc.reason], entry.Error, entry.Name)
				}
			}
		})
	}
}

func TestOutdatedCRDIsReportedOnlyWhenAWrittenRecordWasPruned(t *testing.T) {
	for name, tc := range map[string]struct {
		pad   int
		prune bool
		want  int
	}{
		"record pruned by an outdated CRD":  {prune: true, want: 1},
		"record omitted by the size budget": {pad: cleanupAcknowledgementStatusBudget},
		"record stored":                     {},
	} {
		t.Run(name, func(t *testing.T) {
			ds := failingSession(t)
			if tc.pad > 0 {
				// Leave room for the retirement reasons but not the record.
				ds = budgetSession(t, 0)
				probe := ds.DeepCopy()
				_, _ = completeCleanupAcknowledgement(probe, decideCleanupAcknowledgement(probe, acknowledgement(probe, "a", allResidualsOfFailingSession...), "", false))
				ds.Status.AuxiliaryResourceStatuses[len(ds.Status.AuxiliaryResourceStatuses)-1].Error += strings.Repeat("x", cleanupAcknowledgementStatusBudget-serializedSize(probe)+1)
			}
			f := newAckFixture(t, ds, acknowledgement(ds, "a", allResidualsOfFailingSession...))
			if tc.prune {
				f.c.client = interceptor.NewClient(f.hub.(client.WithWatch), interceptor.Funcs{
					SubResourcePatch: func(ctx context.Context, cl client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
						if err := cl.SubResource(subResource).Patch(ctx, obj, patch, opts...); err != nil {
							return err
						}
						if session, ok := obj.(*breakglassv1alpha1.DebugSession); ok {
							session.Status.CleanupAcknowledgements = nil
							return cl.Status().Update(ctx, session)
						}
						return nil
					},
				})
			}
			core, logs := observer.New(zapcore.ErrorLevel)
			f.c.log = zap.New(core).Sugar()
			require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
			assert.False(t, cleanupConditionFailed(ds), "the residuals are retired")
			assert.Equal(t, tc.want, logs.FilterMessageSnippet("CRD lacks status.cleanupAcknowledgements").Len())
		})
	}
}

func TestUnresolvedApproverKubernetesUserFailsClosed(t *testing.T) {
	ds := failingSession(t)
	ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{ApprovedBy: "alice", ApprovedByIdentities: []string{"alice", "alice@example.com"}, ApprovedByKubernetesUserUnresolved: true}
	ack := acknowledgement(ds, "a", allResidualsOfFailingSession...)
	ack.Spec.AcknowledgedBy = "oidc:alice-sub" // the approver's unrecorded mapped identity
	record := decideCleanupAcknowledgement(ds, ack, "", false)
	assert.False(t, record.Applied)
	assert.Contains(t, record.Message, "approvedByKubernetesUserUnresolved")
	assert.True(t, decideCleanupAcknowledgement(ds, ack, "", true).Applied, "the legacy approver opt-out compares the recorded identities only")
}

func TestCleanupCompleteIsMarkedOnlyWithoutTrackedResources(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		mutate func(*breakglassv1alpha1.DebugSession)
		want   bool
	}{
		"terminal and clean": {mutate: func(*breakglassv1alpha1.DebugSession) {}, want: true},
		"active session": {mutate: func(ds *breakglassv1alpha1.DebugSession) {
			ds.Status.State = breakglassv1alpha1.DebugSessionStateActive
		}},
		"auxiliary resource tracked": {mutate: func(ds *breakglassv1alpha1.DebugSession) { *ds = *failingSession(t) }},
		"copied pod tracked": {mutate: func(ds *breakglassv1alpha1.DebugSession) {
			ds.Status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{CopiedPods: []breakglassv1alpha1.CopiedPodRef{{CopyName: "copy"}}}
		}},
		"cleanup failing, no records": {mutate: func(ds *breakglassv1alpha1.DebugSession) { ds.Status.Conditions = failingSession(t).Status.Conditions }},
	} {
		t.Run(name, func(t *testing.T) {
			ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "ns", UID: "uid"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateTerminated}}
			tc.mutate(ds)
			hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(ds).WithStatusSubresource(ds).Build()
			require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(ds), ds))
			c := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
			require.NoError(t, c.markCleanupComplete(ctx, ds))
			stored := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(ds), stored))
			assert.Equal(t, tc.want, cleanupCompleteRecorded(stored))
		})
	}
}
