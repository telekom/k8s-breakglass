// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
		return &admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-validating-webhook-configuration"},
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
		"match condition": {objects: []client.Object{config(func(w *admissionregistrationv1.ValidatingWebhook) {
			w.MatchConditions = []admissionregistrationv1.MatchCondition{{Name: "skip", Expression: "false"}}
		})}},
	} {
		t.Run(name, func(t *testing.T) {
			hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(tc.objects...).Build()
			active, err := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).cleanupAcknowledgementWebhookActive(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.want, active)
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
	for name, mutate := range map[string]func(*breakglassv1alpha1.DebugSession){
		"requester": func(ds *breakglassv1alpha1.DebugSession) { ds.Spec.RequestedBy = "operator@example.com" },
		"approver": func(ds *breakglassv1alpha1.DebugSession) {
			ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{ApprovedBy: "Operator@example.com"}
		},
		"participant": func(ds *breakglassv1alpha1.DebugSession) {
			ds.Status.Participants = []breakglassv1alpha1.DebugSessionParticipant{{User: "x", Email: "operator@example.com"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			ds := failingSession(t)
			mutate(ds)
			record := applyCleanupAcknowledgement(ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...), "")
			assert.False(t, record.Applied)
			assert.Contains(t, record.Message, "four-eyes")
			assert.False(t, ds.Status.AuxiliaryResourceStatuses[0].Deleted)
		})
	}
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
		"at capacity": {mutate: func(ds *breakglassv1alpha1.DebugSession, _ *breakglassv1alpha1.DebugSessionCleanupAcknowledgement) {
			for i := range maxCleanupAcknowledgementRecords {
				ds.Status.CleanupAcknowledgements = append(ds.Status.CleanupAcknowledgements, breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus{UID: fmt.Sprintf("old-%d", i), Applied: true})
			}
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

func TestAppliedAcknowledgementAtCapacityIsStillRecordedAndAudited(t *testing.T) {
	// Even when the session cannot take another applied record, the
	// rejection is durable and audited exactly once.
	ds := failingSession(t)
	for i := range maxCleanupAcknowledgementRecords {
		ds.Status.CleanupAcknowledgements = append(ds.Status.CleanupAcknowledgements, breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus{UID: fmt.Sprintf("old-%d", i), Applied: true})
	}
	f := newAckFixture(t, ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...))
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	status := acknowledgementPhase(t, f, "a")
	assert.Equal(t, breakglassv1alpha1.CleanupAcknowledgementRejected, status.Phase)
	assert.Len(t, ds.Status.CleanupAcknowledgements, maxCleanupAcknowledgementRecords, "applied provenance is never dropped")
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
	decision := decideCleanupAcknowledgement(ds, ack, "")
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
	assert.Empty(t, f.events(t, audit.EventDebugSessionCleanupAcknowledged), "the deciding replica audits; resumption does not")
}

func TestStalledClaimantCannotChangeTheSessionAfterTakeover(t *testing.T) {
	// Replica 1 claims, then stalls. Replica 2 takes over after the timeout
	// and rejects. Replica 1 resumes: its decision write must fail on the
	// claim's resourceVersion, so it never retires anything.
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	f := newAckFixture(t, ds, ack)
	claimed := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKeyFromObject(ack), claimed))
	old := metav1.NewTime(time.Now().Add(-2 * cleanupAcknowledgementClaimTimeout))
	claimed.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementProcessing, ClaimedAt: &old}
	require.NoError(t, f.hub.Status().Update(context.Background(), claimed)) // replica 1's claim
	stalled := claimed.DeepCopy()

	f.c.acknowledgementWebhookActive = func(context.Context) (bool, error) { return false, nil } // replica 2 rejects
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), ds))
	require.Equal(t, breakglassv1alpha1.CleanupAcknowledgementRejected, acknowledgementPhase(t, f, "a").Phase)

	// Replica 1 resumes with its stale claim and an Applied decision.
	decision := decideCleanupAcknowledgement(ds, ack, "")
	require.True(t, decision.Applied)
	stalled.Status.Phase, stalled.Status.Retired = breakglassv1alpha1.CleanupAcknowledgementApplied, decision.Retired
	err := f.hub.Status().Update(context.Background(), stalled)
	require.True(t, apierrors.IsConflict(err), "the stalled claimant's decision write must conflict, got %v", err)
	persisted := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKeyFromObject(ds), persisted))
	assert.False(t, persisted.Status.AuxiliaryResourceStatuses[0].Deleted, "nothing was retired")
	assert.Empty(t, persisted.Status.CleanupAcknowledgements)
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
	record := decideCleanupAcknowledgement(ds, acknowledgement(ds, "a", ids...), "")
	assert.False(t, record.Applied, "an intentionally retained resource is not a residual")
	assert.Contains(t, record.Message, "kept")
}

func TestLastRecordSlotIsReservedForACompleteAcknowledgement(t *testing.T) {
	ds := failingSession(t)
	for i := range maxCleanupAcknowledgementRecords - 1 {
		ds.Status.CleanupAcknowledgements = append(ds.Status.CleanupAcknowledgements, breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus{UID: fmt.Sprintf("old-%d", i), Applied: true})
	}
	partial := decideCleanupAcknowledgement(ds, acknowledgement(ds, "partial", acknowledgedPolicyExceptions[0]), "")
	assert.False(t, partial.Applied)
	assert.Contains(t, partial.Message, "list all 5 remaining residuals")
	all := append([]CleanupAcknowledgedIdentity{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "breakglass-debug", Name: "other", UID: "other-uid"}}, acknowledgedPolicyExceptions...)
	complete := applyCleanupAcknowledgement(ds, acknowledgement(ds, "complete", all...), "")
	require.True(t, complete.Applied, "a complete acknowledgement still fits")
	assert.Len(t, ds.Status.CleanupAcknowledgements, maxCleanupAcknowledgementRecords)
	setCleanupCondition(ds)
	assert.False(t, cleanupConditionFailed(ds))
}

func TestInterruptedClaimOnCleanSessionRequeues(t *testing.T) {
	ds := failingSession(t)
	ds.Status = breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateFailed}
	ds.Spec.TemplateRef, ds.Spec.RequestedBy = "template", "requester@example.com"
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	recent := metav1.NewTime(time.Now().Add(-30 * time.Second))
	ack.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementProcessing, ClaimedAt: &recent}
	f := newAckFixture(t, ds, ack)
	result, err := f.c.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ds)})
	require.NoError(t, err)
	assert.Greater(t, result.RequeueAfter, time.Duration(0), "a clean session waits for the claim to expire")
	assert.LessOrEqual(t, result.RequeueAfter, cleanupAcknowledgementClaimTimeout)
}
