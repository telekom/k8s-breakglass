// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
			assert.Empty(t, record.Retired)
			before.CleanupAcknowledgements = append(before.CleanupAcknowledgements, record)
			assert.Equal(t, *before, ds.Status, "nothing is retired unless every entry matches")
		})
	}
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
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(objects...).WithStatusSubresource(ds).Build()
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

func TestRejectedAcknowledgementKeepsEarlierRetirementProvenance(t *testing.T) {
	ds := failingSession(t)
	ds.Status.DeployedResources = ds.Status.DeployedResources[:1]
	require.True(t, applyCleanupAcknowledgement(ds, acknowledgement(ds, "a", acknowledgedPolicyExceptions...), "").Applied)
	setCleanupCondition(ds)
	rejected := applyCleanupAcknowledgement(ds, acknowledgement(ds, "b", CleanupAcknowledgedIdentity{APIVersion: "v1", Kind: "ConfigMap", Name: "unknown"}), "")
	assert.False(t, rejected.Applied)
	require.Len(t, ds.Status.CleanupAcknowledgements, 2)
	setCleanupCondition(ds)
	assert.Equal(t, "CleanupAcknowledged", ds.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed)).Reason)
}

func TestCleanupAcknowledgementsMergeAppendOnlyByUID(t *testing.T) {
	// Two reconciles process different acknowledgements from the same baseline.
	ds := failingSession(t)
	f := newAckFixture(t, ds)
	first, second := ds.DeepCopy(), ds.DeepCopy()
	baseline := ds.Status.DeepCopy()
	applyCleanupAcknowledgement(first, acknowledgement(ds, "a", acknowledgedPolicyExceptions[3]), "")
	applyCleanupAcknowledgement(second, acknowledgement(ds, "b", acknowledgedPolicyExceptions[2]), "")
	require.NoError(t, f.c.patchDebugSessionCleanupStatus(context.Background(), first, baseline))
	require.NoError(t, f.c.patchDebugSessionCleanupStatus(context.Background(), second, baseline))
	persisted := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, f.hub.Get(context.Background(), client.ObjectKeyFromObject(ds), persisted))
	assert.True(t, acknowledgementProcessed(persisted, "uid-a"), "the first record survives the second write")
	assert.True(t, acknowledgementProcessed(persisted, "uid-b"))
	assert.Len(t, persisted.Status.CleanupAcknowledgements, 2)
	// The second, stale writer must not restore the residual the first retired.
	for _, ref := range persisted.Status.DeployedResources {
		assert.NotEqual(t, "deployed", ref.Name, "an acknowledged deployed residual stays retired")
	}
	for _, entry := range persisted.Status.PodTemplateResourceStatuses {
		assert.NotEqual(t, "pod-template", entry.ResourceName, "an acknowledged pod-template residual stays retired")
	}
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

func TestConcurrentProcessingOfOneAcknowledgementAuditsOnce(t *testing.T) {
	ds := failingSession(t)
	ack := acknowledgement(ds, "a", acknowledgedPolicyExceptions...)
	f := newAckFixture(t, ds, ack)
	// Two replicas list the same unprocessed acknowledgement before either commits.
	first, second := ds.DeepCopy(), ds.DeepCopy()
	require.NoError(t, f.c.processCleanupAcknowledgement(context.Background(), first))
	other := NewDebugSessionController(zap.NewNop().Sugar(), f.hub, nil).WithAuditManager(f.manager).WithAPIReader(fakeListOnly{f.hub, ack})
	other.acknowledgementWebhookActive = webhookActive
	require.NoError(t, other.processCleanupAcknowledgement(context.Background(), second))
	acks := f.events(t, audit.EventDebugSessionCleanupAcknowledged)
	assert.Len(t, acks, 1, "only the replica that inserted the record audits it")
}

// fakeListOnly serves a stale acknowledgement list, as a replica would before
// observing the other replica's status write.
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
	require.Len(t, ds.Status.CleanupAcknowledgements, 1)
	assert.False(t, ds.Status.CleanupAcknowledgements[0].Applied)
	assert.Contains(t, ds.Status.CleanupAcknowledgements[0].Message, "validating webhook")
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
