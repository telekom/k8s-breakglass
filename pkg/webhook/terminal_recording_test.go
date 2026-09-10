// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestTerminalRecordingRequiredOnlyFencesExecAndAttach(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Audit: &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true}}}}
	assert.True(t, terminalRecordingRequired(session, "exec"))
	assert.True(t, terminalRecordingRequired(session, "attach"))
	assert.False(t, terminalRecordingRequired(session, "logs"))
	session.Status.ResolvedTemplate.Audit.EnableTerminalRecording = false
	assert.False(t, terminalRecordingRequired(session, "exec"))

	assert.False(t, terminalRecordingRequired(nil, "exec"))
}

func TestEarlyDebugSessionDeniesDirectExecWhenRecordingIsRequired(t *testing.T) {
	expires := metav1.NewTime(time.Now().Add(time.Hour))
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "default", UID: "session-uid"}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster"}, Status: breakglassv1alpha1.DebugSessionStatus{
		State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expires,
		AllowedPods:          []breakglassv1alpha1.AllowedPodRef{{Namespace: "default", Name: "pod", UID: "pod-uid"}},
		AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: boolPtr(true)},
		Participants:         []breakglassv1alpha1.DebugSessionParticipant{{User: "alice", Role: breakglassv1alpha1.ParticipantRoleParticipant, IdentityProviderIssuer: "https://issuer.example"}},
		ResolvedTemplate:     &breakglassv1alpha1.DebugSessionTemplateSpec{Audit: &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true}},
	}}
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(ds)
	for key, fn := range debugSessionIndexFnsWebhook {
		builder = builder.WithIndex(&breakglassv1alpha1.DebugSession{}, key, fn)
	}
	cli := builder.Build()
	wc := &WebhookController{log: zap.NewNop().Sugar(), escalManager: &escalation.EscalationManager{Client: cli}, podFetchFn: func(context.Context, string, string, string) (*corev1.Pod, error) {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pod", UID: "pod-uid"}}, nil
	}}
	state := &authorizeState{ctx: context.Background(), clusterName: "cluster", issuer: "https://issuer.example", reqLog: zap.NewNop().Sugar(), phases: NewSARPhaseTracker("cluster", zap.NewNop().Sugar()), sar: authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: "alice", ResourceAttributes: &authorizationv1.ResourceAttributes{Resource: "pods", Subresource: "exec", Namespace: "default", Name: "pod"}}}}
	handled := wc.checkEarlyDebugSession(nil, state)
	assert.True(t, handled)
	assert.False(t, state.allowed)
	assert.Contains(t, state.reason, "terminal recording is required")
	assert.Equal(t, "session", state.debugSessionName)
}
