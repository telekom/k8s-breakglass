// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
)

func TestCollectorJobRuntimeIdentityMetadata(t *testing.T) {
	for _, tc := range []struct {
		name           string
		globalDisabled bool
		templateValue  *bool
		want           bool
	}{
		{name: "default", want: true},
		{name: "global opt-out", globalDisabled: true},
		{name: "template opt-out", templateValue: ptr.To(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
			require.NoError(t, corev1.AddToScheme(scheme))
			require.NoError(t, batchv1.AddToScheme(scheme))
			expires := metav1.NewTime(time.Now().Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "breakglass", UID: types.UID("session-uid")},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", TargetNamespace: "target", TemplateRef: "diagnostics", RequestedBy: "requester@example.com", TicketSystemID: "INC-1"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expires,
					Approval:         &breakglassv1alpha1.DebugSessionApproval{ApprovedBy: "approver@example.com"},
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{},
				},
			}
			if tc.templateValue != nil {
				session.Status.ResolvedTemplate.Audit = &breakglassv1alpha1.DebugSessionAuditConfig{RuntimeIdentityMetadata: tc.templateValue}
			}
			artifact := artifactForValidation()
			artifact.Spec.TargetClusterUID = "cluster-uid"
			artifact.Spec.Recipe = "system-summary.v1"
			artifact.Spec.RecipeVersion = 1
			artifact.Spec.PlanDigest = strings.Repeat("a", 64)
			artifact.Spec.RuntimeBindingDigest = strings.Repeat("b", 64)
			artifact.Spec.RedactionProfile = "default"
			artifact.Spec.RedactionVersion = 1
			artifact.Spec.MaxBytes = 1024
			artifact.Spec.TimeoutSeconds = 30
			artifact.Spec.Inputs.MaxArchiveBytes = 1024
			artifact.Spec.ExpiresAt = expires
			hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session, &artifact).WithStatusSubresource(&breakglassv1alpha1.DebugSessionArtifact{}).Build()
			spoke := &uidAssigningClient{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
			provider := &testTargetProvider{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: types.UID("cluster-uid")}}}
			reconciler := &Reconciler{Client: hub, LiveReader: hub, TokenIssuer: testTokenIssuer{}, Image: "registry.example/collector@sha256:" + strings.Repeat("c", 64), ControllerURL: "https://breakglass.example", ClusterProvider: provider, DisableRuntimeIdentityMetadata: tc.globalDisabled}
			record := backend.Record{ArtifactID: artifact.Spec.ArtifactID, ArtifactUID: string(artifact.UID), SessionUID: artifact.Spec.SessionRef.UID, Namespace: artifact.Spec.SessionRef.Namespace, SessionName: artifact.Spec.SessionRef.Name, ExpiresAt: expires.Time}
			require.NoError(t, reconciler.ensureUploadResources(context.Background(), artifact, record))

			var job batchv1.Job
			require.NoError(t, spoke.Get(context.Background(), types.NamespacedName{Namespace: "target", Name: "dsa-" + string(artifact.UID) + "-collect"}, &job))
			meta := job.Spec.Template.ObjectMeta
			require.Equal(t, "session-uid", job.Labels["breakglass.t-caas.telekom.com/session-uid"], "the existing session label is always kept")
			if !tc.want {
				require.NotContains(t, meta.Labels, debug.DebugSessionUIDLabelKey)
				require.NotContains(t, meta.Annotations, debug.RuntimeIdentityRequestedByAnnotation)
			} else {
				require.Equal(t, "session-uid", meta.Labels[debug.DebugSessionUIDLabelKey])
				require.Equal(t, "session", meta.Labels[debug.DebugSessionLabelKey])
				require.Equal(t, "diagnostics", meta.Labels[debug.DebugTemplateLabelKey])
				require.Equal(t, "requester@example.com", meta.Annotations[debug.RuntimeIdentityRequestedByAnnotation])
				require.Equal(t, "approver@example.com", meta.Annotations[debug.RuntimeIdentityApprovedByAnnotation])
				require.Equal(t, "INC-1", meta.Annotations[debug.RuntimeIdentityTicketAnnotation])
			}

			// Jobs created before an upgrade or before the switch changed
			// differ only in the identity metadata and stay valid.
			var updated breakglassv1alpha1.DebugSessionArtifact
			require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(&artifact), &updated))
			reconciler.DisableRuntimeIdentityMetadata = !tc.globalDisabled
			require.NoError(t, reconciler.ensureUploadResources(context.Background(), updated, record))
		})
	}
}
