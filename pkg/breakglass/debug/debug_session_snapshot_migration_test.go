// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestPendingCapturesCatalogueIdentityBeforeApproval(t *testing.T) {
	for _, catalogue := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "catalogue"}[catalogue], func(t *testing.T) {
			ctx := context.Background()
			template := &breakglassv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "reviewed"},
				Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
					Approvers: &breakglassv1alpha1.DebugSessionApprovers{Groups: []string{"approvers"}},
				},
			}
			if catalogue {
				template.Labels = map[string]string{catalogueProfileLabel: "workload-diagnostics", catalogueIntentLabel: "workload-diagnostics", catalogueElevatedLabel: "false"}
			}
			session := newTestDebugSession("capture", template.Name, "target", "requester@example.com")
			cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session, template).
				WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
			c := NewDebugSessionController(zap.NewNop().Sugar(), cl, nil)
			_, err := c.handlePending(ctx, session)
			require.NoError(t, err)
			var persisted breakglassv1alpha1.DebugSession
			require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(session), &persisted))
			require.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, persisted.Status.State)
			require.Equal(t, "v1", persisted.Status.ResolvedTemplate.Labels[catalogueSnapshotLabel])
			// Reconstruct exactly the metadata-free object used on approved retries.
			synthetic := &breakglassv1alpha1.DebugSessionTemplate{Spec: *persisted.Status.ResolvedTemplate.DeepCopy()}
			podTemplate := &breakglassv1alpha1.DebugPodTemplate{ObjectMeta: metav1.ObjectMeta{Labels: template.Labels}}
			restricted, _, err := restrictedCatalogueProfile(synthetic, podTemplate)
			require.NoError(t, err)
			require.Equal(t, catalogue, restricted)
		})
	}
}

func TestLegacyApprovedSnapshotFailsBeforeActivation(t *testing.T) {
	for _, marker := range []string{"", "unknown-version"} {
		t.Run(marker, func(t *testing.T) {
			ctx := context.Background()
			session := newTestDebugSession("legacy", "now-unrestricted", "target", "requester@example.com")
			session.Status.State = breakglassv1alpha1.DebugSessionStatePendingApproval
			now := metav1.Now()
			session.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{Required: true, ApprovedAt: &now, ApprovedBy: "approver@example.com"}
			session.Status.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{Labels: map[string]string{catalogueSnapshotLabel: marker}}
			session.Status.ResolvedBindingSnapshotCaptured = true
			// A mutable live template cannot attest to the original approved labels.
			template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: session.Spec.TemplateRef}}
			cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session, template).
				WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
			c := NewDebugSessionController(zap.NewNop().Sugar(), cl, nil)
			_, err := c.handlePendingApproval(ctx, session)
			require.NoError(t, err)
			var persisted breakglassv1alpha1.DebugSession
			require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(session), &persisted))
			require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, persisted.Status.State)
			require.Contains(t, persisted.Status.Message, "submit a new request")
			require.Equal(t, marker, persisted.Status.ResolvedTemplate.Labels[catalogueSnapshotLabel])
			require.Empty(t, persisted.Status.DeployedResources)
		})
	}
}
