// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestPlatformSessionNamingEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	environment := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	apiClient, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, apiClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "naming-platform"}}))
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "naming", Namespace: "naming-platform"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "OIDC:Platform_ADMIN", MaxValidFor: "1h",
			Allowed:   breakglassv1alpha1.BreakglassEscalationAllowed{Clusters: []string{"EU-West_1.Prod"}, Groups: []string{"users"}},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
		},
	}
	require.NoError(t, apiClient.Create(ctx, escalation))
	controller := &BreakglassSessionController{sessionManager: NewSessionManagerWithClient(apiClient)}
	params := sessionCreateParams{
		matchedEsc: escalation, userIdentifier: "First.Last+Ops@EXAMPLE.COM",
		request: BreakglassSessionRequest{Clustername: "EU-West_1.Prod", GroupName: "OIDC:Platform_ADMIN", Username: "untrusted"},
		spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "EU-West_1.Prod", GrantedGroup: "OIDC:Platform_ADMIN", User: "First.Last+Ops@EXAMPLE.COM",
		},
	}
	response := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(response)
	session, ok := controller.createAndPersistSession(ginCtx, ctx, params, zap.NewNop().Sugar())
	require.True(t, ok, response.Body.String())
	stored := &breakglassv1alpha1.BreakglassSession{}
	require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), stored))
	require.Equal(t, "eu-west-1.prod-oidc-platform-admin-", stored.GenerateName)
	require.Contains(t, stored.Name, stored.GenerateName)
	require.NotEqual(t, stored.GenerateName, stored.Name, "API server adds a generated suffix")
	require.Equal(t, map[string]string{
		"breakglass.t-caas.telekom.com/cluster": "eu-west-1.prod",
		"breakglass.t-caas.telekom.com/user":    "first.last-ops-example.com",
		"breakglass.t-caas.telekom.com/group":   "oidc-platform-admin",
	}, stored.Labels)
	require.Equal(t, escalation.UID, stored.OwnerReferences[0].UID)
	require.Equal(t, breakglassv1alpha1.SessionStatePending, stored.Status.State)
	selected := &breakglassv1alpha1.BreakglassSessionList{}
	require.NoError(t, apiClient.List(ctx, selected, client.InNamespace(escalation.Namespace),
		client.MatchingLabels{"breakglass.t-caas.telekom.com/user": "first.last-ops-example.com"}))
	require.Len(t, selected.Items, 1, "canonical user label is usable by cleanup selectors")
	require.Equal(t, stored.UID, selected.Items[0].UID)
}
