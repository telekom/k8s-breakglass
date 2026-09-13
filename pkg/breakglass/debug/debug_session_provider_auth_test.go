package debug

import (
	"context"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func providerAuthContext(provider, issuer string) *gin.Context {
	ctx, _ := gin.CreateTestContext(nil)
	ctx.Set("identity_provider_name", provider)
	ctx.Set("issuer", issuer)
	return ctx
}

func TestDebugSessionRequesterUsesApprovedProviderBoundBreakglassSession(t *testing.T) {
	scheme := testScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "approved", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:                "cluster-a",
				User:                   "requester",
				GrantedGroup:           "breakglass:platform:debugsession",
				IdentityProviderName:   "tdi",
				IdentityProviderIssuer: "https://issuer/tdi",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State: breakglassv1alpha1.SessionStateApproved,
			},
		},
	).Build()
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), client, nil, nil)

	allowed, err := controller.isDebugSessionRequesterAllowed(
		providerAuthContext("tdi", "https://issuer/tdi"),
		&breakglassv1alpha1.DebugSessionAllowed{Groups: []string{"breakglass:platform:debugsession"}},
		"requester", "", nil, "cluster-a",
	)
	require.NoError(t, err)
	require.True(t, allowed)

	allowed, err = controller.isDebugSessionRequesterAllowed(
		providerAuthContext("tdg", "https://issuer/tdg"),
		&breakglassv1alpha1.DebugSessionAllowed{Groups: []string{"breakglass:platform:debugsession"}},
		"requester", "", nil, "cluster-a",
	)
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestDebugSessionApproverUsesProviderBoundEscalationMembership(t *testing.T) {
	scheme := testScheme()
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{
				Groups: []string{"breakglass:platform:debugsession"},
			},
		},
	}
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "tdi-escalation", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"cluster-a"},
			},
			EscalatedGroup:                       "breakglass:platform:debugsession",
			AllowedIdentityProvidersForApprovers: []string{"tdi"},
		},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{
				"tdi_security_oidc:s_platform_poweruser": {"approver"},
			},
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding, escalation).Build()
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), client, nil, nil)
	session := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "cluster-a",
			BindingRef: &breakglassv1alpha1.BindingReference{
				Name: "binding", Namespace: "default",
			},
		},
	}

	allowed, err := controller.isProviderAwareBreakglassApprover(
		context.Background(), providerAuthContext("tdi", "https://issuer/tdi"),
		session, "approver", "",
	)
	require.NoError(t, err)
	require.True(t, allowed)

	allowed, err = controller.isProviderAwareBreakglassApprover(
		context.Background(), providerAuthContext("tdg", "https://issuer/tdg"),
		session, "approver", "",
	)
	require.NoError(t, err)
	require.False(t, allowed)
}
