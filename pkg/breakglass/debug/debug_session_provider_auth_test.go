package debug

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestDebugSessionProviderProvenanceFailsClosedAcrossProviderUpgrade(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		provider    string
		issuer      string
		matches     bool
		missing     bool
	}{
		{
			name:     "legacy single provider session",
			provider: "tdi",
			issuer:   "https://issuer/tdi",
			missing:  true,
		},
		{
			name:        "legacy session remains ambiguous with multiple providers",
			annotations: map[string]string{},
			provider:    "tdg",
			issuer:      "https://issuer/tdg",
			missing:     true,
		},
		{
			name: "recorded provider and issuer match",
			annotations: map[string]string{
				debugSessionIdentityProviderAnnotation: "tdi",
				debugSessionIdentityIssuerAnnotation:   "https://issuer/tdi",
			},
			provider: "tdi",
			issuer:   "https://issuer/tdi",
			matches:  true,
		},
		{
			name: "new provider cannot use another provider session",
			annotations: map[string]string{
				debugSessionIdentityProviderAnnotation: "tdi",
				debugSessionIdentityIssuerAnnotation:   "https://issuer/tdi",
			},
			provider: "tdg",
			issuer:   "https://issuer/tdg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Annotations: tt.annotations},
			}
			auth := providerAuthContext(tt.provider, tt.issuer)
			require.Equal(t, tt.missing, debugSessionProviderProvenanceMissing(session, auth))
			require.Equal(t, tt.matches, debugSessionProviderMatchesRequest(session, auth))
		})
	}
}

func TestLegacyDebugSessionCannotBeApprovedOrRejectedByProviderAwareAuth(t *testing.T) {
	for _, operation := range []string{"approve", "reject"} {
		t.Run(operation, func(t *testing.T) {
			scheme := testScheme()
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "default"},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					Cluster:     "cluster-a",
					TemplateRef: "template",
					RequestedBy: "requester",
				},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: breakglassv1alpha1.DebugSessionStatePendingApproval,
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						Approvers: &breakglassv1alpha1.DebugSessionApprovers{
							Users: []string{"approver"},
						},
					},
				},
			}
			client := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(session).
				WithStatusSubresource(session).
				Build()
			controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), client, nil, nil)

			router := gin.New()
			router.Use(func(ctx *gin.Context) {
				ctx.Set("username", "approver")
				ctx.Set("identity_provider_name", "tdi")
				ctx.Set("issuer", "https://issuer/tdi")
				ctx.Next()
			})
			require.NoError(t, controller.Register(router.Group("/debugSessions")))

			request := httptest.NewRequest(http.MethodPost, "/debugSessions/legacy/"+operation+"?namespace=default", nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			require.Equal(t, http.StatusConflict, response.Code)
			require.Contains(t, response.Body.String(), "predates provider provenance")
		})
	}
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
				State:     breakglassv1alpha1.SessionStateApproved,
				ExpiresAt: metav1.NewTime(time.Now().Add(time.Hour)),
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
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Groups: []string{"breakglass:platform:emergency"},
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
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"breakglass:platform:emergency"},
			},
		},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{
				"breakglass:platform:emergency": {"approver"},
			},
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding, escalation).Build()
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), client, nil, nil)
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			debugSessionIdentityProviderAnnotation: "tdi",
			debugSessionIdentityIssuerAnnotation:   "https://issuer/tdi",
		}},
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

func TestDebugSessionRequesterRejectsInvalidProviderBoundBreakglassSessions(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name   string
		status breakglassv1alpha1.BreakglassSessionStatus
	}{
		{
			name: "zero expiry",
			status: breakglassv1alpha1.BreakglassSessionStatus{
				State: breakglassv1alpha1.SessionStateApproved,
			},
		},
		{
			name: "expired",
			status: breakglassv1alpha1.BreakglassSessionStatus{
				State:     breakglassv1alpha1.SessionStateApproved,
				ExpiresAt: metav1.NewTime(now.Add(-time.Minute)),
			},
		},
		{
			name: "rejected",
			status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateApproved,
				ExpiresAt:  metav1.NewTime(now.Add(time.Hour)),
				RejectedAt: metav1.NewTime(now),
			},
		},
		{
			name: "retained terminal session",
			status: breakglassv1alpha1.BreakglassSessionStatus{
				State:         breakglassv1alpha1.SessionStateRejected,
				RejectedAt:    metav1.NewTime(now.Add(-time.Hour)),
				RetainedUntil: metav1.NewTime(now.Add(-time.Minute)),
				ExpiresAt:     metav1.NewTime(now.Add(time.Hour)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := testScheme()
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				&breakglassv1alpha1.BreakglassSession{
					ObjectMeta: metav1.ObjectMeta{Name: "invalid", Namespace: "default"},
					Spec: breakglassv1alpha1.BreakglassSessionSpec{
						Cluster:                "cluster-a",
						User:                   "requester",
						GrantedGroup:           "breakglass:platform:debugsession",
						IdentityProviderName:   "tdi",
						IdentityProviderIssuer: "https://issuer/tdi",
					},
					Status: tt.status,
				},
			).Build()
			controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), client, nil, nil)

			allowed, err := controller.isDebugSessionRequesterAllowed(
				providerAuthContext("tdi", "https://issuer/tdi"),
				&breakglassv1alpha1.DebugSessionAllowed{Groups: []string{"breakglass:platform:debugsession"}},
				"requester", "", nil, "cluster-a",
			)
			require.NoError(t, err)
			require.False(t, allowed)
		})
	}
}

func TestDebugSessionProviderAwareApproverRejectsInactiveBinding(t *testing.T) {
	now := metav1.Now()
	for _, bindingSpec := range []breakglassv1alpha1.DebugSessionClusterBindingSpec{
		{
			Disabled: true,
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{
				Groups: []string{"breakglass:platform:debugsession"},
			},
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Groups: []string{"breakglass:platform:emergency"},
			},
		},
		{
			ExpiresAt: &now,
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{
				Groups: []string{"breakglass:platform:debugsession"},
			},
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Groups: []string{"breakglass:platform:emergency"},
			},
		},
	} {
		scheme := testScheme()
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default"},
			Spec:       bindingSpec,
		}
		client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding).Build()
		controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), client, nil, nil)
		allowed, err := controller.isProviderAwareBreakglassApprover(
			context.Background(),
			providerAuthContext("tdi", "https://issuer/tdi"),
			&breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
					debugSessionIdentityProviderAnnotation: "tdi",
					debugSessionIdentityIssuerAnnotation:   "https://issuer/tdi",
				}},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					Cluster: "cluster-a",
					BindingRef: &breakglassv1alpha1.BindingReference{
						Name: "binding", Namespace: "default",
					},
				},
			},
			"approver", "",
		)
		require.NoError(t, err)
		require.False(t, allowed)
	}
}

func TestDebugSessionProviderAwareApproverHonorsExplicitBindingOverride(t *testing.T) {
	scheme := testScheme()
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{
				Groups: []string{"breakglass:platform:debugsession"},
			},
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Groups: []string{"breakglass:platform:emergency"},
			},
		},
	}
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "poweruser-escalation", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"cluster-a"},
			},
			EscalatedGroup:                       "breakglass:platform:debugsession",
			AllowedIdentityProvidersForApprovers: []string{"tdi"},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"breakglass:platform:poweruser"},
			},
		},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{
				"breakglass:platform:poweruser": {"approver"},
			},
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding, escalation).Build()
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), client, nil, nil)
	allowed, err := controller.isProviderAwareBreakglassApprover(
		context.Background(),
		providerAuthContext("tdi", "https://issuer/tdi"),
		&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
				debugSessionIdentityProviderAnnotation: "tdi",
				debugSessionIdentityIssuerAnnotation:   "https://issuer/tdi",
			}},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster: "cluster-a",
				BindingRef: &breakglassv1alpha1.BindingReference{
					Name: "binding", Namespace: "default",
				},
			},
		},
		"approver", "",
	)
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestDebugSessionProviderAwareApproverInheritsResolvedTemplatePolicy(t *testing.T) {
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
		ObjectMeta: metav1.ObjectMeta{Name: "emergency-escalation", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"cluster-a"},
			},
			EscalatedGroup:                       "breakglass:platform:debugsession",
			AllowedIdentityProvidersForApprovers: []string{"tdi"},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"breakglass:platform:emergency"},
			},
		},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{
				"breakglass:platform:emergency": {"approver"},
			},
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding, escalation).Build()
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), client, nil, nil)
	allowed, err := controller.isProviderAwareBreakglassApprover(
		context.Background(),
		providerAuthContext("tdi", "https://issuer/tdi"),
		&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
				debugSessionIdentityProviderAnnotation: "tdi",
				debugSessionIdentityIssuerAnnotation:   "https://issuer/tdi",
			}},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster: "cluster-a",
				BindingRef: &breakglassv1alpha1.BindingReference{
					Name: "binding", Namespace: "default",
				},
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
					Approvers: &breakglassv1alpha1.DebugSessionApprovers{
						Groups: []string{"breakglass:platform:emergency"},
					},
				},
			},
		},
		"approver", "",
	)
	require.NoError(t, err)
	require.True(t, allowed)
}
