package escalation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
)

func TestBreakglassEscalationController_BasePath(t *testing.T) {
	// TestBreakglassEscalationController_BasePath
	//
	// Purpose:
	//   Simple unit test to verify the controller reports its BasePath constant
	//   correctly.
	//
	// Reasoning:
	//   Ensures routing registration uses a consistent path string.
	//
	controller := BreakglassEscalationController{}
	assert.Equal(t, "breakglassEscalations", controller.BasePath())
}

func TestBreakglassEscalationController_Handlers(t *testing.T) {
	// TestBreakglassEscalationController_Handlers
	//
	// Purpose:
	//   Ensures the controller returns the expected number of handler functions
	//   for registration (sanity check).
	//
	// Reasoning:
	//   Basic sanity test for handler wiring; keeps route registration predictable.
	//
	middleware := func(c *gin.Context) {}
	controller := BreakglassEscalationController{middleware: middleware}

	handlers := controller.Handlers()
	assert.Len(t, handlers, 1)
}

func TestNewBreakglassEscalationController(t *testing.T) {
	// TestNewBreakglassEscalationController
	//
	// Purpose:
	//   Verifies NewBreakglassEscalationController initializes its fields and
	//   factories (identity provider, group resolver) properly when possible.
	//
	// Reasoning:
	//   Basic constructor test that may be skipped if environment lacks a
	//   Kubernetes context required by NewEscalationManager.
	//
	logger := zaptest.NewLogger(t)
	// Create a real EscalationManager for testing initialization
	manager, err := NewEscalationManager("", &KeycloakGroupMemberResolver{})
	if err != nil {
		t.Skip("Skipping test as it requires Kubernetes context")
	}

	middleware := func(c *gin.Context) {}

	controller := NewBreakglassEscalationController(logger.Sugar(), &manager, middleware, "/config/config.yaml")

	assert.NotNil(t, controller)
	assert.Equal(t, logger.Sugar(), controller.log)
	assert.Equal(t, &manager, controller.manager)
	assert.NotNil(t, controller.identityProvider)
	assert.NotNil(t, controller.getUserGroupsFn)
}

func TestDropK8sInternalFieldsEscalationStripsMetadataAndStatus(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			UID:             types.UID("12345"),
			ResourceVersion: "9001",
			Generation:      42,
			ManagedFields:   []metav1.ManagedFieldsEntry{{}},
			Annotations: map[string]string{
				"kubectl.kubernetes.io/last-applied-configuration": "{}",
				"visible": "keep",
			},
		},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{"ops": {"alice", "bob"}},
			IDPGroupMemberships: map[string]map[string][]string{
				"azure": {
					"ops": {"alice"},
				},
			},
		},
	}

	dropK8sInternalFieldsEscalation(esc)

	assert.Equal(t, "", string(esc.UID))
	assert.Equal(t, "", esc.ResourceVersion)
	assert.EqualValues(t, 0, esc.Generation)
	assert.Nil(t, esc.ManagedFields)
	assert.Equal(t, "keep", esc.Annotations["visible"])
	if _, exists := esc.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; exists {
		assert.Fail(t, "kubectl last-applied annotation should be removed")
	}
	assert.Nil(t, esc.Status.ApproverGroupMembers)
	assert.Nil(t, esc.Status.IDPGroupMemberships)
}

type stubIdentityProvider struct {
	email string
	err   error
}

func (s *stubIdentityProvider) GetEmail(_ *gin.Context) (string, error) {
	return s.email, s.err
}
func (s *stubIdentityProvider) GetUsername(_ *gin.Context) string { return "" }
func (s *stubIdentityProvider) GetIdentity(_ *gin.Context) string { return s.email }
func (s *stubIdentityProvider) GetUserIdentifier(_ *gin.Context, _ breakglassv1alpha1.UserIdentifierClaimType) (string, error) {
	return s.email, s.err
}

func TestHandleGetEscalationsDoesNotLogRawTokenGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, recorded := observer.New(zap.DebugLevel)
	obsLogger := zap.New(core).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
	em := &EscalationManager{Client: fakeClient}

	ec := &BreakglassEscalationController{
		manager:          em,
		log:              obsLogger,
		identityProvider: &stubIdentityProvider{email: "alice@example.com"},
		getUserGroupsFn: func(_ context.Context, _ breakglass.ClusterUserGroup) ([]string, error) {
			return []string{}, nil
		},
		configPath: "/nonexistent/config.yaml",
	}

	w := httptest.NewRecorder()
	ctx, engine := gin.CreateTestContext(w)
	ctx.Set("groups", []string{"sensitive-admin-role", "internal-sre-team"})
	ctx.Request, _ = http.NewRequest(http.MethodGet, "/breakglassEscalations", nil)

	engine.GET("/breakglassEscalations", ec.handleGetEscalations)
	engine.ServeHTTP(w, ctx.Request)

	for _, entry := range recorded.All() {
		fields := entry.ContextMap()
		_, hasRawTokenGroups := fields["rawTokenGroups"]
		require.False(t, hasRawTokenGroups,
			"rawTokenGroups field must not appear in log entry %q", entry.Message)
		_, hasMatchingGroup := fields["matchingGroup"]
		require.False(t, hasMatchingGroup,
			"matchingGroup field must not appear in log entry %q", entry.Message)
	}
}
