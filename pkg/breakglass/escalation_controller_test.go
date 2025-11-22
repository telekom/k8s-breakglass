package breakglass

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
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
	esc := &v1alpha1.BreakglassEscalation{
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
		Status: v1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{"ops": {"alice", "bob"}},
			IDPGroupMemberships: map[string]map[string][]string{
				"azure": {
					"ops": {"alice"},
				},
			},
		},
	}

	dropK8sInternalFieldsEscalation(esc)

	assert.Equal(t, "", string(esc.ObjectMeta.UID))
	assert.Equal(t, "", esc.ObjectMeta.ResourceVersion)
	assert.EqualValues(t, 0, esc.ObjectMeta.Generation)
	assert.Nil(t, esc.ObjectMeta.ManagedFields)
	assert.Equal(t, "keep", esc.ObjectMeta.Annotations["visible"])
	if _, exists := esc.ObjectMeta.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; exists {
		assert.Fail(t, "kubectl last-applied annotation should be removed")
	}
	assert.Nil(t, esc.Status.ApproverGroupMembers)
	assert.Nil(t, esc.Status.IDPGroupMemberships)
}
