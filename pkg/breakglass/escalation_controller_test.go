package breakglass

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
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
