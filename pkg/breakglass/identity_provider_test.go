package breakglass

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
)

func TestKeycloakIdentityProvider_GetEmail(t *testing.T) {
	// TestKeycloakIdentityProvider_GetEmail
	//
	// Purpose:
	//   Unit tests for KeycloakIdentityProvider that verify behavior when expected
	//   Gin context keys are present or missing.
	//
	// Reasoning:
	//   Identity provider helpers must correctly retrieve values from context and
	//   return meaningful errors when required keys are absent.
	//
	// Flow pattern:
	//   - Use gin test contexts with and without the expected keys and assert the
	//     returned values and errors match expectations.
	//
	gin.SetMode(gin.TestMode)
	provider := KeycloakIdentityProvider{}

	tests := []struct {
		name        string
		email       string
		expectEmail string
		expectError bool
	}{
		{
			name:        "Valid email",
			email:       "test@example.com",
			expectEmail: "test@example.com",
			expectError: false,
		},
		{
			name:        "Empty email",
			email:       "",
			expectEmail: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(nil)
			if tt.email != "" {
				c.Set("email", tt.email)
			}

			email, err := provider.GetEmail(c)

			assert.Equal(t, tt.expectEmail, email)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestKeycloakIdentityProvider_GetUsername(t *testing.T) {
	// TestKeycloakIdentityProvider_GetUsername
	//
	// Purpose:
	//   Ensures username retrieval from Gin context works for present and absent
	//   values.
	//
	gin.SetMode(gin.TestMode)
	provider := KeycloakIdentityProvider{}

	tests := []struct {
		name           string
		username       string
		expectUsername string
	}{
		{
			name:           "Valid username",
			username:       "testuser",
			expectUsername: "testuser",
		},
		{
			name:           "Empty username",
			username:       "",
			expectUsername: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(nil)
			if tt.username != "" {
				c.Set("username", tt.username)
			}

			username := provider.GetUsername(c)

			assert.Equal(t, tt.expectUsername, username)
		})
	}
}

func TestKeycloakIdentityProvider_GetIdentity(t *testing.T) {
	// TestKeycloakIdentityProvider_GetIdentity
	//
	// Purpose:
	//   Verifies the provider returns the expected identity string from context.
	//
	// Reasoning:
	//   The identity extraction should be simple and predictable; tests cover both
	//   set and unset cases.
	//
	gin.SetMode(gin.TestMode)
	provider := KeycloakIdentityProvider{}

	tests := []struct {
		name           string
		userID         string
		expectIdentity string
	}{
		{
			name:           "Valid user ID",
			userID:         "user123",
			expectIdentity: "user123",
		},
		{
			name:           "Empty user ID",
			userID:         "",
			expectIdentity: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(nil)
			if tt.userID != "" {
				c.Set("user_id", tt.userID)
			}

			identity := provider.GetIdentity(c)

			assert.Equal(t, tt.expectIdentity, identity)
		})
	}
}

func TestKeycloakIdentityProvider_GetUserIdentifier(t *testing.T) {
	// TestKeycloakIdentityProvider_GetUserIdentifier
	//
	// Purpose:
	//   Verifies that GetUserIdentifier correctly extracts the user identifier
	//   based on the configured UserIdentifierClaimType setting.
	//
	// Reasoning:
	//   The userIdentifierClaim field in ClusterConfig determines which OIDC claim
	//   the spoke cluster uses for its username. The hub must store the matching
	//   identifier in the session to enable SAR authorization matching.
	//
	gin.SetMode(gin.TestMode)
	provider := KeycloakIdentityProvider{}

	tests := []struct {
		name             string
		claimType        breakglassv1alpha1.UserIdentifierClaimType
		email            string
		username         string
		userID           string
		expectIdentifier string
		expectError      bool
	}{
		{
			name:             "Email claim - valid",
			claimType:        breakglassv1alpha1.UserIdentifierClaimEmail,
			email:            "test@example.com",
			username:         "testuser",
			userID:           "sub-123",
			expectIdentifier: "test@example.com",
			expectError:      false,
		},
		{
			name:             "Email claim - missing",
			claimType:        breakglassv1alpha1.UserIdentifierClaimEmail,
			email:            "",
			username:         "testuser",
			userID:           "sub-123",
			expectIdentifier: "",
			expectError:      true,
		},
		{
			name:             "Preferred username claim - valid",
			claimType:        breakglassv1alpha1.UserIdentifierClaimPreferredUsername,
			email:            "test@example.com",
			username:         "testuser",
			userID:           "sub-123",
			expectIdentifier: "testuser",
			expectError:      false,
		},
		{
			name:             "Preferred username claim - missing",
			claimType:        breakglassv1alpha1.UserIdentifierClaimPreferredUsername,
			email:            "test@example.com",
			username:         "",
			userID:           "sub-123",
			expectIdentifier: "",
			expectError:      true,
		},
		{
			name:             "Sub claim - valid",
			claimType:        breakglassv1alpha1.UserIdentifierClaimSub,
			email:            "test@example.com",
			username:         "testuser",
			userID:           "sub-123",
			expectIdentifier: "sub-123",
			expectError:      false,
		},
		{
			name:             "Sub claim - missing",
			claimType:        breakglassv1alpha1.UserIdentifierClaimSub,
			email:            "test@example.com",
			username:         "testuser",
			userID:           "",
			expectIdentifier: "",
			expectError:      true,
		},
		{
			name:             "Default (empty) claim type - falls back to email",
			claimType:        "",
			email:            "default@example.com",
			username:         "defaultuser",
			userID:           "sub-default",
			expectIdentifier: "default@example.com",
			expectError:      false,
		},
		{
			name:             "Unknown claim type - falls back to email",
			claimType:        "unknown_claim",
			email:            "fallback@example.com",
			username:         "fallbackuser",
			userID:           "sub-fallback",
			expectIdentifier: "fallback@example.com",
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(nil)
			if tt.email != "" {
				c.Set("email", tt.email)
			}
			if tt.username != "" {
				c.Set("username", tt.username)
			}
			if tt.userID != "" {
				c.Set("user_id", tt.userID)
			}

			identifier, err := provider.GetUserIdentifier(c, tt.claimType)

			assert.Equal(t, tt.expectIdentifier, identifier)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestKeycloakIdentityProvider_LoggerInjection(t *testing.T) {
	t.Run("injected logger is used", func(t *testing.T) {
		logger, err := zap.NewDevelopment()
		require.NoError(t, err)
		t.Cleanup(func() { _ = logger.Sync() })
		sugar := logger.Sugar()
		kip := KeycloakIdentityProvider{log: sugar}

		require.Same(t, sugar, kip.getLogger())
	})

	t.Run("fallback to global logger when no logger set", func(t *testing.T) {
		kip := KeycloakIdentityProvider{}

		require.Nil(t, kip.log, "log field should be nil when no logger set")
		// getLogger() should still return a non-nil logger (global fallback)
		require.NotNil(t, kip.getLogger())
	})
}
