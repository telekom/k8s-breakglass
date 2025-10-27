package breakglass

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
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
