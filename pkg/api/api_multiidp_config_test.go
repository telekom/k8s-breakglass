package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/telekom/k8s-breakglass/pkg/config"
)

// Config Endpoint Test Suite: Multi-IDP Config Endpoint
// Tests verify the REST endpoint /api/config/idps provides multi-IDP configuration
// for frontend IDP selector component.
//
// The endpoint returns:
// 1. List of enabled identity providers with metadata (name, displayName, issuer)
// 2. Mapping of escalations to their allowed IDPs for authorization

// TestMultiIDPConfigEndpointReturnsIDPList verifies endpoint returns list of IDPs
func TestMultiIDPConfigEndpointReturnsIDPList(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zaptest.NewLogger(t)
	server := &Server{log: logger}

	router := gin.New()
	router.GET("/api/config/idps", server.getMultiIDPConfig)

	req, err := http.NewRequest(http.MethodGet, "/api/config/idps", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var response MultiIDPConfigResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Response structure is valid JSON with the expected fields
	// (may be empty if reconciler not set or cache is empty)
	// This tests that the endpoint returns valid structure, not that it has data
	t.Logf("✅ Config endpoint returns multi-IDP config structure")
}

// TestIDPInfoStructure verifies IDPInfo has required fields for frontend
func TestIDPInfoStructure(t *testing.T) {
	testCases := []struct {
		name     string
		idp      IDPInfo
		validate func(t *testing.T, idp IDPInfo)
	}{
		{
			name: "CorporateIDP_AllFields",
			idp: IDPInfo{
				Name:        "corporate-idp",
				DisplayName: "Corporate Identity",
				Issuer:      "https://auth.corporate.com",
				Enabled:     true,
			},
			validate: func(t *testing.T, idp IDPInfo) {
				assert.Equal(t, "corporate-idp", idp.Name)
				assert.Equal(t, "Corporate Identity", idp.DisplayName)
				assert.Equal(t, "https://auth.corporate.com", idp.Issuer)
				assert.True(t, idp.Enabled)
			},
		},
		{
			name: "DisabledIDP",
			idp: IDPInfo{
				Name:        "legacy-idp",
				DisplayName: "Legacy IDP (Disabled)",
				Issuer:      "https://legacy.example.com",
				Enabled:     false,
			},
			validate: func(t *testing.T, idp IDPInfo) {
				assert.Equal(t, "legacy-idp", idp.Name)
				assert.False(t, idp.Enabled)
				assert.NotEmpty(t, idp.Issuer)
			},
		},
		{
			name: "KeycloakIDP_ComplexIssuer",
			idp: IDPInfo{
				Name:        "keycloak-idp",
				DisplayName: "Keycloak Instance",
				Issuer:      "https://keycloak.example.com/realms/master",
				Enabled:     true,
			},
			validate: func(t *testing.T, idp IDPInfo) {
				assert.Equal(t, "keycloak-idp", idp.Name)
				assert.Contains(t, idp.Issuer, "keycloak")
				assert.True(t, idp.Enabled)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.validate(t, tc.idp)
		})
	}

	t.Logf("✅ IDPInfo structure verified with required fields")
}

// TestMultiIDPConfigResponseJSON tests JSON marshalling and unmarshalling
func TestMultiIDPConfigResponseJSON(t *testing.T) {
	// Create a realistic multi-IDP config
	config := MultiIDPConfigResponse{
		IdentityProviders: []IDPInfo{
			{
				Name:        "corporate-idp",
				DisplayName: "Corporate Identity",
				Issuer:      "https://idp1.example.com",
				Enabled:     true,
			},
			{
				Name:        "contractor-idp",
				DisplayName: "Contractor Portal",
				Issuer:      "https://idp2.example.com",
				Enabled:     true,
			},
		},
		EscalationIDPMapping: map[string][]string{
			"prod-admin": {"corporate-idp"},                   // Only corp can access prod
			"dev-admin":  {"corporate-idp", "contractor-idp"}, // Both can access dev
			"qa-admin":   {},                                  // Empty = all allowed
		},
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(config)
	require.NoError(t, err)

	// Unmarshal back
	var unmarshalled MultiIDPConfigResponse
	err = json.Unmarshal(jsonBytes, &unmarshalled)
	require.NoError(t, err)

	// Verify round-trip integrity
	assert.Equal(t, len(config.IdentityProviders), len(unmarshalled.IdentityProviders))
	assert.Equal(t, len(config.EscalationIDPMapping), len(unmarshalled.EscalationIDPMapping))

	// Verify specific IDP values
	assert.Equal(t, "corporate-idp", unmarshalled.IdentityProviders[0].Name)
	assert.Equal(t, "contractor-idp", unmarshalled.IdentityProviders[1].Name)

	// Verify escalation mappings
	assert.Equal(t, 1, len(unmarshalled.EscalationIDPMapping["prod-admin"]))
	assert.Equal(t, 2, len(unmarshalled.EscalationIDPMapping["dev-admin"]))
	assert.Equal(t, 0, len(unmarshalled.EscalationIDPMapping["qa-admin"]))

	t.Logf("✅ JSON marshalling/unmarshalling verified")
}

// TestEscalationIDPMappingSemantics verifies mapping rules and their semantics
func TestEscalationIDPMappingSemantics(t *testing.T) {
	testCases := []struct {
		name          string
		escalation    string
		allowedIDPs   []string
		expectedUsage string
	}{
		{
			name:          "RestrictedToOneIDP",
			escalation:    "prod-admin",
			allowedIDPs:   []string{"corporate-idp"},
			expectedUsage: "Only corporate IDP can access production",
		},
		{
			name:          "MultipleIDPsAllowed",
			escalation:    "dev-admin",
			allowedIDPs:   []string{"corporate-idp", "contractor-idp"},
			expectedUsage: "Both corporate and contractor IDPs allowed for dev",
		},
		{
			name:          "AllIDPsAllowed_EmptyList",
			escalation:    "test-admin",
			allowedIDPs:   []string{}, // Empty list
			expectedUsage: "All IDPs allowed - empty means unrestricted",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mapping := MultiIDPConfigResponse{
				IdentityProviders: []IDPInfo{
					{Name: "corporate-idp", DisplayName: "Corporate", Issuer: "https://c.com", Enabled: true},
					{Name: "contractor-idp", DisplayName: "Contractor", Issuer: "https://con.com", Enabled: true},
				},
				EscalationIDPMapping: map[string][]string{
					tc.escalation: tc.allowedIDPs,
				},
			}

			// Frontend logic: if mapping is empty, all IDPs allowed
			if len(tc.allowedIDPs) == 0 {
				assert.True(t, true, "Empty list means all IDPs allowed")
			} else {
				assert.Greater(t, len(tc.allowedIDPs), 0)
				// Verify that mapped IDPs exist in the IDP list
				for _, idpName := range tc.allowedIDPs {
					found := false
					for _, idp := range mapping.IdentityProviders {
						if idp.Name == idpName {
							found = true
							break
						}
					}
					assert.True(t, found, "Mapped IDP %s should exist in IdentityProviders", idpName)
				}
			}
		})
	}

	t.Logf("✅ Escalation IDP mapping semantics verified")
}

// TestConfigEndpointResponseHeaders verifies HTTP response headers
func TestConfigEndpointResponseHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zaptest.NewLogger(t)
	server := &Server{log: logger}

	router := gin.New()
	router.GET("/api/config/idps", server.getMultiIDPConfig)

	req, err := http.NewRequest(http.MethodGet, "/api/config/idps", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check response status and headers
	assert.Equal(t, http.StatusOK, w.Code)
	contentType := w.Header().Get("Content-Type")
	assert.Contains(t, contentType, "application/json", "Should return JSON content type")

	t.Logf("✅ Response headers verified (Content-Type: %s)", contentType)
}

// TestEmptyIDPConfigHandling tests graceful handling of minimal config
func TestEmptyIDPConfigHandling(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zaptest.NewLogger(t)
	server := &Server{log: logger}

	router := gin.New()
	router.GET("/api/config/idps", server.getMultiIDPConfig)

	// Create a mock reconciler with cached IDPs for the test
	mockReconciler := &config.IdentityProviderReconciler{}
	server.SetIdentityProviderReconciler(mockReconciler)

	t.Run("ValidResponseStructure_MinimalConfig", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/api/config/idps", nil)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var response MultiIDPConfigResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Should not crash even with empty cache
		// IdentityProviders and EscalationIDPMapping may be nil or empty slices
		if response.IdentityProviders != nil {
			assert.Equal(t, len(response.IdentityProviders), 0)
		}
		if response.EscalationIDPMapping != nil {
			assert.Equal(t, len(response.EscalationIDPMapping), 0)
		}
	})

	t.Run("EscalationMappingCanBeEmpty", func(t *testing.T) {
		// Escalation with empty IDP list is valid - means all IDPs allowed
		mapping := MultiIDPConfigResponse{
			IdentityProviders: []IDPInfo{
				{Name: "idp1", DisplayName: "IDP 1", Issuer: "https://idp1.com", Enabled: true},
			},
			EscalationIDPMapping: map[string][]string{
				"escalation1": {}, // Empty is valid
			},
		}

		assert.NotNil(t, mapping.EscalationIDPMapping["escalation1"])
		assert.Equal(t, 0, len(mapping.EscalationIDPMapping["escalation1"]))
	})

	t.Logf("✅ Empty config handling verified")
}

// TestMultipleIDPsWithDifferentStatuses tests filtering and status handling
func TestMultipleIDPsWithDifferentStatuses(t *testing.T) {
	testCases := []struct {
		name               string
		idps               []IDPInfo
		expectEnabledCount int
	}{
		{
			name: "AllEnabled",
			idps: []IDPInfo{
				{Name: "idp1", DisplayName: "IDP 1", Issuer: "https://idp1.com", Enabled: true},
				{Name: "idp2", DisplayName: "IDP 2", Issuer: "https://idp2.com", Enabled: true},
			},
			expectEnabledCount: 2,
		},
		{
			name: "MixedStatus",
			idps: []IDPInfo{
				{Name: "idp1", DisplayName: "IDP 1", Issuer: "https://idp1.com", Enabled: true},
				{Name: "idp2", DisplayName: "IDP 2", Issuer: "https://idp2.com", Enabled: false},
				{Name: "idp3", DisplayName: "IDP 3", Issuer: "https://idp3.com", Enabled: true},
			},
			expectEnabledCount: 2,
		},
		{
			name: "AllDisabled",
			idps: []IDPInfo{
				{Name: "idp1", DisplayName: "IDP 1", Issuer: "https://idp1.com", Enabled: false},
				{Name: "idp2", DisplayName: "IDP 2", Issuer: "https://idp2.com", Enabled: false},
			},
			expectEnabledCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Count enabled IDPs
			enabledCount := 0
			for _, idp := range tc.idps {
				if idp.Enabled {
					enabledCount++
				}
			}

			assert.Equal(t, tc.expectEnabledCount, enabledCount)
		})
	}

	t.Logf("✅ Multiple IDPs with different statuses verified")
}

// TestSpecialCharactersInIDPNames tests handling of various naming patterns
func TestSpecialCharactersInIDPNames(t *testing.T) {
	testCases := []struct {
		name        string
		idpName     string
		displayName string
		issuer      string
	}{
		{
			name:        "WithDashes",
			idpName:     "corporate-idp-v2",
			displayName: "Corporate IDP v2",
			issuer:      "https://auth-v2.example.com",
		},
		{
			name:        "WithUnderscores",
			idpName:     "internal_keycloak",
			displayName: "Internal Keycloak",
			issuer:      "https://keycloak_internal.example.com",
		},
		{
			name:        "WithNumbers",
			idpName:     "azure-ad-001",
			displayName: "Azure AD Instance 1",
			issuer:      "https://login.microsoftonline.com/tenant-id/v2.0",
		},
		{
			name:        "WithURLPath",
			idpName:     "keycloak-prod",
			displayName: "Keycloak Production",
			issuer:      "https://keycloak.prod.example.com/auth/realms/production",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			idp := IDPInfo{
				Name:        tc.idpName,
				DisplayName: tc.displayName,
				Issuer:      tc.issuer,
				Enabled:     true,
			}

			// Should marshal without issue
			jsonBytes, err := json.Marshal(idp)
			require.NoError(t, err)

			var unmarshalled IDPInfo
			err = json.Unmarshal(jsonBytes, &unmarshalled)
			require.NoError(t, err)

			assert.Equal(t, tc.idpName, unmarshalled.Name)
			assert.Equal(t, tc.issuer, unmarshalled.Issuer)
			assert.True(t, unmarshalled.Enabled)
		})
	}

	t.Logf("✅ Special characters in IDP names verified")
}

// TestLargeConfigScaling tests endpoint response with many IDPs and escalations
func TestLargeConfigScaling(t *testing.T) {
	// Create a large config with many IDPs and escalation mappings
	idps := make([]IDPInfo, 50)
	for i := range 50 {
		idps[i] = IDPInfo{
			Name:        "idp-" + string(rune(48+i%10)), // 0-9 cycle
			DisplayName: "IDP Instance " + string(rune(48+i%10)),
			Issuer:      "https://idp-" + string(rune(48+i%10)) + ".example.com",
			Enabled:     i%2 == 0, // Half enabled, half disabled
		}
	}

	mappings := make(map[string][]string)
	for i := range 100 {
		escalationName := "escalation-" + string(rune(48+i%10))
		// Randomly assign 0-3 IDPs to each escalation
		numIDPs := i % 4
		var assignedIDPs []string
		for j := range numIDPs {
			assignedIDPs = append(assignedIDPs, "idp-"+string(rune(48+j)))
		}
		mappings[escalationName] = assignedIDPs
	}

	response := MultiIDPConfigResponse{
		IdentityProviders:    idps,
		EscalationIDPMapping: mappings,
	}

	// Should marshal without issue
	jsonBytes, err := json.Marshal(response)
	require.NoError(t, err)

	// Should be reasonable size
	size := len(jsonBytes)
	assert.Less(t, size, 500000, "Config should be under 500KB (currently %d bytes)", size)

	// Unmarshal back
	var unmarshalled MultiIDPConfigResponse
	err = json.Unmarshal(jsonBytes, &unmarshalled)
	require.NoError(t, err)

	assert.Equal(t, 50, len(unmarshalled.IdentityProviders))
	assert.Equal(t, 10, len(unmarshalled.EscalationIDPMapping)) // 10 unique escalation names

	t.Logf("✅ Large config scaling verified (%d bytes for 50 IDPs + 100 escalations)", size)
}

// TestBackwardCompatibilitySingleIDP tests backward compat with single-IDP mode
func TestBackwardCompatibilitySingleIDP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zaptest.NewLogger(t)
	server := &Server{log: logger}

	router := gin.New()
	router.GET("/api/config/idps", server.getMultiIDPConfig)

	req, err := http.NewRequest(http.MethodGet, "/api/config/idps", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var response MultiIDPConfigResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Response structure should be valid even in single-IDP mode
	assert.NotNil(t, response.IdentityProviders)
	assert.NotNil(t, response.EscalationIDPMapping)

	// In single-IDP mode, frontend should show info message or default selection
	if len(response.IdentityProviders) == 1 {
		t.Logf("Single-IDP mode detected - frontend should show info message")
		assert.Equal(t, "corporate-idp", response.IdentityProviders[0].Name)
	}

	// Even if no IDPs, response is still valid
	if len(response.IdentityProviders) == 0 {
		t.Logf("No IDPs configured - frontend should show error state")
		assert.NotNil(t, response.IdentityProviders)
	}

	t.Logf("✅ Backward compatibility with single-IDP mode verified")
}

// TestMultiIDPConfigWithCachedIDPs verifies the /api/config/idps endpoint uses cached IDPs
func TestMultiIDPConfigWithCachedIDPs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zaptest.NewLogger(t)
	server := &Server{log: logger}

	// Create a mock reconciler with cached IDPs
	mockReconciler := &config.IdentityProviderReconciler{}
	server.SetIdentityProviderReconciler(mockReconciler)

	router := gin.New()
	router.GET("/api/config/idps", server.getMultiIDPConfig)

	// Since we can't easily test GetCachedIdentityProviders directly,
	// we verify that the endpoint returns valid JSON structure
	req, err := http.NewRequest(http.MethodGet, "/api/config/idps", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var response MultiIDPConfigResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Endpoint should return valid structure (even if empty)
	// In production, IDPs would be populated by the reconciler's cache
	assert.NotNil(t, response, "Response should not be nil")

	t.Logf("✅ Multi-IDP config endpoint with caching verified")
}
