package mail

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderRequest(t *testing.T) {
	params := RequestMailParams{
		SubjectFullName: "John Doe",
		SubjectEmail:    "john.doe@example.com",
		RequestedRole:   "admin",
		URL:             "https://example.com/approve",
		BrandingName:    "Das SCHIFF Breakglass",
	}

	result, err := RenderRequest(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.SubjectFullName)
	assert.Contains(t, result, params.SubjectEmail)
	assert.Contains(t, result, params.RequestedRole)
	assert.Contains(t, result, params.URL)
}

func TestRenderApproved(t *testing.T) {
	params := ApprovedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		ApproverFullName: "Jane Smith",
		ApproverEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
	}

	result, err := RenderApproved(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.SubjectFullName)
	assert.Contains(t, result, params.SubjectEmail)
	assert.Contains(t, result, params.RequestedRole)
	assert.Contains(t, result, params.ApproverFullName)
	assert.Contains(t, result, params.ApproverEmail)
}

func TestRenderRejected(t *testing.T) {
	params := RejectedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		RejectorFullName: "Jane Smith",
		RejectorEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
		RejectedAt:       "2025-11-18 10:30:00",
		RejectionReason:  "Insufficient justification provided",
		SessionID:        "rejected-session-123",
		Cluster:          "prod-cluster-01",
		Username:         "john.doe",
	}

	result, err := RenderRejected(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.SubjectFullName)
	assert.Contains(t, result, params.SubjectEmail)
	assert.Contains(t, result, params.RequestedRole)
	assert.Contains(t, result, params.RejectorFullName)
	assert.Contains(t, result, params.RejectorEmail)
	assert.Contains(t, result, params.RejectedAt)
	assert.Contains(t, result, params.RejectionReason)
	assert.Contains(t, result, params.SessionID)
	assert.Contains(t, result, params.Cluster)
	assert.Contains(t, result, "REJECTED")
	assert.Contains(t, result, "What Can You Do?")
}

// TestRenderRejectedWithoutReason tests the rejected email when no reason is provided
func TestRenderRejectedWithoutReason(t *testing.T) {
	params := RejectedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		RejectorFullName: "Jane Smith",
		RejectorEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
		RejectedAt:       "2025-11-18 10:30:00",
		RejectionReason:  "", // No reason provided
		SessionID:        "rejected-session-456",
		Cluster:          "prod-cluster-01",
	}

	result, err := RenderRejected(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.SubjectFullName)
	assert.Contains(t, result, "REJECTED")
	// Should not crash or error with empty reason
}

// TestRenderApprovedWithCompleteInfo tests the approved email with all fields populated
func TestRenderApprovedWithCompleteInfo(t *testing.T) {
	params := ApprovedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		ApproverFullName: "Jane Smith",
		ApproverEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
		ApprovedAt:       "2025-11-18 10:30:00",
		ActivationTime:   "2025-11-18 10:30:00",
		ExpirationTime:   "2025-11-18 12:30:00",
		IsScheduled:      false,
		SessionID:        "test-session-123",
		Cluster:          "prod-cluster-01",
		Username:         "john.doe",
		ApprovalReason:   "Production incident - database recovery",
	}

	result, err := RenderApproved(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	// Check all fields are rendered
	assert.Contains(t, result, params.SubjectFullName)
	assert.Contains(t, result, params.SubjectEmail)
	assert.Contains(t, result, params.RequestedRole)
	assert.Contains(t, result, params.ApproverFullName)
	assert.Contains(t, result, params.ApproverEmail)
	assert.Contains(t, result, params.ApprovedAt)
	assert.Contains(t, result, params.ActivationTime)
	assert.Contains(t, result, params.ExpirationTime)
	assert.Contains(t, result, params.SessionID)
	assert.Contains(t, result, params.Cluster)
	assert.Contains(t, result, params.Username)
	assert.Contains(t, result, params.ApprovalReason)
	// Check for key audit messaging
	assert.Contains(t, result, "audited")
	assert.Contains(t, result, "permanent")
	assert.Contains(t, result, "emergency use only")
}

// TestRenderApprovedScheduled tests the approved email for a scheduled session
func TestRenderApprovedScheduled(t *testing.T) {
	params := ApprovedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		ApproverFullName: "Jane Smith",
		ApproverEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
		ApprovedAt:       "2025-11-18 10:30:00",
		ActivationTime:   "2025-11-18 14:00:00", // Future activation
		ExpirationTime:   "2025-11-18 16:00:00",
		IsScheduled:      true,
		SessionID:        "scheduled-session-456",
		Cluster:          "prod-cluster-01",
		Username:         "john.doe",
	}

	result, err := RenderApproved(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.ActivationTime)
	assert.Contains(t, result, "SCHEDULED")
	assert.Contains(t, result, "will become active")
	// Should mention the scheduled nature
	assert.Contains(t, result, "scheduled")
}

// TestRenderApprovedImmediate tests the approved email for an immediately active session
func TestRenderApprovedImmediate(t *testing.T) {
	params := ApprovedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		ApproverFullName: "Jane Smith",
		ApproverEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
		ApprovedAt:       "2025-11-18 10:30:00",
		ActivationTime:   "2025-11-18 10:30:00", // Immediate activation
		ExpirationTime:   "2025-11-18 12:30:00",
		IsScheduled:      false,
		SessionID:        "immediate-session-789",
		Cluster:          "prod-cluster-01",
		Username:         "john.doe",
	}

	result, err := RenderApproved(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "ACTIVE NOW")
	assert.Contains(t, result, "granted immediately")
}

func TestRenderBreakglassSessionRequest(t *testing.T) {
	params := RequestBreakglassSessionMailParams{
		SubjectEmail:      "john.doe@example.com",
		SubjectFullName:   "John Doe",
		RequestedCluster:  "test-cluster",
		RequestedUsername: "testuser",
		RequestedGroup:    "admin",
		URL:               "https://example.com/session",
		BrandingName:      "Das SCHIFF Breakglass",
	}

	result, err := RenderBreakglassSessionRequest(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.SubjectEmail)
	assert.Contains(t, result, params.SubjectFullName)
	assert.Contains(t, result, params.RequestedCluster)
	assert.Contains(t, result, params.RequestedUsername)
	assert.Contains(t, result, params.RequestedGroup)
	assert.Contains(t, result, params.URL)
}

func TestRenderBreakglassSessionNotification(t *testing.T) {
	params := RequestBreakglassSessionMailParams{
		SubjectEmail:      "john.doe@example.com",
		SubjectFullName:   "John Doe",
		RequestedCluster:  "test-cluster",
		RequestedUsername: "testuser",
		RequestedGroup:    "admin",
		URL:               "https://example.com/session",
		BrandingName:      "Das SCHIFF Breakglass",
	}

	result, err := RenderBreakglassSessionNotification(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.SubjectEmail)
	assert.Contains(t, result, params.SubjectFullName)
	assert.Contains(t, result, params.RequestedCluster)
	assert.Contains(t, result, params.RequestedUsername)
	assert.Contains(t, result, params.RequestedGroup)
	assert.Contains(t, result, params.URL)
}

func TestRender(t *testing.T) {
	tests := []struct {
		name        string
		params      interface{}
		expectError bool
	}{
		{
			name: "Valid params",
			params: RequestMailParams{
				SubjectFullName: "Test User",
				SubjectEmail:    "test@example.com",
				RequestedRole:   "admin",
				URL:             "https://example.com",
			},
			expectError: false,
		},
		{
			name:        "Nil params",
			params:      nil,
			expectError: false, // template execution with nil should work
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := render(requestTemplate, tt.params)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestTemplateParameterTypes(t *testing.T) {
	t.Run("RequestMailParams", func(t *testing.T) {
		params := RequestMailParams{}
		assert.IsType(t, "", params.SubjectFullName)
		assert.IsType(t, "", params.SubjectEmail)
		assert.IsType(t, "", params.RequestedRole)
		assert.IsType(t, "", params.URL)
		assert.IsType(t, "", params.BrandingName)
	})

	t.Run("ApprovedMailParams", func(t *testing.T) {
		params := ApprovedMailParams{}
		assert.IsType(t, "", params.SubjectFullName)
		assert.IsType(t, "", params.SubjectEmail)
		assert.IsType(t, "", params.RequestedRole)
		assert.IsType(t, "", params.ApproverFullName)
		assert.IsType(t, "", params.ApproverEmail)
		assert.IsType(t, "", params.BrandingName)
		// New fields for comprehensive approval info
		assert.IsType(t, "", params.ApprovedAt)
		assert.IsType(t, "", params.ActivationTime)
		assert.IsType(t, "", params.ExpirationTime)
		assert.IsType(t, false, params.IsScheduled)
		assert.IsType(t, "", params.SessionID)
		assert.IsType(t, "", params.Cluster)
		assert.IsType(t, "", params.Username)
		assert.IsType(t, "", params.ApprovalReason)
		// IDP information fields
		assert.IsType(t, "", params.IDPName)
		assert.IsType(t, "", params.IDPIssuer)
	})

	t.Run("RequestBreakglassSessionMailParams", func(t *testing.T) {
		params := RequestBreakglassSessionMailParams{}
		assert.IsType(t, "", params.SubjectEmail)
		assert.IsType(t, "", params.SubjectFullName)
		assert.IsType(t, "", params.RequestedCluster)
		assert.IsType(t, "", params.RequestedUsername)
		assert.IsType(t, "", params.RequestedGroup)
		assert.IsType(t, "", params.URL)
		assert.IsType(t, "", params.BrandingName)
	})
}

func TestRenderWithEmptyParams(t *testing.T) {
	t.Run("RenderRequest with empty params", func(t *testing.T) {
		params := RequestMailParams{}
		result, err := RenderRequest(params)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("RenderApproved with empty params", func(t *testing.T) {
		params := ApprovedMailParams{}
		result, err := RenderApproved(params)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("RenderBreakglassSessionRequest with empty params", func(t *testing.T) {
		params := RequestBreakglassSessionMailParams{}
		result, err := RenderBreakglassSessionRequest(params)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("RenderBreakglassSessionNotification with empty params", func(t *testing.T) {
		params := RequestBreakglassSessionMailParams{}
		result, err := RenderBreakglassSessionNotification(params)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})
}

// TestApprovedEmailAuditAndCompliance tests that audit and compliance messaging is present
func TestApprovedEmailAuditAndCompliance(t *testing.T) {
	params := ApprovedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		ApproverFullName: "Jane Smith",
		ApproverEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
		ApprovedAt:       "2025-11-18 10:30:00",
		ActivationTime:   "2025-11-18 10:30:00",
		ExpirationTime:   "2025-11-18 12:30:00",
		IsScheduled:      false,
		SessionID:        "test-session-123",
		Cluster:          "prod-cluster-01",
		Username:         "john.doe",
	}

	result, err := RenderApproved(params)

	assert.NoError(t, err)
	// Check for audit and compliance notices
	assert.Contains(t, result, "Audit & Compliance Notice", "Should include audit notice section")
	assert.Contains(t, result, "All your actions are being recorded", "Should mention recording of actions")
	assert.Contains(t, result, "Security team", "Should mention security team review")
	assert.Contains(t, result, "Compliance team", "Should mention compliance team review")
}

// TestApprovedEmailDisclaimers tests that all required disclaimers are present
func TestApprovedEmailDisclaimers(t *testing.T) {
	params := ApprovedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		ApproverFullName: "Jane Smith",
		ApproverEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
		ApprovedAt:       "2025-11-18 10:30:00",
		ActivationTime:   "2025-11-18 10:30:00",
		ExpirationTime:   "2025-11-18 12:30:00",
		IsScheduled:      false,
		SessionID:        "test-session-123",
		Cluster:          "prod-cluster-01",
		Username:         "john.doe",
	}

	result, err := RenderApproved(params)

	assert.NoError(t, err)
	// Check for all key disclaimer items
	assert.Contains(t, result, "permanent and auditable", "Should state actions are permanent and auditable")
	assert.Contains(t, result, "personally responsible", "Should state personal responsibility")
	assert.Contains(t, result, "Misuse of escalated privileges", "Should warn about misuse")
	assert.Contains(t, result, "automatically expire", "Should mention auto-expiration")
	assert.Contains(t, result, "Never share your session", "Should warn against sharing")
	assert.Contains(t, result, "emergency use only", "Should state this is for emergency use only")
}

// TestApprovedEmailSessionTracking tests that session tracking information is included
func TestApprovedEmailSessionTracking(t *testing.T) {
	params := ApprovedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		ApproverFullName: "Jane Smith",
		ApproverEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
		ApprovedAt:       "2025-11-18 10:30:00",
		ActivationTime:   "2025-11-18 10:30:00",
		ExpirationTime:   "2025-11-18 12:30:00",
		IsScheduled:      false,
		SessionID:        "session-abc123def456",
		Cluster:          "prod-cluster-01",
		Username:         "john.doe",
		ApprovalReason:   "Database recovery",
	}

	result, err := RenderApproved(params)

	assert.NoError(t, err)
	// Check that all tracking info is present
	assert.Contains(t, result, params.SessionID, "Should include session ID for reference")
	assert.Contains(t, result, params.Cluster, "Should include cluster name")
	assert.Contains(t, result, params.Username, "Should include username")
	assert.Contains(t, result, params.ApprovalReason, "Should include approver notes/reason")
	assert.Contains(t, result, params.ApprovedAt, "Should include approval timestamp")
}

// TestApprovedEmailApproverInfo tests that approver information is clearly displayed
func TestApprovedEmailApproverInfo(t *testing.T) {
	params := ApprovedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		ApproverFullName: "Jane Smith",
		ApproverEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
		ApprovedAt:       "2025-11-18 10:30:00",
		ActivationTime:   "2025-11-18 10:30:00",
		ExpirationTime:   "2025-11-18 12:30:00",
		IsScheduled:      false,
		SessionID:        "test-session-123",
		Cluster:          "prod-cluster-01",
		Username:         "john.doe",
	}

	result, err := RenderApproved(params)

	assert.NoError(t, err)
	// Check that approver information is present
	assert.Contains(t, result, params.ApproverFullName, "Should include approver name")
	assert.Contains(t, result, params.ApproverEmail, "Should include approver email")
	assert.Contains(t, result, "Approved By", "Should have 'Approved By' label")
}

// TestApprovedEmailSchedulingHandling tests scheduling information handling
func TestApprovedEmailSchedulingHandling(t *testing.T) {
	testCases := []struct {
		name         string
		isScheduled  bool
		expectedText string
	}{
		{
			name:         "Immediate activation",
			isScheduled:  false,
			expectedText: "granted immediately",
		},
		{
			name:         "Scheduled activation",
			isScheduled:  true,
			expectedText: "will become active",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := ApprovedMailParams{
				SubjectFullName:  "John Doe",
				SubjectEmail:     "john.doe@example.com",
				RequestedRole:    "admin",
				ApproverFullName: "Jane Smith",
				ApproverEmail:    "jane.smith@example.com",
				BrandingName:     "Das SCHIFF Breakglass",
				ApprovedAt:       "2025-11-18 10:30:00",
				ActivationTime:   "2025-11-18 10:30:00",
				ExpirationTime:   "2025-11-18 12:30:00",
				IsScheduled:      tc.isScheduled,
				SessionID:        "test-session",
				Cluster:          "prod-cluster",
				Username:         "john.doe",
			}

			result, err := RenderApproved(params)
			assert.NoError(t, err)
			assert.Contains(t, result, tc.expectedText)
		})
	}
}

// TestApprovedEmailWithIDPInfo tests IDP information is displayed
func TestApprovedEmailWithIDPInfo(t *testing.T) {
	params := ApprovedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		ApproverFullName: "Jane Smith",
		ApproverEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
		ApprovedAt:       "2025-11-18 10:30:00",
		ActivationTime:   "2025-11-18 10:30:00",
		ExpirationTime:   "2025-11-18 12:30:00",
		IsScheduled:      false,
		SessionID:        "test-session",
		Cluster:          "prod-cluster",
		Username:         "john.doe",
		IDPName:          "keycloak-prod",
		IDPIssuer:        "https://keycloak.example.com/auth/realms/production",
	}

	result, err := RenderApproved(params)

	assert.NoError(t, err)
	assert.Contains(t, result, "Identity Provider Information", "Should include IDP section header")
	assert.Contains(t, result, "IDP to Use:", "Should include IDP label")
	assert.Contains(t, result, "keycloak-prod", "Should include IDP name")
	assert.Contains(t, result, "You must use the", "Should include usage instruction")
}

// TestApprovedEmailWithoutIDPInfo tests email renders without IDP when not provided
func TestApprovedEmailWithoutIDPInfo(t *testing.T) {
	params := ApprovedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		ApproverFullName: "Jane Smith",
		ApproverEmail:    "jane.smith@example.com",
		BrandingName:     "Das SCHIFF Breakglass",
		ApprovedAt:       "2025-11-18 10:30:00",
		ActivationTime:   "2025-11-18 10:30:00",
		ExpirationTime:   "2025-11-18 12:30:00",
		IsScheduled:      false,
		SessionID:        "test-session",
		Cluster:          "prod-cluster",
		Username:         "john.doe",
		// IDPName and IDPIssuer left empty
	}

	result, err := RenderApproved(params)

	assert.NoError(t, err)
	// Should not include IDP section when no IDP info is provided
	// (conditional rendering in template)
	assert.NotEmpty(t, result)
}

// TestRenderDebugSessionRequest tests the debug session request email template
func TestRenderDebugSessionRequest(t *testing.T) {
	params := DebugSessionRequestMailParams{
		RequesterName:     "John Doe",
		RequesterEmail:    "john.doe@example.com",
		RequestedAt:       "2025-11-18 10:00:00",
		SessionID:         "debug-session-123",
		Cluster:           "prod-cluster-01",
		TemplateName:      "emergency-debug",
		Namespace:         "production",
		RequestedDuration: "2 hours",
		Reason:            "Investigate memory leak in production pods",
		BrandingName:      "Das SCHIFF Breakglass",
		URL:               "https://example.com/approve/debug-session-123",
	}

	result, err := RenderDebugSessionRequest(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.RequesterName)
	assert.Contains(t, result, params.RequesterEmail)
	assert.Contains(t, result, params.SessionID)
	assert.Contains(t, result, params.Cluster)
	assert.Contains(t, result, params.TemplateName)
	assert.Contains(t, result, params.Namespace)
	assert.Contains(t, result, params.Reason)
	assert.Contains(t, result, params.URL)
	assert.Contains(t, result, "Debug Session")
	assert.Contains(t, result, "Action Required")
}

// TestRenderDebugSessionApproved tests the debug session approval email template
func TestRenderDebugSessionApproved(t *testing.T) {
	params := DebugSessionApprovedMailParams{
		RequesterName:  "John Doe",
		RequesterEmail: "john.doe@example.com",
		SessionID:      "debug-session-123",
		Cluster:        "prod-cluster-01",
		TemplateName:   "emergency-debug",
		Namespace:      "production",
		ApproverName:   "Jane Smith",
		ApproverEmail:  "jane.smith@example.com",
		ApprovedAt:     "2025-11-18 10:30:00",
		Duration:       "2 hours",
		ExpiresAt:      "2025-11-18 12:30:00",
		BrandingName:   "Das SCHIFF Breakglass",
	}

	result, err := RenderDebugSessionApproved(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.RequesterName)
	assert.Contains(t, result, params.SessionID)
	assert.Contains(t, result, params.Cluster)
	assert.Contains(t, result, params.TemplateName)
	assert.Contains(t, result, params.Namespace)
	assert.Contains(t, result, params.ApproverName)
	assert.Contains(t, result, params.ApproverEmail)
	assert.Contains(t, result, params.ApprovedAt)
	assert.Contains(t, result, params.ExpiresAt)
	assert.Contains(t, result, "APPROVED")
	assert.Contains(t, result, "audited")
}

// TestRenderDebugSessionRejected tests the debug session rejection email template
func TestRenderDebugSessionRejected(t *testing.T) {
	params := DebugSessionRejectedMailParams{
		RequesterName:   "John Doe",
		RequesterEmail:  "john.doe@example.com",
		SessionID:       "debug-session-123",
		Cluster:         "prod-cluster-01",
		TemplateName:    "emergency-debug",
		Namespace:       "production",
		RejectorName:    "Jane Smith",
		RejectorEmail:   "jane.smith@example.com",
		RejectedAt:      "2025-11-18 10:30:00",
		RejectionReason: "Insufficient justification for debug access",
		BrandingName:    "Das SCHIFF Breakglass",
	}

	result, err := RenderDebugSessionRejected(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.RequesterName)
	assert.Contains(t, result, params.SessionID)
	assert.Contains(t, result, params.Cluster)
	assert.Contains(t, result, params.TemplateName)
	assert.Contains(t, result, params.Namespace)
	assert.Contains(t, result, params.RejectorName)
	assert.Contains(t, result, params.RejectorEmail)
	assert.Contains(t, result, params.RejectedAt)
	assert.Contains(t, result, params.RejectionReason)
	assert.Contains(t, result, "REJECTED")
	assert.Contains(t, result, "What Can You Do?")
}

// TestRenderDebugSessionRejectedWithoutReason tests rejection email without reason
func TestRenderDebugSessionRejectedWithoutReason(t *testing.T) {
	params := DebugSessionRejectedMailParams{
		RequesterName:   "John Doe",
		RequesterEmail:  "john.doe@example.com",
		SessionID:       "debug-session-456",
		Cluster:         "prod-cluster-01",
		TemplateName:    "emergency-debug",
		Namespace:       "production",
		RejectorName:    "Jane Smith",
		RejectorEmail:   "jane.smith@example.com",
		RejectedAt:      "2025-11-18 10:30:00",
		RejectionReason: "", // No reason provided
		BrandingName:    "Das SCHIFF Breakglass",
	}

	result, err := RenderDebugSessionRejected(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.RequesterName)
	assert.Contains(t, result, "REJECTED")
	// Should not crash or error with empty reason
}

// TestRenderSessionExpired tests the session expiration email template
func TestRenderSessionExpired(t *testing.T) {
	params := SessionExpiredMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		Cluster:          "prod-cluster-01",
		Username:         "john.doe",
		SessionID:        "session-123",
		StartedAt:        "2025-11-18 10:30:00 UTC",
		ExpiredAt:        "2025-11-18 12:30:00 UTC",
		ExpirationReason: "Session validity period has ended",
		BrandingName:     "Das SCHIFF Breakglass",
	}

	result, err := RenderSessionExpired(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.SubjectFullName)
	assert.Contains(t, result, params.RequestedRole)
	assert.Contains(t, result, params.Cluster)
	assert.Contains(t, result, params.SessionID)
	assert.Contains(t, result, params.StartedAt)
	assert.Contains(t, result, params.ExpiredAt)
	assert.Contains(t, result, "EXPIRED")
}

// TestRenderSessionExpiredWithApprovalTimeout tests expiration email for approval timeout
func TestRenderSessionExpiredWithApprovalTimeout(t *testing.T) {
	params := SessionExpiredMailParams{
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		Cluster:          "prod-cluster-01",
		SessionID:        "session-timeout-123",
		StartedAt:        "",
		ExpiredAt:        "2025-11-18 10:30:00 UTC",
		ExpirationReason: "Session approval timed out before being approved",
		BrandingName:     "Das SCHIFF Breakglass",
	}

	result, err := RenderSessionExpired(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.ExpirationReason)
}

// TestRenderSessionActivated tests the session activated email template
func TestRenderSessionActivated(t *testing.T) {
	params := SessionActivatedMailParams{
		SubjectFullName:  "John Doe",
		SubjectEmail:     "john.doe@example.com",
		RequestedRole:    "admin",
		Cluster:          "prod-cluster-01",
		Username:         "john.doe",
		SessionID:        "session-123",
		ActivatedAt:      "2025-11-18 10:30:00 UTC",
		ExpirationTime:   "2025-11-18 12:30:00 UTC",
		ApproverFullName: "Jane Smith",
		ApproverEmail:    "jane.smith@example.com",
		IDPName:          "corporate-idp",
		IDPIssuer:        "https://idp.example.com",
		BrandingName:     "Das SCHIFF Breakglass",
	}

	result, err := RenderSessionActivated(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.SubjectFullName)
	assert.Contains(t, result, params.RequestedRole)
	assert.Contains(t, result, params.Cluster)
	assert.Contains(t, result, params.SessionID)
	assert.Contains(t, result, params.ActivatedAt)
	assert.Contains(t, result, params.ExpirationTime)
	assert.Contains(t, result, "ACTIVE NOW") // The badge says "ACTIVE NOW" not "ACTIVATED"
}

// TestRenderSessionActivatedWithIDP tests activation email with IDP info
func TestRenderSessionActivatedWithIDP(t *testing.T) {
	params := SessionActivatedMailParams{
		SubjectEmail:   "john.doe@example.com",
		RequestedRole:  "admin",
		Cluster:        "prod-cluster-01",
		SessionID:      "session-idp-123",
		ActivatedAt:    "2025-11-18 10:30:00 UTC",
		ExpirationTime: "2025-11-18 12:30:00 UTC",
		IDPName:        "enterprise-sso",
		IDPIssuer:      "https://sso.enterprise.com",
		BrandingName:   "Das SCHIFF Breakglass",
	}

	result, err := RenderSessionActivated(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.IDPName)
}

// TestRenderDebugSessionExpired tests the debug session expiration email template
func TestRenderDebugSessionExpired(t *testing.T) {
	params := DebugSessionExpiredMailParams{
		RequesterName:  "John Doe",
		RequesterEmail: "john.doe@example.com",
		SessionID:      "debug-session-123",
		Cluster:        "prod-cluster-01",
		TemplateName:   "emergency-debug",
		Namespace:      "production",
		StartedAt:      "2025-11-18 10:00:00 UTC",
		ExpiredAt:      "2025-11-18 12:00:00 UTC",
		Duration:       "2h0m0s",
		BrandingName:   "Das SCHIFF Breakglass",
	}

	result, err := RenderDebugSessionExpired(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, params.RequesterName)
	assert.Contains(t, result, params.SessionID)
	assert.Contains(t, result, params.Cluster)
	assert.Contains(t, result, params.TemplateName)
	assert.Contains(t, result, params.Namespace)
	assert.Contains(t, result, params.StartedAt)
	assert.Contains(t, result, params.ExpiredAt)
	assert.Contains(t, result, "EXPIRED")
	assert.Contains(t, result, "Debug")
}

// TestRenderDebugSessionExpiredWithoutDuration tests expiration email without duration
func TestRenderDebugSessionExpiredWithoutDuration(t *testing.T) {
	params := DebugSessionExpiredMailParams{
		RequesterEmail: "john.doe@example.com",
		SessionID:      "debug-session-456",
		Cluster:        "prod-cluster-01",
		TemplateName:   "emergency-debug",
		Namespace:      "production",
		ExpiredAt:      "2025-11-18 12:00:00 UTC",
		Duration:       "", // Duration not available
		BrandingName:   "Das SCHIFF Breakglass",
	}

	result, err := RenderDebugSessionExpired(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	// Should not crash or error with empty duration
}

// TestRenderDebugSessionCreated tests the debug session created email template
func TestRenderDebugSessionCreated(t *testing.T) {
	params := DebugSessionCreatedMailParams{
		RequesterName:     "John Doe",
		RequesterEmail:    "john.doe@example.com",
		SessionID:         "debug-session-789",
		Cluster:           "prod-cluster-01",
		TemplateName:      "standard-debug",
		Namespace:         "production",
		RequestedDuration: "2h",
		Reason:            "Investigating production issue #1234",
		RequestedAt:       "2025-01-15 10:30:00 UTC",
		RequiresApproval:  true,
		URL:               "https://breakglass.example.com/sessions/debug-session-789",
		BrandingName:      "Das SCHIFF Breakglass",
	}

	result, err := RenderDebugSessionCreated(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "debug-session-789")
	assert.Contains(t, result, "prod-cluster-01")
	assert.Contains(t, result, "production")
	assert.Contains(t, result, "standard-debug")
}

// TestRenderDebugSessionCreatedNoApproval tests template without approval requirement
func TestRenderDebugSessionCreatedNoApproval(t *testing.T) {
	params := DebugSessionCreatedMailParams{
		RequesterName:     "Jane Smith",
		RequesterEmail:    "jane.smith@example.com",
		SessionID:         "debug-session-abc",
		Cluster:           "dev-cluster",
		TemplateName:      "quick-debug",
		Namespace:         "development",
		RequestedDuration: "30m",
		Reason:            "Quick debugging session",
		RequestedAt:       "2025-01-15 11:00:00 UTC",
		RequiresApproval:  false,
		URL:               "https://breakglass.example.com/sessions/debug-session-abc",
		BrandingName:      "Breakglass",
	}

	result, err := RenderDebugSessionCreated(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "debug-session-abc")
}

// TestRenderDebugSessionFailed tests the debug session failed email template
func TestRenderDebugSessionFailed(t *testing.T) {
	params := DebugSessionFailedMailParams{
		RequesterName:  "John Doe",
		RequesterEmail: "john.doe@example.com",
		SessionID:      "debug-session-fail",
		Cluster:        "prod-cluster-01",
		TemplateName:   "emergency-debug",
		Namespace:      "production",
		FailedAt:       "2025-01-15 12:30:00 UTC",
		FailureReason:  "Pod creation failed: quota exceeded",
		URL:            "https://breakglass.example.com/sessions/debug-session-fail",
		BrandingName:   "Das SCHIFF Breakglass",
	}

	result, err := RenderDebugSessionFailed(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "debug-session-fail")
	assert.Contains(t, result, "quota exceeded")
	assert.Contains(t, result, "prod-cluster-01")
}

// TestRenderDebugSessionFailedMinimalParams tests with minimal parameters
func TestRenderDebugSessionFailedMinimalParams(t *testing.T) {
	params := DebugSessionFailedMailParams{
		RequesterEmail: "user@example.com",
		SessionID:      "session-min",
		Cluster:        "cluster",
		FailedAt:       "2025-01-15",
		FailureReason:  "Unknown error",
	}

	result, err := RenderDebugSessionFailed(params)

	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "session-min")
}
