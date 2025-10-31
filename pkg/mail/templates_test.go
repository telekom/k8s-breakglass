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
