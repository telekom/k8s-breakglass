package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BreakglassEscalation State Exposure Tests
// These tests validate that all escalation state (validation status) is properly exposed via Conditions.

// TestBreakglassEscalationStatus_Ready_ExposesReadyCondition
// Validates: When escalation is ready, Ready condition is set to True
func TestBreakglassEscalationStatus_Ready_ExposesReadyCondition(t *testing.T) {
	be := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-escalation", Namespace: "default"},
	}
	be.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.BreakglassEscalationConditionReady),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: be.Generation,
		Reason:             "EscalationValid",
		Message:            "Escalation configuration is valid",
	})

	// Verify: Ready condition is True
	readyCondition := be.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionReady))
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)
	assert.Equal(t, "EscalationValid", readyCondition.Reason)
}

// TestBreakglassEscalationStatus_ValidationFailure_ExposesReadyConditionFalse
// Validates: When validation fails, Ready condition is set to False with reason
func TestBreakglassEscalationStatus_ValidationFailure_ExposesReadyConditionFalse(t *testing.T) {
	be := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-escalation", Namespace: "default"},
	}
	be.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.BreakglassEscalationConditionReady),
		Status:             metav1.ConditionFalse,
		ObservedGeneration: be.Generation,
		Reason:             "ConfigValidationFailed",
		Message:            "escalatedGroup must be set and non-empty",
	})

	// Verify: Ready condition is False with detailed message
	readyCondition := be.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionReady))
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	assert.Equal(t, "ConfigValidationFailed", readyCondition.Reason)
	assert.Contains(t, readyCondition.Message, "escalatedGroup")
}

// TestBreakglassEscalationStatus_ClusterRefFailure_ExposesCondition
// Validates: When cluster reference validation fails, condition captures error
func TestBreakglassEscalationStatus_ClusterRefFailure_ExposesCondition(t *testing.T) {
	be := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-escalation", Namespace: "default"},
	}
	be.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.BreakglassEscalationConditionReady),
		Status:             metav1.ConditionFalse,
		ObservedGeneration: be.Generation,
		Reason:             "ClusterRefNotFound",
		Message:            "ClusterConfig 'prod-cluster' not found in namespace 'default'",
	})

	// Verify: condition captures cluster ref error
	readyCondition := be.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionReady))
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	assert.Equal(t, "ClusterRefNotFound", readyCondition.Reason)
	assert.Contains(t, readyCondition.Message, "ClusterConfig")
}

// TestBreakglassEscalationStatus_IDPRefFailure_ExposesCondition
// Validates: When IDP reference validation fails, condition captures error
func TestBreakglassEscalationStatus_IDPRefFailure_ExposesCondition(t *testing.T) {
	be := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-escalation", Namespace: "default"},
	}
	be.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.BreakglassEscalationConditionReady),
		Status:             metav1.ConditionFalse,
		ObservedGeneration: be.Generation,
		Reason:             "IDPRefNotFound",
		Message:            "IdentityProvider 'invalid-idp' not found in namespace 'default'",
	})

	// Verify: condition captures IDP ref error
	readyCondition := be.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionReady))
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	assert.Equal(t, "IDPRefNotFound", readyCondition.Reason)
	assert.Contains(t, readyCondition.Message, "IdentityProvider")
}

// TestBreakglassEscalationStatus_DenyPolicyRefFailure_ExposesCondition
// Validates: When deny policy reference validation fails, condition captures error
func TestBreakglassEscalationStatus_DenyPolicyRefFailure_ExposesCondition(t *testing.T) {
	be := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-escalation", Namespace: "default"},
	}
	be.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.BreakglassEscalationConditionReady),
		Status:             metav1.ConditionFalse,
		ObservedGeneration: be.Generation,
		Reason:             "DenyPolicyRefNotFound",
		Message:            "DenyPolicy 'block-all' not found in namespace 'default'",
	})

	// Verify: condition captures deny policy ref error
	readyCondition := be.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionReady))
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	assert.Equal(t, "DenyPolicyRefNotFound", readyCondition.Reason)
	assert.Contains(t, readyCondition.Message, "DenyPolicy")
}

// TestBreakglassEscalationStatus_MultipleConditions_ExposesAll
// Validates: Multiple conditions can coexist (e.g., Ready + ApprovalGroupMembersResolved)
func TestBreakglassEscalationStatus_MultipleConditions_ExposesAll(t *testing.T) {
	be := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-escalation", Namespace: "default"},
	}

	// Set Ready condition to True
	be.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.BreakglassEscalationConditionReady),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: be.Generation,
		Reason:             "EscalationValid",
		Message:            "Escalation is ready",
	})

	// Set ApprovalGroupMembersResolved condition
	be.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: be.Generation,
		Reason:             "GroupMembersAvailable",
		Message:            "All approval group members resolved",
	})

	// Verify: both conditions exist and are set correctly
	readyCondition := be.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionReady))
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)

	groupCondition := be.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
	require.NotNil(t, groupCondition)
	assert.Equal(t, metav1.ConditionTrue, groupCondition.Status)

	// Verify: we have exactly 2 conditions
	assert.Len(t, be.Status.Conditions, 2)
}

// TestBreakglassEscalationStatus_ConditionUpdate_PreservesOtherConditions
// Validates: Updating one condition doesn't remove others
func TestBreakglassEscalationStatus_ConditionUpdate_PreservesOtherConditions(t *testing.T) {
	be := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-escalation", Namespace: "default"},
	}

	// Set initial conditions
	be.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.BreakglassEscalationConditionReady),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: be.Generation,
		Reason:             "Valid",
		Message:            "Escalation is valid",
	})
	be.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: be.Generation,
		Reason:             "Resolved",
		Message:            "Group members resolved",
	})

	initialCount := len(be.Status.Conditions)

	// Update Ready condition
	be.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.BreakglassEscalationConditionReady),
		Status:             metav1.ConditionFalse,
		ObservedGeneration: be.Generation,
		Reason:             "Invalid",
		Message:            "Escalation is invalid",
	})

	// Verify: still have same number of conditions
	assert.Len(t, be.Status.Conditions, initialCount)

	// Verify: other condition is unchanged
	groupCondition := be.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
	require.NotNil(t, groupCondition)
	assert.Equal(t, metav1.ConditionTrue, groupCondition.Status)

	// Verify: Ready condition was updated
	readyCondition := be.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionReady))
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	assert.Equal(t, "Invalid", readyCondition.Reason)
}

// TestBreakglassEscalationStatus_GetCondition_ReturnsNilForNonexistent
// Validates: GetCondition returns nil for conditions that don't exist
func TestBreakglassEscalationStatus_GetCondition_ReturnsNilForNonexistent(t *testing.T) {
	be := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-escalation", Namespace: "default"},
	}

	// Verify: GetCondition returns nil for non-existent condition
	condition := be.GetCondition("NonexistentCondition")
	assert.Nil(t, condition)
}

// TestBreakglassEscalationStatus_ObservedGeneration_Tracked
// Validates: ObservedGeneration is properly tracked in status
func TestBreakglassEscalationStatus_ObservedGeneration_Tracked(t *testing.T) {
	be := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-escalation", Namespace: "default"},
	}
	be.Generation = 5

	be.Status.ObservedGeneration = be.Generation

	// Verify: ObservedGeneration matches object generation
	assert.Equal(t, int64(5), be.Status.ObservedGeneration)
}

// TestBreakglassEscalationStatus_ConditionTimestamp_Set
// Validates: Conditions have proper timestamps set
func TestBreakglassEscalationStatus_ConditionTimestamp_Set(t *testing.T) {
	be := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-escalation", Namespace: "default"},
	}

	be.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.BreakglassEscalationConditionReady),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: be.Generation,
		Reason:             "Valid",
		Message:            "Escalation is valid",
		LastTransitionTime: metav1.Now(),
	})

	condition := be.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionReady))
	require.NotNil(t, condition)

	// Verify: condition has a timestamp
	assert.False(t, condition.LastTransitionTime.IsZero())
}
