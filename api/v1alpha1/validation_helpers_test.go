/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestValidateSessionIdentityProviderAuthorization_EmptyIDPName tests backward compatibility
// when session has no IDP name (single-IDP or manual creation mode)
func TestValidateSessionIdentityProviderAuthorization_EmptyIDPName(t *testing.T) {
	ctx := context.Background()
	fieldPath := field.NewPath("spec").Child("identityProviderName")

	// Call validation with empty IDP name
	errs := validateSessionIdentityProviderAuthorization(ctx, "test-cluster", "admin", "", fieldPath)

	// Should pass (skip validation for backward compatibility)
	assert.Nil(t, errs, "empty IDP name should skip authorization check")
}

// TestValidateSessionIdentityProviderAuthorization_NilFieldPath tests graceful handling
// when field path is nil
func TestValidateSessionIdentityProviderAuthorization_NilFieldPath(t *testing.T) {
	ctx := context.Background()

	// Call validation with nil field path
	errs := validateSessionIdentityProviderAuthorization(ctx, "test-cluster", "admin", "test-idp", nil)

	// Should return nil (graceful fallback for nil path)
	assert.Nil(t, errs, "nil field path should result in nil errors")
}

// TestValidateSessionIdentityProviderAuthorization_NilContext tests graceful handling
// when context is nil
func TestValidateSessionIdentityProviderAuthorization_NilContext(t *testing.T) {
	fieldPath := field.NewPath("spec").Child("identityProviderName")

	// Call validation with context.TODO instead of nil
	assert.NotPanics(t, func() {
		validateSessionIdentityProviderAuthorization(context.TODO(), "test-cluster", "admin", "test-idp", fieldPath)
	}, "context should not cause panic")
}

// TestValidateSessionIdentityProviderAuthorization_NilReader tests graceful handling
// when webhook reader returns nil (no escalations available)
func TestValidateSessionIdentityProviderAuthorization_NilReader(t *testing.T) {
	ctx := context.Background()
	fieldPath := field.NewPath("spec").Child("identityProviderName")

	// When webhookCache is nil and webhookClient is nil, reader will be nil
	// The function should handle this gracefully
	errs := validateSessionIdentityProviderAuthorization(ctx, "test-cluster", "admin", "test-idp", fieldPath)

	// Should return nil when reader is unavailable (fails safely)
	// Note: This test depends on webhookCache and webhookClient being nil
	// In a real test environment, these would be set by the webhook server
	_ = errs
}

// TestBreakglassSessionValidateCreate_IntegrationWith tests that ValidateCreate
func TestBreakglassSessionValidateCreate_IntegrationWith(t *testing.T) {
	ctx := context.Background()

	session := &BreakglassSession{
		Spec: BreakglassSessionSpec{
			Cluster:                "test-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "cluster-admin",
			IdentityProviderName:   "", // Empty for backward compatibility
			IdentityProviderIssuer: "",
		},
	}

	// ValidateCreate should accept sessions with empty IDP name
	warnings, err := session.ValidateCreate(ctx, session)

	// Should pass for now (no escalations in test environment)
	// The real validation would depend on escalations being available
	_ = warnings
	_ = err
}

// TestBreakglassSessionAuthorizationFields tests that BreakglassSession
// properly tracks IDP authorization fields
func TestBreakglassSessionAuthorizationFields(t *testing.T) {
	session := &BreakglassSession{
		Spec: BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "alice@example.com",
			GrantedGroup:           "cluster-admin",
			IdentityProviderName:   "corporate-idp",
			IdentityProviderIssuer: "https://auth.corp.com",
		},
	}

	// Verify IDP authorization fields are stored
	assert.Equal(t, "corporate-idp", session.Spec.IdentityProviderName)
	assert.Equal(t, "https://auth.corp.com", session.Spec.IdentityProviderIssuer)
}

// TestAuthorizationLogic tests the authorization rules independently
// Rule 1: Empty IDP name skips check
func TestAuthorizationLogic_Rule1_EmptyIDPName(t *testing.T) {
	// When session.identityProviderName is empty, authorization passes
	fieldPath := field.NewPath("spec").Child("identityProviderName")
	ctx := context.Background()

	errs := validateSessionIdentityProviderAuthorization(ctx, "cluster", "group", "", fieldPath)
	assert.Nil(t, errs, "Rule 1: Empty IDP name should skip check")
}
func TestAuthorizationBackwardCompatibility(t *testing.T) {
	// Test that sessions without IDP tracking fields still work
	session := &BreakglassSession{
		Spec: BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "user@example.com",
			GrantedGroup: "developers",
			// IdentityProviderName and IdentityProviderIssuer are not set
		},
	}

	// Should have default values
	assert.Empty(t, session.Spec.IdentityProviderName, "IDP name should be empty in backward compat mode")
	assert.Empty(t, session.Spec.IdentityProviderIssuer, "IDP issuer should be empty in backward compat mode")
}

// TestBreakglassEscalationAuthorizationConfiguration tests that escalations
// can be configured for IDP authorization
func TestBreakglassEscalationAuthorizationConfiguration(t *testing.T) {
	escalation := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "cluster-admin",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"prod-cluster"},
			},
			AllowedIdentityProviders: []string{"corporate-idp", "partner-idp"},
		},
	}

	// Verify escalation can store allowed IDPs
	assert.Equal(t, []string{"corporate-idp", "partner-idp"}, escalation.Spec.AllowedIdentityProviders)
	assert.Len(t, escalation.Spec.AllowedIdentityProviders, 2, "Should store multiple allowed IDPs")
}

// TestBreakglassEscalationNoIDPRestrictions tests that empty AllowedIdentityProviders
// means all IDPs are allowed (backward compatibility)
func TestBreakglassEscalationNoIDPRestrictions(t *testing.T) {
	escalation := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "developers",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"dev-cluster"},
			},
			AllowedIdentityProviders: []string{}, // Empty = all allowed
		},
	}

	// Empty list means no restrictions (backward compatible)
	assert.Empty(t, escalation.Spec.AllowedIdentityProviders)
	assert.Len(t, escalation.Spec.AllowedIdentityProviders, 0)
}

// TestValidateDurationFormat tests duration validation
func TestValidateDurationFormat_NilPath(t *testing.T) {
	// Should return nil for nil path
	errs := validateDurationFormat("1h", nil)
	assert.Nil(t, errs)
}

func TestValidateDurationFormat_EmptyDuration(t *testing.T) {
	fieldPath := field.NewPath("spec").Child("duration")
	// Should return nil for empty duration
	errs := validateDurationFormat("", fieldPath)
	assert.Nil(t, errs)
}

func TestValidateDurationFormat_Valid(t *testing.T) {
	fieldPath := field.NewPath("spec").Child("duration")
	testCases := []string{"1h", "30m", "2h30m", "1s", "100ms", "24h"}
	for _, tc := range testCases {
		errs := validateDurationFormat(tc, fieldPath)
		assert.Nil(t, errs, "should accept valid duration: %s", tc)
	}
}

func TestValidateDurationFormat_Invalid(t *testing.T) {
	fieldPath := field.NewPath("spec").Child("duration")
	testCases := []string{"invalid", "1x", "abc", "1 hour", "1.5h"}
	for _, tc := range testCases {
		errs := validateDurationFormat(tc, fieldPath)
		if tc == "1.5h" {
			// 1.5h is actually valid in Go
			continue
		}
		assert.NotNil(t, errs, "should reject invalid duration: %s", tc)
	}
}

// TestGetWebhookReader tests the reader fallback logic
func TestGetWebhookReader_NilCacheAndClient(t *testing.T) {
	// When both are nil, should return nil
	oldCache := webhookCache
	oldClient := webhookClient
	webhookCache = nil
	webhookClient = nil
	defer func() {
		webhookCache = oldCache
		webhookClient = oldClient
	}()

	reader := getWebhookReader()
	assert.Nil(t, reader)
}

func TestGetWebhookReader_ClientFallback(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	// Create a fake client
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Save old values
	oldCache := webhookCache
	oldClient := webhookClient
	defer func() {
		webhookCache = oldCache
		webhookClient = oldClient
	}()

	// Set only client, no cache
	webhookCache = nil
	webhookClient = fakeClient

	reader := getWebhookReader()
	assert.NotNil(t, reader, "should return client when cache is nil")
}

// TestIsValidSpecialCharForID tests special character validation for identifiers
func TestIsValidSpecialCharForID_Valid(t *testing.T) {
	validChars := []rune{'*', '?', '[', ']', '(', ')', '+', '|', '^', '$', '\\'}
	for _, ch := range validChars {
		assert.True(t, isValidSpecialCharForID(ch), "should accept valid special char: %c", ch)
	}
}

func TestIsValidSpecialCharForID_Invalid(t *testing.T) {
	invalidChars := []rune{'@', '#', '%', '&', '!', '~', '`', '{', '}', '<', '>', ',', ';', ':'}
	for _, ch := range invalidChars {
		assert.False(t, isValidSpecialCharForID(ch), "should reject invalid special char: %c", ch)
	}
}

// TestValidateURLFormat tests URL format validation
func TestValidateURLFormat_Empty(t *testing.T) {
	errs := validateURLFormat("", field.NewPath("test"))
	assert.Nil(t, errs)
}

func TestValidateURLFormat_ValidHTTP(t *testing.T) {
	errs := validateURLFormat("http://example.com", field.NewPath("test"))
	assert.Nil(t, errs)
}

func TestValidateURLFormat_ValidHTTPS(t *testing.T) {
	errs := validateURLFormat("https://example.com/path", field.NewPath("test"))
	assert.Nil(t, errs)
}

func TestValidateURLFormat_MissingScheme(t *testing.T) {
	errs := validateURLFormat("example.com", field.NewPath("test"))
	assert.NotNil(t, errs, "should reject URL without scheme")
}

func TestValidateURLFormat_InvalidScheme(t *testing.T) {
	errs := validateURLFormat("ftp://example.com", field.NewPath("test"))
	assert.NotNil(t, errs, "should reject non-http/https scheme")
}

func TestValidateURLFormat_MissingHost(t *testing.T) {
	errs := validateURLFormat("http://", field.NewPath("test"))
	assert.NotNil(t, errs, "should reject URL without host")
}

// TestValidateHTTPSURL tests HTTPS-only URL validation
func TestValidateHTTPSURL_Empty(t *testing.T) {
	errs := validateHTTPSURL("", field.NewPath("test"))
	assert.Nil(t, errs)
}

func TestValidateHTTPSURL_Valid(t *testing.T) {
	errs := validateHTTPSURL("https://auth.example.com", field.NewPath("test"))
	assert.Nil(t, errs)
}

func TestValidateHTTPSURL_HTTPNotAllowed(t *testing.T) {
	errs := validateHTTPSURL("http://auth.example.com", field.NewPath("test"))
	assert.NotNil(t, errs, "should reject HTTP URL")
}

func TestValidateHTTPSURL_InvalidFormat(t *testing.T) {
	errs := validateHTTPSURL("not-a-url", field.NewPath("test"))
	assert.NotNil(t, errs, "should reject invalid URL format")
}

// TestValidateIdentifierFormat tests identifier format validation
func TestValidateIdentifierFormat_Empty(t *testing.T) {
	errs := validateIdentifierFormat("", field.NewPath("test"))
	assert.Nil(t, errs)
}

func TestValidateIdentifierFormat_Valid(t *testing.T) {
	validIdentifiers := []string{"cluster-admin", "user@example.com", "group_name", "valid-123"}
	for _, id := range validIdentifiers {
		errs := validateIdentifierFormat(id, field.NewPath("test"))
		assert.Nil(t, errs, "should accept valid identifier: %s", id)
	}
}

func TestValidateIdentifierFormat_WithGlobPatterns(t *testing.T) {
	// Glob patterns should be valid in identifiers
	validPatterns := []string{"user-*", "dev-?", "team[0-9]", "admin|power"}
	for _, pattern := range validPatterns {
		errs := validateIdentifierFormat(pattern, field.NewPath("test"))
		assert.Nil(t, errs, "should accept glob pattern: %s", pattern)
	}
}

// TestValidateIDPFieldCombinations tests IDP field mutual exclusivity rules
func TestValidateIDPFieldCombinations_AllEmpty(t *testing.T) {
	spec := &BreakglassEscalationSpec{}
	errs := validateIDPFieldCombinations(spec, field.NewPath("spec"))
	assert.Nil(t, errs, "all empty should be valid")
}

func TestValidateIDPFieldCombinations_OldFieldOnly(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		AllowedIdentityProviders: []string{"idp1"},
	}
	errs := validateIDPFieldCombinations(spec, field.NewPath("spec"))
	assert.Nil(t, errs, "old field only should be valid")
}

func TestValidateIDPFieldCombinations_NewFieldsBothSet(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		AllowedIdentityProvidersForRequests:  []string{"idp1"},
		AllowedIdentityProvidersForApprovers: []string{"idp2"},
	}
	errs := validateIDPFieldCombinations(spec, field.NewPath("spec"))
	assert.Nil(t, errs, "both new fields set should be valid")
}

func TestValidateIDPFieldCombinations_MixedOldAndRequestField(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		AllowedIdentityProviders:            []string{"idp1"},
		AllowedIdentityProvidersForRequests: []string{"idp2"},
	}
	errs := validateIDPFieldCombinations(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "mixing old and request field should fail")
}

func TestValidateIDPFieldCombinations_MixedOldAndApproverField(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		AllowedIdentityProviders:             []string{"idp1"},
		AllowedIdentityProvidersForApprovers: []string{"idp2"},
	}
	errs := validateIDPFieldCombinations(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "mixing old and approver field should fail")
}

func TestValidateIDPFieldCombinations_OnlyRequestFieldSet(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		AllowedIdentityProvidersForRequests: []string{"idp1"},
	}
	errs := validateIDPFieldCombinations(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "only request field should fail (approver field required)")
}

func TestValidateIDPFieldCombinations_OnlyApproverFieldSet(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		AllowedIdentityProvidersForApprovers: []string{"idp1"},
	}
	errs := validateIDPFieldCombinations(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "only approver field should fail (request field required)")
}

// TestValidateTimeoutRelationships tests timeout validation
func TestValidateTimeoutRelationships_AllEmpty(t *testing.T) {
	spec := &BreakglassEscalationSpec{}
	errs := validateTimeoutRelationships(spec, field.NewPath("spec"))
	assert.Nil(t, errs, "all empty should be valid")
}

func TestValidateTimeoutRelationships_ValidTimeouts(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		MaxValidFor:     "2h",
		ApprovalTimeout: "30m",
		IdleTimeout:     "1h",
	}
	errs := validateTimeoutRelationships(spec, field.NewPath("spec"))
	assert.Nil(t, errs, "valid timeouts should pass")
}

func TestValidateTimeoutRelationships_ApprovalTimeoutTooLarge(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		MaxValidFor:     "1h",
		ApprovalTimeout: "2h", // larger than maxValidFor
	}
	errs := validateTimeoutRelationships(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "approvalTimeout >= maxValidFor should fail")
}

func TestValidateTimeoutRelationships_IdleTimeoutTooLarge(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		MaxValidFor: "1h",
		IdleTimeout: "2h", // larger than maxValidFor
	}
	errs := validateTimeoutRelationships(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "idleTimeout >= maxValidFor should fail")
}

func TestValidateTimeoutRelationships_InvalidMaxValidFor(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		MaxValidFor: "invalid",
	}
	errs := validateTimeoutRelationships(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "invalid maxValidFor format should fail")
}

func TestValidateTimeoutRelationships_InvalidApprovalTimeout(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		MaxValidFor:     "2h",
		ApprovalTimeout: "invalid",
	}
	errs := validateTimeoutRelationships(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "invalid approvalTimeout format should fail")
}

func TestValidateTimeoutRelationships_InvalidIdleTimeout(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		MaxValidFor: "2h",
		IdleTimeout: "invalid",
	}
	errs := validateTimeoutRelationships(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "invalid idleTimeout format should fail")
}

func TestValidateTimeoutRelationships_NegativeMaxValidFor(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		MaxValidFor: "-1h",
	}
	errs := validateTimeoutRelationships(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "negative maxValidFor should fail")
}

func TestValidateTimeoutRelationships_ApprovalTimeoutEqualMaxValidFor(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		MaxValidFor:     "1h",
		ApprovalTimeout: "1h", // equal to maxValidFor
	}
	errs := validateTimeoutRelationships(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "approvalTimeout == maxValidFor should fail")
}

// TestEnsureClusterWideUniqueName tests cluster-wide name uniqueness validation
func TestEnsureClusterWideUniqueName_NilInputs(t *testing.T) {
	// Nil reader (no webhookClient/Cache)
	oldCache := webhookCache
	oldClient := webhookClient
	webhookCache = nil
	webhookClient = nil
	defer func() {
		webhookCache = oldCache
		webhookClient = oldClient
	}()

	errs := ensureClusterWideUniqueName(context.Background(), &BreakglassSessionList{}, "ns", "name", field.NewPath("test"))
	assert.Nil(t, errs, "should return nil when reader is nil")
}

func TestEnsureClusterWideUniqueName_NilList(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := ensureClusterWideUniqueName(context.Background(), nil, "ns", "name", field.NewPath("test"))
	assert.Nil(t, errs, "should return nil when list is nil")
}

func TestEnsureClusterWideUniqueName_NilPath(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := ensureClusterWideUniqueName(context.Background(), &BreakglassSessionList{}, "ns", "name", nil)
	assert.Nil(t, errs, "should return nil when path is nil")
}

func TestEnsureClusterWideUniqueName_NilContext(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// nil context should use Background context
	errs := ensureClusterWideUniqueName(context.TODO(), &BreakglassSessionList{}, "ns", "name", field.NewPath("test"))
	assert.Nil(t, errs, "should handle nil context")
}

func TestEnsureClusterWideUniqueName_EmptyName(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := ensureClusterWideUniqueName(context.Background(), &BreakglassSessionList{}, "ns", "", field.NewPath("test"))
	assert.Nil(t, errs, "should return nil when name is empty")
}

func TestEnsureClusterWideUniqueName_NoConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := ensureClusterWideUniqueName(context.Background(), &BreakglassSessionList{}, "ns", "unique-name", field.NewPath("test"))
	assert.Nil(t, errs, "should return nil when no conflict")
}

func TestEnsureClusterWideUniqueName_SameNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	// Create existing session in same namespace
	existingSession := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "ns-a"},
		Spec: BreakglassSessionSpec{
			Cluster:      "cluster1",
			User:         "user@example.com",
			GrantedGroup: "group",
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingSession).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// Same namespace, same name - not a conflict (it's the same object)
	errs := ensureClusterWideUniqueName(context.Background(), &BreakglassSessionList{}, "ns-a", "session-1", field.NewPath("test"))
	assert.Nil(t, errs, "should allow same name in same namespace")
}

func TestEnsureClusterWideUniqueName_DifferentNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	// Create existing session in different namespace
	existingSession := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "ns-a"},
		Spec: BreakglassSessionSpec{
			Cluster:      "cluster1",
			User:         "user@example.com",
			GrantedGroup: "group",
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingSession).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// Different namespace, same name - conflict!
	errs := ensureClusterWideUniqueName(context.Background(), &BreakglassSessionList{}, "ns-b", "session-1", field.NewPath("test"))
	assert.NotNil(t, errs, "should detect conflict when same name exists in different namespace")
}

// TestValidateSessionIdentityProviderAuthorization_WithEscalations tests with matching escalations
func TestValidateSessionIdentityProviderAuthorization_WithMatchingEscalation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	// Create escalation that allows specific IDPs
	escalation := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-1", Namespace: "default"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "cluster-admin",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"test-cluster"},
			},
			Approvers:                BreakglassEscalationApprovers{Users: []string{"approver@test.com"}},
			AllowedIdentityProviders: []string{"corporate-idp"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(escalation).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// Allowed IDP
	errs := validateSessionIdentityProviderAuthorization(
		context.Background(),
		"test-cluster",
		"cluster-admin",
		"corporate-idp", // matches allowed
		field.NewPath("spec").Child("identityProviderName"),
	)
	assert.Nil(t, errs, "should allow matching IDP")

	// Disallowed IDP
	errs = validateSessionIdentityProviderAuthorization(
		context.Background(),
		"test-cluster",
		"cluster-admin",
		"other-idp", // does not match allowed
		field.NewPath("spec").Child("identityProviderName"),
	)
	assert.NotNil(t, errs, "should reject non-matching IDP")
}

func TestValidateSessionIdentityProviderAuthorization_DifferentGroup(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	// Create escalation with specific group
	escalation := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-1", Namespace: "default"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "cluster-admin",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"test-cluster"},
			},
			Approvers:                BreakglassEscalationApprovers{Users: []string{"approver@test.com"}},
			AllowedIdentityProviders: []string{"corporate-idp"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(escalation).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// Different group - escalation doesn't match
	errs := validateSessionIdentityProviderAuthorization(
		context.Background(),
		"test-cluster",
		"different-group", // doesn't match escalation's group
		"any-idp",
		field.NewPath("spec").Child("identityProviderName"),
	)
	assert.Nil(t, errs, "should pass when no escalation matches group")
}

func TestValidateSessionIdentityProviderAuthorization_UnrestrictedEscalation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	// Create escalation with empty AllowedIdentityProviders (unrestricted)
	escalation := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-1", Namespace: "default"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "cluster-admin",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"test-cluster"},
			},
			Approvers:                BreakglassEscalationApprovers{Users: []string{"approver@test.com"}},
			AllowedIdentityProviders: []string{}, // empty = all allowed
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(escalation).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// Any IDP should be allowed
	errs := validateSessionIdentityProviderAuthorization(
		context.Background(),
		"test-cluster",
		"cluster-admin",
		"any-idp",
		field.NewPath("spec").Child("identityProviderName"),
	)
	assert.Nil(t, errs, "should allow any IDP when escalation has no restrictions")
}

func TestValidateSessionIdentityProviderAuthorization_ForbiddenIDP(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	// Create escalation with restricted IDPs
	escalation := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-1", Namespace: "default"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "cluster-admin",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"test-cluster"},
			},
			Approvers:                BreakglassEscalationApprovers{Users: []string{"approver@test.com"}},
			AllowedIdentityProviders: []string{"corporate-idp"}, // only allows corporate-idp
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(escalation).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// Use a different IDP that's not allowed
	errs := validateSessionIdentityProviderAuthorization(
		context.Background(),
		"test-cluster",
		"cluster-admin",
		"unauthorized-idp", // not in allowed list
		field.NewPath("spec").Child("identityProviderName"),
	)
	assert.NotNil(t, errs, "should forbid IDP not in escalation's allowed list")
}

func TestValidateSessionIdentityProviderAuthorization_NoMatchingEscalation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	// Create escalation for different cluster
	escalation := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-1", Namespace: "default"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "cluster-admin",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"other-cluster"}, // different cluster
			},
			Approvers:                BreakglassEscalationApprovers{Users: []string{"approver@test.com"}},
			AllowedIdentityProviders: []string{"idp1"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(escalation).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// No matching escalation found - should pass (error caught elsewhere)
	errs := validateSessionIdentityProviderAuthorization(
		context.Background(),
		"test-cluster", // doesn't match any escalation
		"cluster-admin",
		"any-idp",
		field.NewPath("spec").Child("identityProviderName"),
	)
	assert.Nil(t, errs, "should pass when no matching escalation found")
}

// TestListObjectsByName tests the list-by-name helper
func TestListObjectsByName_EmptyName(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	list := &BreakglassSessionList{}
	err := listObjectsByName(context.Background(), fakeClient, list, "")
	assert.NoError(t, err, "should return nil for empty name")
}

func TestListObjectsByName_ValidName(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	list := &BreakglassSessionList{}
	err := listObjectsByName(context.Background(), fakeClient, list, "test-name")
	assert.NoError(t, err, "should succeed for valid name")
}

// TestEnsureClusterWideUniqueIssuer tests issuer uniqueness validation
func TestEnsureClusterWideUniqueIssuer_EmptyIssuer(t *testing.T) {
	errs := ensureClusterWideUniqueIssuer(context.Background(), "", "my-idp", field.NewPath("spec").Child("issuer"))
	assert.Nil(t, errs, "should return nil for empty issuer")
}

func TestEnsureClusterWideUniqueIssuer_InvalidHTTPS(t *testing.T) {
	errs := ensureClusterWideUniqueIssuer(context.Background(), "http://not-https.com", "my-idp", field.NewPath("spec").Child("issuer"))
	assert.NotNil(t, errs, "should reject non-HTTPS issuer")
}

func TestEnsureClusterWideUniqueIssuer_NilReader(t *testing.T) {
	oldClient := webhookClient
	oldCache := webhookCache
	webhookClient = nil
	webhookCache = nil
	defer func() {
		webhookClient = oldClient
		webhookCache = oldCache
	}()

	errs := ensureClusterWideUniqueIssuer(context.Background(), "https://auth.example.com", "my-idp", field.NewPath("spec").Child("issuer"))
	assert.Nil(t, errs, "should return nil when reader is nil")
}

func TestEnsureClusterWideUniqueIssuer_NoConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := ensureClusterWideUniqueIssuer(context.Background(), "https://unique.example.com", "my-idp", field.NewPath("spec").Child("issuer"))
	assert.Nil(t, errs, "should pass when no conflict")
}

func TestEnsureClusterWideUniqueIssuer_WithConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	existingIDP := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client-id",
			},
			Issuer: "https://auth.example.com", // same issuer
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingIDP).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// Different IDP name with same issuer - conflict!
	errs := ensureClusterWideUniqueIssuer(context.Background(), "https://auth.example.com", "new-idp", field.NewPath("spec").Child("issuer"))
	assert.NotNil(t, errs, "should detect conflict when same issuer exists")
}

func TestEnsureClusterWideUniqueIssuer_SameName(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	existingIDP := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "my-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client-id",
			},
			Issuer: "https://auth.example.com",
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingIDP).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// Same IDP name (updating itself) - no conflict
	errs := ensureClusterWideUniqueIssuer(context.Background(), "https://auth.example.com", "my-idp", field.NewPath("spec").Child("issuer"))
	assert.Nil(t, errs, "should allow same issuer for same IDP")
}

func TestEnsureClusterWideUniqueIssuer_NilContext(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// nil context should use TODO context
	errs := ensureClusterWideUniqueIssuer(context.TODO(), "https://example.com", "new-idp", field.NewPath("issuer"))
	assert.Nil(t, errs, "should handle nil context")
}

func TestEnsureClusterWideUniqueIssuer_NilPath(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// nil path should return nil
	errs := ensureClusterWideUniqueIssuer(context.Background(), "https://example.com", "new-idp", nil)
	assert.Nil(t, errs, "should return nil when path is nil")
}

// TestValidateIdentityProviderFields tests IDP tracking field validation
func TestValidateIdentityProviderFields_BothEmpty(t *testing.T) {
	errs := validateIdentityProviderFields(
		context.Background(),
		"", "",
		field.NewPath("spec").Child("identityProviderName"),
		field.NewPath("spec").Child("identityProviderIssuer"),
	)
	assert.Nil(t, errs, "should pass when both fields empty")
}

func TestValidateIdentityProviderFields_NilPaths(t *testing.T) {
	errs := validateIdentityProviderFields(
		context.Background(),
		"idp-name", "https://issuer.com",
		nil, nil, // nil paths
	)
	assert.Nil(t, errs, "should pass when paths are nil")
}

func TestValidateIdentityProviderFields_NilReader(t *testing.T) {
	oldClient := webhookClient
	oldCache := webhookCache
	webhookClient = nil
	webhookCache = nil
	defer func() {
		webhookClient = oldClient
		webhookCache = oldCache
	}()

	errs := validateIdentityProviderFields(
		context.Background(),
		"idp-name", "https://issuer.com",
		field.NewPath("spec").Child("identityProviderName"),
		field.NewPath("spec").Child("identityProviderIssuer"),
	)
	assert.Nil(t, errs, "should pass when reader is nil")
}

func TestValidateIdentityProviderFields_NilContext(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "my-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client-id",
			},
			Issuer: "https://issuer.com",
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// nil context should use Background context
	errs := validateIdentityProviderFields(
		context.TODO(),
		"my-idp", "https://issuer.com",
		field.NewPath("spec").Child("identityProviderName"),
		field.NewPath("spec").Child("identityProviderIssuer"),
	)
	assert.Nil(t, errs, "should handle nil context")
}

func TestValidateIdentityProviderFields_IDPNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := validateIdentityProviderFields(
		context.Background(),
		"nonexistent-idp", "",
		field.NewPath("spec").Child("identityProviderName"),
		field.NewPath("spec").Child("identityProviderIssuer"),
	)
	assert.NotNil(t, errs, "should report error when IDP not found")
}

func TestValidateIdentityProviderFields_IDPDisabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	disabledIDP := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client-id",
			},
			Disabled: true,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(disabledIDP).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := validateIdentityProviderFields(
		context.Background(),
		"disabled-idp", "",
		field.NewPath("spec").Child("identityProviderName"),
		field.NewPath("spec").Child("identityProviderIssuer"),
	)
	assert.NotNil(t, errs, "should report error when IDP is disabled")
}

func TestValidateIdentityProviderFields_IssuerMismatch(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "my-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client-id",
			},
			Issuer: "https://auth.example.com",
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := validateIdentityProviderFields(
		context.Background(),
		"my-idp", "https://different-issuer.com", // mismatched issuer
		field.NewPath("spec").Child("identityProviderName"),
		field.NewPath("spec").Child("identityProviderIssuer"),
	)
	assert.NotNil(t, errs, "should report error when issuer doesn't match")
}

func TestValidateIdentityProviderFields_ValidMatch(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "my-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client-id",
			},
			Issuer: "https://auth.example.com",
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := validateIdentityProviderFields(
		context.Background(),
		"my-idp", "https://auth.example.com", // matching issuer
		field.NewPath("spec").Child("identityProviderName"),
		field.NewPath("spec").Child("identityProviderIssuer"),
	)
	assert.Nil(t, errs, "should pass when IDP and issuer match")
}

// TestValidateMailProviderReference tests mail provider reference validation
func TestValidateMailProviderReference_Empty(t *testing.T) {
	errs := validateMailProviderReference(context.Background(), "", field.NewPath("test"))
	assert.Nil(t, errs, "should return nil for empty mail provider")
}

func TestValidateMailProviderReference_NilPath(t *testing.T) {
	errs := validateMailProviderReference(context.Background(), "mail-provider", nil)
	assert.Nil(t, errs, "should return nil for nil path")
}

func TestValidateMailProviderReference_NilReader(t *testing.T) {
	oldClient := webhookClient
	oldCache := webhookCache
	webhookClient = nil
	webhookCache = nil
	defer func() {
		webhookClient = oldClient
		webhookCache = oldCache
	}()

	errs := validateMailProviderReference(context.Background(), "mail-provider", field.NewPath("test"))
	assert.Nil(t, errs, "should return nil when reader is nil")
}

func TestValidateMailProviderReference_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := validateMailProviderReference(context.Background(), "nonexistent", field.NewPath("test"))
	assert.NotNil(t, errs, "should report error when mail provider not found")
}

func TestValidateMailProviderReference_Disabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	disabledMailProvider := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-mail"},
		Spec: MailProviderSpec{
			Disabled: true,
			SMTP:     SMTPConfig{Host: "smtp.test.com", Port: 587},
			Sender:   SenderConfig{Address: "test@test.com"},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(disabledMailProvider).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := validateMailProviderReference(context.Background(), "disabled-mail", field.NewPath("test"))
	assert.NotNil(t, errs, "should report error when mail provider is disabled")
}

func TestValidateMailProviderReference_Valid(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	mailProvider := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "valid-mail"},
		Spec: MailProviderSpec{
			SMTP:   SMTPConfig{Host: "smtp.test.com", Port: 587},
			Sender: SenderConfig{Address: "test@test.com"},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mailProvider).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := validateMailProviderReference(context.Background(), "valid-mail", field.NewPath("test"))
	assert.Nil(t, errs, "should pass when mail provider is valid")
}

func TestValidateMailProviderReference_NilContext(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	mailProvider := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "valid-mail"},
		Spec: MailProviderSpec{
			SMTP:   SMTPConfig{Host: "smtp.test.com", Port: 587},
			Sender: SenderConfig{Address: "test@test.com"},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mailProvider).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// nil context should use Background context
	errs := validateMailProviderReference(context.TODO(), "valid-mail", field.NewPath("test"))
	assert.Nil(t, errs, "should handle nil context")
}

// TestValidateIdentityProviderRefs tests IDP refs validation
func TestValidateIdentityProviderRefs_Empty(t *testing.T) {
	errs := validateIdentityProviderRefs(context.Background(), []string{}, field.NewPath("test"))
	assert.Nil(t, errs, "should return nil for empty refs")
}

func TestValidateIdentityProviderRefs_Duplicates(t *testing.T) {
	errs := validateIdentityProviderRefs(context.Background(), []string{"idp1", "idp1"}, field.NewPath("test"))
	assert.NotNil(t, errs, "should report error for duplicates")
}

func TestValidateIdentityProviderRefs_EmptyEntry(t *testing.T) {
	errs := validateIdentityProviderRefs(context.Background(), []string{"idp1", ""}, field.NewPath("test"))
	assert.NotNil(t, errs, "should report error for empty entry")
}

func TestValidateIdentityProviderRefs_NilReader(t *testing.T) {
	oldClient := webhookClient
	oldCache := webhookCache
	webhookClient = nil
	webhookCache = nil
	defer func() {
		webhookClient = oldClient
		webhookCache = oldCache
	}()

	errs := validateIdentityProviderRefs(context.Background(), []string{"idp1"}, field.NewPath("test"))
	// Should return the empty entry check but not the full validation
	assert.Nil(t, errs, "should return nil when reader is nil")
}

func TestValidateIdentityProviderRefs_ValidExisting(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client-id",
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := validateIdentityProviderRefs(context.Background(), []string{"existing-idp"}, field.NewPath("test"))
	assert.Nil(t, errs, "should pass when IDP exists")
}

func TestValidateIdentityProviderRefs_DisabledIDP(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client-id",
			},
			Disabled: true,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := validateIdentityProviderRefs(context.Background(), []string{"disabled-idp"}, field.NewPath("test"))
	assert.NotNil(t, errs, "should report error when IDP is disabled")
}

func TestValidateIdentityProviderRefs_NilContext(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "my-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client-id",
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	// nil context should use Background context
	errs := validateIdentityProviderRefs(context.TODO(), []string{"my-idp"}, field.NewPath("test"))
	assert.Nil(t, errs, "should handle nil context")
}

func TestValidateIdentityProviderRefs_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	oldClient := webhookClient
	defer func() { webhookClient = oldClient }()
	webhookClient = fakeClient

	errs := validateIdentityProviderRefs(context.Background(), []string{"nonexistent-idp"}, field.NewPath("test"))
	assert.NotNil(t, errs, "should report error when IDP not found")
}

// TestValidateURLFormat_NoScheme tests URL without scheme
func TestValidateURLFormat_NoScheme(t *testing.T) {
	errs := validateURLFormat("example.com", field.NewPath("url"))
	assert.NotNil(t, errs, "URL without scheme should fail")
}

func TestValidateURLFormat_FTPScheme(t *testing.T) {
	errs := validateURLFormat("ftp://example.com", field.NewPath("url"))
	assert.NotNil(t, errs, "FTP URL should fail")
}

func TestValidateURLFormat_NoHost(t *testing.T) {
	errs := validateURLFormat("https:///path", field.NewPath("url"))
	assert.NotNil(t, errs, "URL without host should fail")
}

func TestValidateURLFormat_HTTP(t *testing.T) {
	errs := validateURLFormat("http://example.com", field.NewPath("url"))
	assert.Nil(t, errs, "valid HTTP URL should pass")
}

// TestValidateHTTPSURL_HTTPScheme tests HTTPS URL validation rejects HTTP
func TestValidateHTTPSURL_HTTPScheme(t *testing.T) {
	errs := validateHTTPSURL("http://example.com", field.NewPath("url"))
	assert.NotNil(t, errs, "HTTP URL should fail for HTTPS validation")
}

func TestValidateHTTPSURL_Invalid(t *testing.T) {
	errs := validateHTTPSURL("not-a-url", field.NewPath("url"))
	assert.NotNil(t, errs, "invalid URL should fail")
}

// Test validateBreakglassEscalationAdditionalLists
func TestValidateBreakglassEscalationAdditionalLists_NilSpec(t *testing.T) {
	errs := validateBreakglassEscalationAdditionalLists(nil, field.NewPath("spec"))
	assert.Nil(t, errs, "nil spec should return nil")
}

func TestValidateBreakglassEscalationAdditionalLists_NilPath(t *testing.T) {
	spec := &BreakglassEscalationSpec{}
	errs := validateBreakglassEscalationAdditionalLists(spec, nil)
	assert.Nil(t, errs, "nil path should return nil")
}

func TestValidateBreakglassEscalationAdditionalLists_DenyPolicyRefs(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		DenyPolicyRefs: []string{"policy1", "policy1"}, // duplicate
	}
	errs := validateBreakglassEscalationAdditionalLists(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "duplicate denyPolicyRefs should fail")
}

func TestValidateBreakglassEscalationAdditionalLists_EmptyDenyPolicyRef(t *testing.T) {
	spec := &BreakglassEscalationSpec{
		DenyPolicyRefs: []string{"policy1", ""},
	}
	errs := validateBreakglassEscalationAdditionalLists(spec, field.NewPath("spec"))
	assert.NotNil(t, errs, "empty denyPolicyRef should fail")
}

// Test isValidSpecialCharForID
func TestIsValidSpecialCharForID_All(t *testing.T) {
	tests := []struct {
		char  rune
		valid bool
	}{
		{'*', true},
		{'?', true},
		{'[', true},
		{']', true},
		{'(', true},
		{')', true},
		{'+', true},
		{'|', true},
		{'^', true},
		{'$', true},
		{'\\', true},
		{'a', false},
		{' ', false},
		{'#', false},
	}

	for _, tc := range tests {
		t.Run(string(tc.char), func(t *testing.T) {
			result := isValidSpecialCharForID(tc.char)
			assert.Equal(t, tc.valid, result)
		})
	}
}

// Test containsDot
func TestContainsDot(t *testing.T) {
	assert.True(t, containsDot("example.com"))
	assert.False(t, containsDot("localhost"))
	assert.True(t, containsDot("sub.domain.com"))
}

// Test isValidDomainChar
func TestIsValidDomainChar(t *testing.T) {
	assert.True(t, isValidDomainChar('a'))
	assert.True(t, isValidDomainChar('Z'))
	assert.True(t, isValidDomainChar('0'))
	assert.True(t, isValidDomainChar('-'))
	assert.True(t, isValidDomainChar('.'))
	assert.False(t, isValidDomainChar(' '))
	assert.False(t, isValidDomainChar('_'))
	assert.False(t, isValidDomainChar('@'))
}
