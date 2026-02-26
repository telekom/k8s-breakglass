// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCELValidationRulesInCRD verifies that the generated CRD manifests contain
// the expected CEL validation expressions added to the types via kubebuilder markers.
func TestCELValidationRulesInCRD(t *testing.T) {
	tests := []struct {
		name     string
		crdFile  string
		expected []string
	}{
		{
			name:    "BreakglassEscalation CEL rules",
			crdFile: "config/crd/bases/breakglass.t-caas.telekom.com_breakglassescalations.yaml",
			expected: []string{
				// CEL rule expressions (may be wrapped across lines in YAML, match key fragments)
				"has(self.approvers) && ((has(self.approvers.users) && size(self.approvers.users)",
				"at least one approver (user or group) must be specified",
				"blockSelfApproval requires at least one approver group",
				"escalatedGroup cannot be an approver group when blockSelfApproval",
				"allowedIdentityProviders is mutually exclusive with allowedIdentityProvidersForRequests",
				"allowedIdentityProvidersForRequests and allowedIdentityProvidersForApprovers",
				"unlimited=true is mutually exclusive with maxActiveSessionsPerUser",
			},
		},
		{
			name:    "DenyPolicy CEL rules",
			crdFile: "config/crd/bases/breakglass.t-caas.telekom.com_denypolicies.yaml",
			expected: []string{
				"at least one deny rule or podSecurityRules must be specified",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Read the generated CRD from the repo root
			data, err := os.ReadFile(filepath.Join(crdBasesDir(), filepath.Base(tc.crdFile)))
			if err != nil {
				t.Fatalf("CRD file not found at %s (run 'make manifests' first): %v", tc.crdFile, err)
			}
			content := string(data)

			for _, expected := range tc.expected {
				if !strings.Contains(content, expected) {
					t.Errorf("CRD %s is missing expected CEL rule/message: %q", tc.crdFile, expected)
				}
			}
		})
	}
}

// TestValidateBreakglassEscalation_NoApprovers verifies Go validation catches missing approvers.
func TestValidateBreakglassEscalation_NoApprovers(t *testing.T) {
	esc := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "test-group",
			Approvers:      BreakglassEscalationApprovers{},
		},
	}

	result := ValidateBreakglassEscalation(esc)
	if result.IsValid() {
		t.Fatal("expected validation error for escalation with no approvers, but got valid")
	}
	if !strings.Contains(result.ErrorMessage(), "approver") {
		t.Errorf("expected error about approvers, got: %s", result.ErrorMessage())
	}
}

// TestValidateBreakglassEscalation_BlockSelfApprovalWithoutGroups verifies Go validation
// catches blockSelfApproval enabled without group approvers.
func TestValidateBreakglassEscalation_BlockSelfApprovalWithoutGroups(t *testing.T) {
	blockSelf := true
	esc := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup:    "test-group",
			BlockSelfApproval: &blockSelf,
			Approvers: BreakglassEscalationApprovers{
				Users: []string{"admin@example.com"},
			},
		},
	}

	result := ValidateBreakglassEscalation(esc)
	if result.IsValid() {
		t.Fatal("expected validation error for blockSelfApproval without group approvers, but got valid")
	}
	if !strings.Contains(result.ErrorMessage(), "blockSelfApproval") {
		t.Errorf("expected error about blockSelfApproval, got: %s", result.ErrorMessage())
	}
}

// TestValidateBreakglassEscalation_EscalatedGroupInApprovers verifies Go validation
// catches escalatedGroup being in the approvers group list when blockSelfApproval is enabled.
func TestValidateBreakglassEscalation_EscalatedGroupInApprovers(t *testing.T) {
	blockSelf := true
	esc := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup:    "platform-sre",
			BlockSelfApproval: &blockSelf,
			Approvers: BreakglassEscalationApprovers{
				Groups: []string{"platform-sre", "other-group"},
			},
		},
	}

	result := ValidateBreakglassEscalation(esc)
	if result.IsValid() {
		t.Fatal("expected validation error for escalatedGroup in approver groups with blockSelfApproval, but got valid")
	}
	if !strings.Contains(result.ErrorMessage(), "escalatedGroup") {
		t.Errorf("expected error about escalatedGroup, got: %s", result.ErrorMessage())
	}
}

// TestValidateBreakglassEscalation_MutuallyExclusiveIDPFields verifies that
// setting both AllowedIdentityProviders and AllowedIdentityProvidersForRequests is invalid.
func TestValidateBreakglassEscalation_MutuallyExclusiveIDPFields(t *testing.T) {
	esc := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "test-group",
			Approvers: BreakglassEscalationApprovers{
				Groups: []string{"approvers"},
			},
			AllowedIdentityProviders:             []string{"idp1"},
			AllowedIdentityProvidersForRequests:  []string{"idp2"},
			AllowedIdentityProvidersForApprovers: []string{"idp3"},
		},
	}

	result := ValidateBreakglassEscalation(esc)
	if result.IsValid() {
		t.Fatal("expected validation error for mutually exclusive IDP fields, but got valid")
	}
	if !strings.Contains(result.ErrorMessage(), "cannot use allowedIdentityProvidersForRequests together with") {
		t.Errorf("expected error about mutually exclusive IDP fields, got: %s", result.ErrorMessage())
	}
}

// TestValidateBreakglassEscalation_SessionLimitsUnlimitedWithLimits verifies that
// unlimited=true with per-user or total limits set is caught by Go validation.
func TestValidateBreakglassEscalation_SessionLimitsUnlimitedWithLimits(t *testing.T) {
	maxPerUser := int32(5)
	esc := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "test-group",
			Approvers: BreakglassEscalationApprovers{
				Groups: []string{"approvers"},
			},
			SessionLimitsOverride: &SessionLimitsOverride{
				Unlimited:                true,
				MaxActiveSessionsPerUser: &maxPerUser,
			},
		},
	}

	result := ValidateBreakglassEscalation(esc)
	if result.IsValid() {
		t.Fatal("expected validation error for unlimited=true with maxActiveSessionsPerUser set, but got valid")
	}
	if !strings.Contains(result.ErrorMessage(), "unlimited") {
		t.Errorf("expected error about unlimited, got: %s", result.ErrorMessage())
	}
}

// TestValidateDenyPolicy_NoRulesOrPodSecurityRules verifies Go validation catches
// a DenyPolicy with no rules and no podSecurityRules.
func TestValidateDenyPolicy_NoRulesOrPodSecurityRules(t *testing.T) {
	dp := &DenyPolicy{
		Spec: DenyPolicySpec{},
	}

	result := ValidateDenyPolicy(dp)
	if result.IsValid() {
		t.Fatal("expected validation error for DenyPolicy with no rules or podSecurityRules, but got valid")
	}
	if !strings.Contains(result.ErrorMessage(), "at least one") {
		t.Errorf("expected error about requiring at least one rule, got: %s", result.ErrorMessage())
	}
}

// TestValidateBreakglassEscalation_ValidSpec verifies that a well-formed escalation
// with both user and group approvers passes Go validation (happy path).
func TestValidateBreakglassEscalation_ValidSpec(t *testing.T) {
	esc := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "platform-sre",
			Allowed: BreakglassEscalationAllowed{
				Groups: []string{"platform-sre"},
			},
			Approvers: BreakglassEscalationApprovers{
				Users:  []string{"admin@example.com"},
				Groups: []string{"approvers"},
			},
		},
	}

	result := ValidateBreakglassEscalation(esc)
	if !result.IsValid() {
		t.Fatalf("expected valid escalation, got errors: %s", result.ErrorMessage())
	}
}

// TestValidateBreakglassEscalation_BlockSelfApprovalNil verifies that a nil
// blockSelfApproval with only user approvers passes validation.
func TestValidateBreakglassEscalation_BlockSelfApprovalNil(t *testing.T) {
	esc := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "test-group",
			Allowed: BreakglassEscalationAllowed{
				Groups: []string{"test-group"},
			},
			Approvers: BreakglassEscalationApprovers{
				Users: []string{"admin@example.com"},
			},
		},
	}

	result := ValidateBreakglassEscalation(esc)
	if !result.IsValid() {
		t.Fatalf("expected valid escalation with nil blockSelfApproval and user-only approvers, got errors: %s", result.ErrorMessage())
	}
}

// TestValidateBreakglassEscalation_SessionLimitsUnlimitedWithTotal verifies that
// unlimited=true with maxActiveSessionsTotal set is caught by Go validation.
func TestValidateBreakglassEscalation_SessionLimitsUnlimitedWithTotal(t *testing.T) {
	maxTotal := int32(10)
	esc := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "test-group",
			Approvers: BreakglassEscalationApprovers{
				Groups: []string{"approvers"},
			},
			SessionLimitsOverride: &SessionLimitsOverride{
				Unlimited:              true,
				MaxActiveSessionsTotal: &maxTotal,
			},
		},
	}

	result := ValidateBreakglassEscalation(esc)
	if result.IsValid() {
		t.Fatal("expected validation error for unlimited=true with maxActiveSessionsTotal set, but got valid")
	}
	if !strings.Contains(result.ErrorMessage(), "unlimited") {
		t.Errorf("expected error about unlimited, got: %s", result.ErrorMessage())
	}
}
