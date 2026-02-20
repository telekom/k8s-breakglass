package v1alpha1_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCELValidationRulesPresent verifies that the generated CRD manifests
// contain the expected x-kubernetes-validations (CEL) rules. CEL rules are
// enforced by the Kubernetes API server, so they cannot be unit-tested in Go.
// This test ensures that controller-gen has successfully emitted them.
func TestCELValidationRulesPresent(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	basePath := filepath.Join(filepath.Dir(thisFile), "..", "..", "config", "crd", "bases")

	tests := []struct {
		name         string
		crdFile      string
		ruleSnippets []string
	}{
		{
			name:    "BreakglassEscalation/blockSelfApproval requires approver groups",
			crdFile: "breakglass.t-caas.telekom.com_breakglassescalations.yaml",
			ruleSnippets: []string{
				"blockSelfApproval",
				"approvers.groups",
			},
		},
		{
			name:    "BreakglassEscalation/allowedIdentityProviders mutual exclusivity",
			crdFile: "breakglass.t-caas.telekom.com_breakglassescalations.yaml",
			ruleSnippets: []string{
				"allowedIdentityProviders",
				"allowedIdentityProvidersForRequests",
				"allowedIdentityProvidersForApprovers",
			},
		},
		{
			name:    "BreakglassEscalation/SessionLimitsOverride unlimited check",
			crdFile: "breakglass.t-caas.telekom.com_breakglassescalations.yaml",
			ruleSnippets: []string{
				"self.unlimited",
				"maxActiveSessionsPerUser",
				"maxActiveSessionsTotal",
			},
		},
		{
			name:    "BreakglassEscalation/PodSecurityOverrides requireApproval",
			crdFile: "breakglass.t-caas.telekom.com_breakglassescalations.yaml",
			ruleSnippets: []string{
				"self.requireApproval",
				"self.approvers",
			},
		},
		{
			name:    "DenyPolicy/at least one rule or podSecurityRules",
			crdFile: "breakglass.t-caas.telekom.com_denypolicies.yaml",
			ruleSnippets: []string{
				"size(self.rules)",
				"podSecurityRules",
			},
		},
		{
			name:    "IdentityProvider/keycloak required when groupSyncProvider is Keycloak",
			crdFile: "breakglass.t-caas.telekom.com_identityproviders.yaml",
			ruleSnippets: []string{
				"groupSyncProvider",
				"Keycloak",
				"self.keycloak",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crdPath := filepath.Join(basePath, tt.crdFile)
			data, err := os.ReadFile(crdPath)
			if err != nil {
				t.Fatalf("failed to read CRD file %s: %v", tt.crdFile, err)
			}
			content := string(data)

			// Verify the file contains x-kubernetes-validations
			if !strings.Contains(content, "x-kubernetes-validations") {
				t.Fatalf("CRD %s does not contain any x-kubernetes-validations", tt.crdFile)
			}

			// Verify each expected rule snippet appears in the file
			for _, snippet := range tt.ruleSnippets {
				if !strings.Contains(content, snippet) {
					t.Errorf("CRD %s missing expected CEL rule snippet: %q", tt.crdFile, snippet)
				}
			}
		})
	}
}
