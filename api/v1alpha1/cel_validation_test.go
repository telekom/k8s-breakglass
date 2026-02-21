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
// enforced by the Kubernetes API server at admission time, so they cannot
// be unit-tested in Go. This test ensures that controller-gen has
// successfully emitted them into the CRD YAML.
func TestCELValidationRulesPresent(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	basePath := filepath.Join(filepath.Dir(thisFile), "..", "..", "config", "crd", "bases")

	tests := []struct {
		name         string
		crdFile      string
		ruleSnippets []string // Each snippet must appear within a CEL rule expression in the CRD
	}{
		{
			name:    "BreakglassEscalation/blockSelfApproval requires approver groups or users",
			crdFile: "breakglass.t-caas.telekom.com_breakglassescalations.yaml",
			ruleSnippets: []string{
				"blockSelfApproval",
				"approvers.groups",
				"approvers.users",
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

			// Extract all CEL rule expressions from the CRD to avoid false positives
			// from matching field names or descriptions outside validation blocks.
			celRules := extractCELRules(content)

			// Verify each expected rule snippet appears within a CEL rule expression
			for _, snippet := range tt.ruleSnippets {
				found := false
				for _, rule := range celRules {
					if strings.Contains(rule, snippet) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("CRD %s: no CEL rule expression contains snippet %q", tt.crdFile, snippet)
				}
			}
		})
	}
}

// extractCELRules extracts all multi-line CEL rule expressions and messages
// from CRD YAML content. Rules and messages may span multiple YAML lines
// (continuation lines are indented further than the key line).
// This ensures test snippets are matched only within validation blocks,
// preventing false positives from field names or descriptions.
func extractCELRules(content string) []string {
	var rules []string
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "- rule:") || strings.HasPrefix(trimmed, "rule:") ||
			strings.HasPrefix(trimmed, "- message:") || strings.HasPrefix(trimmed, "message:") {
			// Capture the key line plus any continuation lines
			block := trimmed
			indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " "))
			for i+1 < len(lines) {
				nextIndent := len(lines[i+1]) - len(strings.TrimLeft(lines[i+1], " "))
				nextTrimmed := strings.TrimSpace(lines[i+1])
				// Continuation lines are indented further and don't start a new key
				if nextTrimmed == "" || nextIndent <= indent ||
					strings.HasPrefix(nextTrimmed, "- ") ||
					strings.HasPrefix(nextTrimmed, "rule:") ||
					strings.HasPrefix(nextTrimmed, "message:") {
					break
				}
				block += " " + nextTrimmed
				i++
			}
			rules = append(rules, block)
		}
	}
	return rules
}
