/*
Copyright 2026.

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
	t.Parallel()
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
		{
			name:    "DenyPolicy/at least one rule required",
			crdFile: "breakglass.t-caas.telekom.com_denypolicies.yaml",
			ruleSnippets: []string{
				"self.rules",
				"self.podSecurityRules",
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

			// Verify that ALL rule snippets appear together within a single CEL rule
			// expression. This prevents false positives where snippets individually
			// match different rules but no single rule contains all of them.
			foundAllInOneRule := false
			for _, rule := range celRules {
				allPresent := true
				for _, snippet := range tt.ruleSnippets {
					if !strings.Contains(rule, snippet) {
						allPresent = false
						break
					}
				}
				if allPresent {
					foundAllInOneRule = true
					break
				}
			}
			if !foundAllInOneRule {
				t.Errorf("CRD %s: no single CEL rule expression contains all expected snippets %v", tt.crdFile, tt.ruleSnippets)
			}
		})
	}
}

// extractCELRules extracts only CEL rule expressions (not message blocks)
// from CRD YAML content. Rules may span multiple YAML lines (continuation
// lines are indented further than the key line).
// This ensures test snippets are matched only within actual rule expressions,
// preventing false positives from message text or field descriptions.
func extractCELRules(content string) []string {
	var rules []string
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "- rule:") || strings.HasPrefix(trimmed, "rule:") {
			// Capture the key line plus any continuation lines using strings.Builder
			// to avoid repeated string concatenation.
			var b strings.Builder
			b.WriteString(trimmed)
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
				b.WriteByte(' ')
				b.WriteString(nextTrimmed)
				i++
			}
			rules = append(rules, b.String())
		}
	}
	return rules
}
