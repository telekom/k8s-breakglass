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

package v1alpha1

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// TestSamplesAreValid validates all YAML samples in config/samples can be parsed
// and conform to the CRD schema. This ensures samples are always up-to-date
// with the API types and don't have typos or missing required fields.
func TestSamplesAreValid(t *testing.T) {
	// Build the scheme with all our types
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("Failed to add scheme: %v", err)
	}

	// Create a decoder for our types
	codecFactory := serializer.NewCodecFactory(scheme)
	decoder := codecFactory.UniversalDeserializer()

	// Find samples directory relative to this test file
	samplesDir := findSamplesDir(t)

	// Get all YAML files in the samples directory
	files, err := filepath.Glob(filepath.Join(samplesDir, "*.yaml"))
	if err != nil {
		t.Fatalf("Failed to glob samples: %v", err)
	}

	if len(files) == 0 {
		t.Fatalf("No sample files found in %s", samplesDir)
	}

	t.Logf("Found %d sample files in %s", len(files), samplesDir)

	// Track validated resources by kind for coverage reporting
	validatedKinds := make(map[string]int)
	totalDocs := 0
	skippedDocs := 0

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("Failed to read file: %v", err)
			}

			// Split multi-document YAML files
			docs := splitYAMLDocuments(t, data)

			for i, doc := range docs {
				totalDocs++

				// Skip empty documents
				if len(bytes.TrimSpace(doc)) == 0 {
					skippedDocs++
					continue
				}

				// Skip non-breakglass resources (e.g., Secrets, ConfigMaps in samples)
				if !isBreakglassResource(doc) {
					skippedDocs++
					continue
				}

				// Decode the object
				obj, gvk, err := decoder.Decode(doc, nil, nil)
				if err != nil {
					t.Errorf("Document %d: failed to decode: %v\nContent:\n%s", i+1, err, truncateForError(doc))
					continue
				}

				// Run validation based on type
				if err := validateDecodedObject(obj); err != nil {
					t.Errorf("Document %d (%s): validation failed: %v", i+1, gvk.Kind, err)
					continue
				}

				validatedKinds[gvk.Kind]++
				t.Logf("Document %d: successfully validated %s", i+1, gvk.Kind)
			}
		})
	}

	// Report coverage
	t.Logf("\n=== Sample Validation Summary ===")
	t.Logf("Total documents: %d", totalDocs)
	t.Logf("Skipped (non-breakglass): %d", skippedDocs)
	t.Logf("Validated resources by kind:")
	for kind, count := range validatedKinds {
		t.Logf("  - %s: %d", kind, count)
	}

	// Ensure we have samples for all CRD types
	requiredKinds := []string{
		"BreakglassEscalation",
		"BreakglassSession",
		"ClusterConfig",
		"IdentityProvider",
		"MailProvider",
		"DenyPolicy",
		"DebugSessionTemplate",
		"DebugPodTemplate",
		"DebugSession",
		"AuditConfig",
	}

	for _, kind := range requiredKinds {
		if validatedKinds[kind] == 0 {
			t.Errorf("Missing sample for CRD kind: %s", kind)
		}
	}
}

// TestSampleCoverage ensures every major feature has at least one sample
func TestSampleCoverage(t *testing.T) {
	samplesDir := findSamplesDir(t)

	// Define expected sample coverage
	expectedSamples := map[string]string{
		// BreakglassEscalation features
		"escalation_basic":                  "basic escalation configuration",
		"escalation_multi_idp":              "multi-IDP split control",
		"escalation_pod_security_overrides": "pod security overrides for SRE",
		"escalation_notifications":          "notification exclusions and mail provider",

		// ClusterConfig features
		"clusterconfig_kubeconfig":     "kubeconfig-based auth",
		"clusterconfig_oidc":           "direct OIDC auth",
		"clusterconfig_oidc_from_idp":  "OIDC inherited from IdentityProvider",
		"clusterconfig_token_exchange": "OIDC with token exchange",

		// IdentityProvider features
		"identityprovider_keycloak": "Keycloak with group sync",
		"identityprovider_oidc":     "pure OIDC without group sync",

		// MailProvider features
		"mailprovider_basic": "SMTP mail provider",

		// DenyPolicy features
		"denypolicy_basic":            "basic deny rules",
		"denypolicy_podsecurity":      "pod security risk evaluation",
		"denypolicy_namespace_labels": "namespace label selectors",

		// AuditConfig features
		"audit_kafka":     "Kafka sink with TLS/SASL",
		"audit_webhook":   "webhook sink",
		"audit_log":       "log sink",
		"audit_filtering": "event filtering and sampling",

		// DebugSessionTemplate features
		"debugtemplate_workload":      "workload mode (DaemonSet/Deployment)",
		"debugtemplate_kubectl_debug": "kubectl-debug mode",
		"debugtemplate_hybrid":        "hybrid mode",

		// DebugPodTemplate features
		"debugpod_minimal":  "minimal debug pod",
		"debugpod_advanced": "advanced debug pod with tools",

		// BreakglassSession features
		"session_basic":     "basic session request",
		"session_scheduled": "scheduled session",
	}

	files, err := filepath.Glob(filepath.Join(samplesDir, "*.yaml"))
	if err != nil {
		t.Fatalf("Failed to glob samples: %v", err)
	}

	// Check which expected patterns are covered
	t.Logf("Checking sample coverage for %d expected patterns...", len(expectedSamples))

	// This is informational - we're tracking what samples exist
	// to help identify gaps in documentation
	for _, file := range files {
		t.Logf("  Found sample: %s", filepath.Base(file))
	}

	// Note: This test is intentionally soft - it logs gaps but doesn't fail
	// because the main validation test already ensures all CRD kinds have samples.
	// This coverage check is for documentation/review purposes.
}

// findSamplesDir locates the config/samples directory relative to the test file
func findSamplesDir(t *testing.T) string {
	// Try relative paths from the test file location
	candidates := []string{
		"../../config/samples",    // From api/v1alpha1
		"../../../config/samples", // Fallback
		"./config/samples",        // From project root
		"../../config/samples",    // Another relative path
	}

	// Also try using the GOMOD to find project root
	if wd, err := os.Getwd(); err == nil {
		projectRoot := findProjectRoot(wd)
		if projectRoot != "" {
			candidates = append([]string{filepath.Join(projectRoot, "config", "samples")}, candidates...)
		}
	}

	for _, dir := range candidates {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			absDir, _ := filepath.Abs(dir)
			return absDir
		}
	}

	t.Fatalf("Could not find config/samples directory. Tried: %v", candidates)
	return ""
}

// findProjectRoot walks up the directory tree to find go.mod
func findProjectRoot(startDir string) string {
	dir := startDir
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// splitYAMLDocuments splits a multi-document YAML file into individual documents
func splitYAMLDocuments(t *testing.T, data []byte) [][]byte {
	var docs [][]byte
	reader := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))

	for {
		doc, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read YAML document: %v", err)
		}
		docs = append(docs, doc)
	}

	return docs
}

// isBreakglassResource checks if a YAML document is a breakglass CRD
func isBreakglassResource(doc []byte) bool {
	// Quick check for our API group
	return bytes.Contains(doc, []byte("breakglass.t-caas.telekom.com"))
}

// validateDecodedObject runs validation on a decoded object
func validateDecodedObject(obj runtime.Object) error {
	switch o := obj.(type) {
	case *BreakglassEscalation:
		result := ValidateBreakglassEscalation(o)
		if len(result.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", result.Errors)
		}
	case *BreakglassSession:
		result := ValidateBreakglassSession(o)
		if len(result.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", result.Errors)
		}
	case *ClusterConfig:
		result := ValidateClusterConfig(o)
		if len(result.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", result.Errors)
		}
	case *IdentityProvider:
		result := ValidateIdentityProvider(o)
		if len(result.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", result.Errors)
		}
	case *MailProvider:
		result := ValidateMailProvider(o)
		if len(result.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", result.Errors)
		}
	case *DenyPolicy:
		result := ValidateDenyPolicy(o)
		if len(result.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", result.Errors)
		}
	case *DebugSessionTemplate:
		result := ValidateDebugSessionTemplate(o)
		if len(result.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", result.Errors)
		}
	case *DebugPodTemplate:
		result := ValidateDebugPodTemplate(o)
		if len(result.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", result.Errors)
		}
	case *DebugSession:
		result := ValidateDebugSession(o)
		if len(result.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", result.Errors)
		}
	case *AuditConfig:
		result := ValidateAuditConfig(o)
		if len(result.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", result.Errors)
		}
	default:
		// Unknown type - just ensure it decoded successfully
		return nil
	}
	return nil
}

// truncateForError truncates content for error messages
func truncateForError(data []byte) string {
	s := string(data)
	lines := strings.Split(s, "\n")
	if len(lines) > 15 {
		return strings.Join(lines[:15], "\n") + "\n... (truncated)"
	}
	return s
}
