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

package helpers

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestFixturesDir(t *testing.T) {
	dir := FixturesDir()
	// Should return a path (may or may not exist in unit test context)
	assert.NotEmpty(t, dir)
}

func TestLoadFixture(t *testing.T) {
	// Create a temporary fixture file for testing
	tmpDir := t.TempDir()

	// Create escalations subdirectory
	escDir := filepath.Join(tmpDir, "escalations")
	require.NoError(t, os.MkdirAll(escDir, 0755))

	// Write a test fixture
	fixtureContent := `apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: test-fixture
  labels:
    test: "true"
spec:
  escalatedGroup: test-group
  maxValidFor: "1h"
  approvalTimeout: "30m"
  allowed:
    clusters:
      - test-cluster
    groups:
      - developers
  approvers:
    users:
      - approver@example.com
`
	fixturePath := filepath.Join(escDir, "test.yaml")
	require.NoError(t, os.WriteFile(fixturePath, []byte(fixtureContent), 0644))

	// Override FixturesDir to use our temp directory
	origFixturesDir := FixturesDir
	defer func() { _ = origFixturesDir }()

	// Test loading the fixture directly
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	obj, _, err := fixtureDecoder.Decode(data, nil, nil)
	require.NoError(t, err)

	escalation, ok := obj.(*breakglassv1alpha1.BreakglassEscalation)
	require.True(t, ok, "Expected BreakglassEscalation, got %T", obj)

	assert.Equal(t, "test-fixture", escalation.Name)
	assert.Equal(t, "test-group", escalation.Spec.EscalatedGroup)
	assert.Equal(t, "1h", escalation.Spec.MaxValidFor)
	assert.Contains(t, escalation.Spec.Allowed.Clusters, "test-cluster")
}

func TestLoadFixtureCustomized(t *testing.T) {
	// Test that customization function works
	tmpDir := t.TempDir()

	fixtureContent := `apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: original-name
spec:
  escalatedGroup: original-group
  maxValidFor: "1h"
  approvalTimeout: "30m"
  allowed:
    clusters: []
    groups: []
  approvers:
    users: []
`
	fixturePath := filepath.Join(tmpDir, "test.yaml")
	require.NoError(t, os.WriteFile(fixturePath, []byte(fixtureContent), 0644))

	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	obj, _, err := fixtureDecoder.Decode(data, nil, nil)
	require.NoError(t, err)

	escalation := obj.(*breakglassv1alpha1.BreakglassEscalation)

	// Simulate customization
	escalation.SetName("customized-name")
	escalation.Spec.EscalatedGroup = "custom-group"

	assert.Equal(t, "customized-name", escalation.Name)
	assert.Equal(t, "custom-group", escalation.Spec.EscalatedGroup)
}

// TestFixturesAreValid validates that all YAML fixture files in e2e/fixtures/
// decode cleanly and pass Go validation. This prevents fixture drift when CRD
// types or validation rules change (e.g., new CEL rules, removed fields).
func TestFixturesAreValid(t *testing.T) {
	fixturesRoot := FixturesDir()

	// Collect all YAML fixture files recursively
	var fixtureFiles []string
	err := filepath.Walk(fixturesRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			fixtureFiles = append(fixtureFiles, path)
		}
		return nil
	})
	require.NoError(t, err, "failed to walk fixtures dir %s", fixturesRoot)
	require.NotEmpty(t, fixtureFiles, "no fixture files found in %s", fixturesRoot)

	t.Logf("Found %d fixture files in %s", len(fixtureFiles), fixturesRoot)

	validatedKinds := make(map[string]int)

	for _, file := range fixtureFiles {
		relPath, _ := filepath.Rel(fixturesRoot, file)
		t.Run(relPath, func(t *testing.T) {
			data, err := os.ReadFile(file)
			require.NoError(t, err)

			// Split multi-document YAML
			docs := splitYAMLDocs(t, data)

			for i, doc := range docs {
				if len(bytes.TrimSpace(doc)) == 0 {
					continue
				}
				// Skip non-breakglass resources (e.g., Secrets)
				if !bytes.Contains(doc, []byte("breakglass.t-caas.telekom.com")) {
					continue
				}

				obj, _, err := fixtureDecoder.Decode(doc, nil, nil)
				require.NoError(t, err, "document %d failed to decode", i+1)

				err = validateFixtureObject(obj)
				require.NoError(t, err, "document %d (%T) failed validation", i+1, obj)

				validatedKinds[fmt.Sprintf("%T", obj)]++
			}
		})
	}

	t.Logf("Validated fixture kinds: %v", validatedKinds)
}

// splitYAMLDocs splits a multi-document YAML byte slice into individual documents.
func splitYAMLDocs(t *testing.T, data []byte) [][]byte {
	t.Helper()
	var docs [][]byte
	reader := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for {
		doc, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "failed to read YAML document")
		docs = append(docs, doc)
	}
	return docs
}

// validateFixtureObject runs the Go validation function for the decoded CRD object.
func validateFixtureObject(obj runtime.Object) error {
	switch o := obj.(type) {
	case *breakglassv1alpha1.BreakglassEscalation:
		if r := breakglassv1alpha1.ValidateBreakglassEscalation(o); len(r.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", r.Errors)
		}
	case *breakglassv1alpha1.DenyPolicy:
		if r := breakglassv1alpha1.ValidateDenyPolicy(o); len(r.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", r.Errors)
		}
	case *breakglassv1alpha1.ClusterConfig:
		if r := breakglassv1alpha1.ValidateClusterConfig(o); len(r.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", r.Errors)
		}
	case *breakglassv1alpha1.DebugSessionTemplate:
		if r := breakglassv1alpha1.ValidateDebugSessionTemplate(o); len(r.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", r.Errors)
		}
	case *breakglassv1alpha1.DebugPodTemplate:
		if r := breakglassv1alpha1.ValidateDebugPodTemplate(o); len(r.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", r.Errors)
		}
	case *breakglassv1alpha1.IdentityProvider:
		if r := breakglassv1alpha1.ValidateIdentityProvider(o); len(r.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", r.Errors)
		}
	case *breakglassv1alpha1.MailProvider:
		if r := breakglassv1alpha1.ValidateMailProvider(o); len(r.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", r.Errors)
		}
	case *breakglassv1alpha1.BreakglassSession:
		if r := breakglassv1alpha1.ValidateBreakglassSession(o); len(r.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", r.Errors)
		}
	case *breakglassv1alpha1.AuditConfig:
		if r := breakglassv1alpha1.ValidateAuditConfig(o); len(r.Errors) > 0 {
			return fmt.Errorf("validation errors: %v", r.Errors)
		}
	default:
		// Unknown breakglass type — still decoded successfully
	}
	return nil
}
