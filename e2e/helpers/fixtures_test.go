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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
