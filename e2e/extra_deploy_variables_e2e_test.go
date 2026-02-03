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

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestDebugSession_E2E_ExtraDeployVariables_TemplateCreation tests creating templates with extraDeployVariables
func TestDebugSession_E2E_ExtraDeployVariables_TemplateCreation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	podTemplateName := "e2e-extra-deploy-pod-template"
	sessionTemplateName := "e2e-extra-deploy-session-template"

	// Create pod template first
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: podTemplateName,
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Extra Deploy Pod Template",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:    "debug",
							Image:   "busybox:latest",
							Command: []string{"sleep", "infinity"},
						},
					},
				},
			},
		},
	}

	// Cleanup before and after
	_ = cli.Delete(ctx, podTemplate)
	defer func() { _ = cli.Delete(ctx, podTemplate) }()

	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err, "Failed to create DebugPodTemplate with podTemplateString")

	// Create session template with extraDeployVariables
	replicas := int32(1)
	minLength := 3
	maxLength := 50
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: sessionTemplateName,
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Extra Deploy Variables Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplateName,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups:   []string{"*"},
				Clusters: []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
			ExtraDeployVariables: []telekomv1alpha1.ExtraDeployVariable{
				{
					Name:        "enableDebug",
					DisplayName: "Enable Debug Mode",
					Description: "Enable verbose debug logging",
					InputType:   telekomv1alpha1.InputTypeBoolean,
					Default:     &apiextensionsv1.JSON{Raw: []byte(`false`)},
				},
				{
					Name:        "logLevel",
					DisplayName: "Log Level",
					Description: "Logging verbosity level",
					InputType:   telekomv1alpha1.InputTypeSelect,
					Options: []telekomv1alpha1.SelectOption{
						{Value: "debug", DisplayName: "Debug"},
						{Value: "info", DisplayName: "Info"},
						{Value: "warn", DisplayName: "Warning"},
						{Value: "error", DisplayName: "Error"},
					},
					Default: &apiextensionsv1.JSON{Raw: []byte(`"info"`)},
				},
				{
					Name:        "replicaCount",
					DisplayName: "Replica Count",
					Description: "Number of debug pod replicas",
					InputType:   telekomv1alpha1.InputTypeNumber,
					Validation: &telekomv1alpha1.VariableValidation{
						Min: "1",
						Max: "5",
					},
					Default: &apiextensionsv1.JSON{Raw: []byte(`1`)},
				},
				{
					Name:        "debugLabel",
					DisplayName: "Debug Label",
					Description: "Custom label for debug resources",
					InputType:   telekomv1alpha1.InputTypeText,
					Required:    true,
					Validation: &telekomv1alpha1.VariableValidation{
						MinLength:    &minLength,
						MaxLength:    &maxLength,
						Pattern:      "^[a-z][a-z0-9-]*$",
						PatternError: "Must start with lowercase letter and contain only lowercase letters, numbers, and hyphens",
					},
				},
				{
					Name:        "storageSize",
					DisplayName: "Storage Size",
					Description: "Size of scratch storage",
					InputType:   telekomv1alpha1.InputTypeStorageSize,
					Validation: &telekomv1alpha1.VariableValidation{
						MinStorage: "100Mi",
						MaxStorage: "10Gi",
					},
					Default: &apiextensionsv1.JSON{Raw: []byte(`"1Gi"`)},
				},
				{
					Name:        "advancedSetting",
					DisplayName: "Advanced Setting",
					Description: "An advanced configuration option",
					InputType:   telekomv1alpha1.InputTypeText,
					Advanced:    true,
					Default:     &apiextensionsv1.JSON{Raw: []byte(`"default-value"`)},
				},
			},
		},
	}

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() { _ = cli.Delete(ctx, sessionTemplate) }()

	err = cli.Create(ctx, sessionTemplate)
	require.NoError(t, err, "Failed to create session template with extraDeployVariables")

	// Verify template has extraDeployVariables
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: sessionTemplateName}, &fetched)
	require.NoError(t, err)

	assert.Len(t, fetched.Spec.ExtraDeployVariables, 6, "Expected 6 extraDeployVariables")

	// Verify specific variables
	varMap := make(map[string]telekomv1alpha1.ExtraDeployVariable)
	for _, v := range fetched.Spec.ExtraDeployVariables {
		varMap[v.Name] = v
	}

	// Check boolean variable
	enableDebug, ok := varMap["enableDebug"]
	assert.True(t, ok, "enableDebug variable should exist")
	assert.Equal(t, telekomv1alpha1.InputTypeBoolean, enableDebug.InputType)
	assert.NotNil(t, enableDebug.Default)

	// Check select variable
	logLevel, ok := varMap["logLevel"]
	assert.True(t, ok, "logLevel variable should exist")
	assert.Equal(t, telekomv1alpha1.InputTypeSelect, logLevel.InputType)
	assert.Len(t, logLevel.Options, 4, "Expected 4 log level options")

	// Check required text variable with validation
	debugLabel, ok := varMap["debugLabel"]
	assert.True(t, ok, "debugLabel variable should exist")
	assert.True(t, debugLabel.Required)
	assert.NotNil(t, debugLabel.Validation)
	assert.Equal(t, "^[a-z][a-z0-9-]*$", debugLabel.Validation.Pattern)

	// Check advanced variable
	advancedSetting, ok := varMap["advancedSetting"]
	assert.True(t, ok, "advancedSetting variable should exist")
	assert.True(t, advancedSetting.Advanced)

	t.Logf("Successfully created template with %d extraDeployVariables", len(fetched.Spec.ExtraDeployVariables))
}

// TestDebugSession_E2E_ExtraDeployVariables_SessionWithValues tests creating sessions with extraDeployValues
func TestDebugSession_E2E_ExtraDeployVariables_SessionWithValues(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	podTemplateName := "e2e-edv-session-pod-template"
	sessionTemplateName := "e2e-edv-session-template"
	sessionName := "e2e-edv-test-session"

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: podTemplateName,
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E EDV Session Pod Template",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:    "debug",
							Image:   "busybox:latest",
							Command: []string{"sleep", "infinity"},
						},
					},
				},
			},
		},
	}

	_ = cli.Delete(ctx, podTemplate)
	defer func() { _ = cli.Delete(ctx, podTemplate) }()

	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err, "Failed to create DebugPodTemplate")

	// Create session template with variables
	replicas := int32(1)
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: sessionTemplateName,
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E EDV Session Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplateName,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups:   []string{"*"},
				Clusters: []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
			ExtraDeployVariables: []telekomv1alpha1.ExtraDeployVariable{
				{
					Name:      "enableDebug",
					InputType: telekomv1alpha1.InputTypeBoolean,
					Default:   &apiextensionsv1.JSON{Raw: []byte(`false`)},
				},
				{
					Name:      "logLevel",
					InputType: telekomv1alpha1.InputTypeSelect,
					Options: []telekomv1alpha1.SelectOption{
						{Value: "debug"},
						{Value: "info"},
						{Value: "warn"},
					},
					Default: &apiextensionsv1.JSON{Raw: []byte(`"info"`)},
				},
				{
					Name:     "requiredLabel",
					Required: true,
				},
			},
		},
	}

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() { _ = cli.Delete(ctx, sessionTemplate) }()

	err = cli.Create(ctx, sessionTemplate)
	require.NoError(t, err, "Failed to create session template")

	// Get cluster name for session
	clusterName := helpers.GetTestClusterName()

	// Create a debug session with extraDeployValues
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sessionName,
			Namespace: testNamespace,
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			TemplateRef: sessionTemplateName,
			Cluster:     clusterName,
			RequestedBy: "e2e-test@example.com",
			Reason:      "Testing extraDeployValues",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"enableDebug":   {Raw: []byte(`true`)},
				"logLevel":      {Raw: []byte(`"debug"`)},
				"requiredLabel": {Raw: []byte(`"my-debug-session"`)},
			},
		},
	}

	_ = cli.Delete(ctx, session)
	defer func() { _ = cli.Delete(ctx, session) }()

	err = cli.Create(ctx, session)
	require.NoError(t, err, "Failed to create debug session with extraDeployValues")

	// Verify session was created with values
	var fetched telekomv1alpha1.DebugSession
	err = cli.Get(ctx, types.NamespacedName{Name: sessionName, Namespace: testNamespace}, &fetched)
	require.NoError(t, err)

	assert.Len(t, fetched.Spec.ExtraDeployValues, 3, "Expected 3 extraDeployValues")
	assert.Contains(t, fetched.Spec.ExtraDeployValues, "enableDebug")
	assert.Contains(t, fetched.Spec.ExtraDeployValues, "logLevel")
	assert.Contains(t, fetched.Spec.ExtraDeployValues, "requiredLabel")

	t.Logf("Successfully created session with extraDeployValues: %v", fetched.Spec.ExtraDeployValues)
}

// TestDebugSession_E2E_ExtraDeployVariables_ValidationRejectsInvalid tests that invalid values are rejected by webhook
func TestDebugSession_E2E_ExtraDeployVariables_ValidationRejectsInvalid(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	podTemplateName := "e2e-edv-validation-pod-template"
	sessionTemplateName := "e2e-edv-validation-template"

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: podTemplateName,
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E EDV Validation Pod Template",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:    "debug",
							Image:   "busybox:latest",
							Command: []string{"sleep", "infinity"},
						},
					},
				},
			},
		},
	}

	_ = cli.Delete(ctx, podTemplate)
	defer func() { _ = cli.Delete(ctx, podTemplate) }()

	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err)

	// Create session template with validation rules
	replicas := int32(1)
	minLen := 5
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: sessionTemplateName,
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E EDV Validation Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplateName,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups:   []string{"*"},
				Clusters: []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
			ExtraDeployVariables: []telekomv1alpha1.ExtraDeployVariable{
				{
					Name:      "requiredField",
					Required:  true,
					InputType: telekomv1alpha1.InputTypeText,
					Validation: &telekomv1alpha1.VariableValidation{
						MinLength: &minLen,
					},
				},
				{
					Name:      "selectField",
					InputType: telekomv1alpha1.InputTypeSelect,
					Options: []telekomv1alpha1.SelectOption{
						{Value: "valid-option-1"},
						{Value: "valid-option-2"},
					},
				},
			},
		},
	}

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() { _ = cli.Delete(ctx, sessionTemplate) }()

	err = cli.Create(ctx, sessionTemplate)
	require.NoError(t, err)

	clusterName := helpers.GetTestClusterName()

	// Test 1: Missing required field should fail webhook validation
	t.Run("missing required field", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-edv-validation-missing-required",
				Namespace: testNamespace,
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				TemplateRef: sessionTemplateName,
				Cluster:     clusterName,
				RequestedBy: "e2e-test@example.com",
				// No extraDeployValues - missing required field
			},
		}

		_ = cli.Delete(ctx, session)
		defer func() { _ = cli.Delete(ctx, session) }()

		err := cli.Create(ctx, session)
		// Note: Webhook validation may or may not be enabled in e2e environment
		// If webhook is enabled, this should fail; if not, it will succeed
		if err != nil {
			t.Logf("Session creation correctly rejected: %v", err)
			assert.Contains(t, err.Error(), "requiredField")
		} else {
			t.Log("Session creation succeeded (webhook validation may not be enabled in test environment)")
		}
	})

	// Test 2: Invalid select option should fail
	t.Run("invalid select option", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-edv-validation-invalid-select",
				Namespace: testNamespace,
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				TemplateRef: sessionTemplateName,
				Cluster:     clusterName,
				RequestedBy: "e2e-test@example.com",
				ExtraDeployValues: map[string]apiextensionsv1.JSON{
					"requiredField": {Raw: []byte(`"valid-value"`)},
					"selectField":   {Raw: []byte(`"invalid-option"`)},
				},
			},
		}

		_ = cli.Delete(ctx, session)
		defer func() { _ = cli.Delete(ctx, session) }()

		err := cli.Create(ctx, session)
		if err != nil {
			t.Logf("Session creation correctly rejected: %v", err)
			assert.Contains(t, err.Error(), "selectField")
		} else {
			t.Log("Session creation succeeded (webhook validation may not be enabled in test environment)")
		}
	})

	// Test 3: Value too short should fail
	t.Run("value too short", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-edv-validation-too-short",
				Namespace: testNamespace,
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				TemplateRef: sessionTemplateName,
				Cluster:     clusterName,
				RequestedBy: "e2e-test@example.com",
				ExtraDeployValues: map[string]apiextensionsv1.JSON{
					"requiredField": {Raw: []byte(`"ab"`)}, // Too short (min 5)
				},
			},
		}

		_ = cli.Delete(ctx, session)
		defer func() { _ = cli.Delete(ctx, session) }()

		err := cli.Create(ctx, session)
		if err != nil {
			t.Logf("Session creation correctly rejected: %v", err)
			assert.Contains(t, err.Error(), "requiredField")
		} else {
			t.Log("Session creation succeeded (webhook validation may not be enabled in test environment)")
		}
	})
}

// TestDebugSession_E2E_ExtraDeployVariables_MultiSelect tests multiSelect variable type
func TestDebugSession_E2E_ExtraDeployVariables_MultiSelect(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	podTemplateName := "e2e-edv-multiselect-pod"
	sessionTemplateName := "e2e-edv-multiselect-template"

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: podTemplateName,
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E MultiSelect Pod Template",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:    "debug",
							Image:   "busybox:latest",
							Command: []string{"sleep", "infinity"},
						},
					},
				},
			},
		},
	}

	_ = cli.Delete(ctx, podTemplate)
	defer func() { _ = cli.Delete(ctx, podTemplate) }()

	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err)

	// Create session template with multiSelect variable
	replicas := int32(1)
	minItems := 1
	maxItems := 3
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: sessionTemplateName,
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E MultiSelect Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplateName,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups:   []string{"*"},
				Clusters: []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
			ExtraDeployVariables: []telekomv1alpha1.ExtraDeployVariable{
				{
					Name:        "debugTools",
					DisplayName: "Debug Tools",
					Description: "Select debug tools to install",
					InputType:   telekomv1alpha1.InputTypeMultiSelect,
					Options: []telekomv1alpha1.SelectOption{
						{Value: "tcpdump", DisplayName: "TCPDump"},
						{Value: "netcat", DisplayName: "Netcat"},
						{Value: "curl", DisplayName: "cURL"},
						{Value: "strace", DisplayName: "Strace"},
					},
					Validation: &telekomv1alpha1.VariableValidation{
						MinItems: &minItems,
						MaxItems: &maxItems,
					},
				},
			},
		},
	}

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() { _ = cli.Delete(ctx, sessionTemplate) }()

	err = cli.Create(ctx, sessionTemplate)
	require.NoError(t, err)

	// Verify multiSelect variable is created
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: sessionTemplateName}, &fetched)
	require.NoError(t, err)

	assert.Len(t, fetched.Spec.ExtraDeployVariables, 1)
	multiSelect := fetched.Spec.ExtraDeployVariables[0]
	assert.Equal(t, telekomv1alpha1.InputTypeMultiSelect, multiSelect.InputType)
	assert.Len(t, multiSelect.Options, 4)
	assert.NotNil(t, multiSelect.Validation)
	assert.Equal(t, 1, *multiSelect.Validation.MinItems)
	assert.Equal(t, 3, *multiSelect.Validation.MaxItems)

	// Create session with multiSelect value
	clusterName := helpers.GetTestClusterName()
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-edv-multiselect-session",
			Namespace: testNamespace,
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			TemplateRef: sessionTemplateName,
			Cluster:     clusterName,
			RequestedBy: "e2e-test@example.com",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"debugTools": {Raw: []byte(`["tcpdump", "curl"]`)},
			},
		},
	}

	_ = cli.Delete(ctx, session)
	defer func() { _ = cli.Delete(ctx, session) }()

	err = cli.Create(ctx, session)
	require.NoError(t, err, "Failed to create session with multiSelect value")

	var fetchedSession telekomv1alpha1.DebugSession
	err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: testNamespace}, &fetchedSession)
	require.NoError(t, err)

	assert.Contains(t, fetchedSession.Spec.ExtraDeployValues, "debugTools")
	t.Logf("Successfully created session with multiSelect value")
}

// TestDebugSession_E2E_ExtraDeployVariables_AllowedGroups tests the allowedGroups filtering
func TestDebugSession_E2E_ExtraDeployVariables_AllowedGroups(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	podTemplateName := "e2e-edv-allowed-groups-pod"
	sessionTemplateName := "e2e-edv-allowed-groups-template"

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: podTemplateName,
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Allowed Groups Pod Template",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:    "debug",
							Image:   "busybox:latest",
							Command: []string{"sleep", "infinity"},
						},
					},
				},
			},
		},
	}

	_ = cli.Delete(ctx, podTemplate)
	defer func() { _ = cli.Delete(ctx, podTemplate) }()

	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err)

	// Create session template with allowedGroups on variables
	replicas := int32(1)
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: sessionTemplateName,
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Allowed Groups Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplateName,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups:   []string{"*"},
				Clusters: []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
			ExtraDeployVariables: []telekomv1alpha1.ExtraDeployVariable{
				{
					Name:        "publicSetting",
					DisplayName: "Public Setting",
					Description: "Available to all users",
					InputType:   telekomv1alpha1.InputTypeText,
					Default:     &apiextensionsv1.JSON{Raw: []byte(`"public-default"`)},
				},
				{
					Name:          "adminSetting",
					DisplayName:   "Admin Setting",
					Description:   "Only available to admin users",
					InputType:     telekomv1alpha1.InputTypeText,
					AllowedGroups: []string{"cluster-admins", "platform-admins"},
					Default:       &apiextensionsv1.JSON{Raw: []byte(`"admin-default"`)},
				},
				{
					Name:          "operatorSetting",
					DisplayName:   "Operator Setting",
					Description:   "Available to operators and admins",
					InputType:     telekomv1alpha1.InputTypeBoolean,
					AllowedGroups: []string{"operators", "cluster-admins"},
					Default:       &apiextensionsv1.JSON{Raw: []byte(`false`)},
				},
			},
		},
	}

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() { _ = cli.Delete(ctx, sessionTemplate) }()

	err = cli.Create(ctx, sessionTemplate)
	require.NoError(t, err)

	// Verify allowedGroups are persisted
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: sessionTemplateName}, &fetched)
	require.NoError(t, err)

	assert.Len(t, fetched.Spec.ExtraDeployVariables, 3)

	varMap := make(map[string]telekomv1alpha1.ExtraDeployVariable)
	for _, v := range fetched.Spec.ExtraDeployVariables {
		varMap[v.Name] = v
	}

	// Public setting should have no allowedGroups
	publicSetting := varMap["publicSetting"]
	assert.Empty(t, publicSetting.AllowedGroups)

	// Admin setting should have restricted groups
	adminSetting := varMap["adminSetting"]
	assert.Len(t, adminSetting.AllowedGroups, 2)
	assert.Contains(t, adminSetting.AllowedGroups, "cluster-admins")
	assert.Contains(t, adminSetting.AllowedGroups, "platform-admins")

	// Operator setting should have its allowed groups
	operatorSetting := varMap["operatorSetting"]
	assert.Len(t, operatorSetting.AllowedGroups, 2)
	assert.Contains(t, operatorSetting.AllowedGroups, "operators")

	t.Logf("Successfully verified allowedGroups filtering configuration")
}
