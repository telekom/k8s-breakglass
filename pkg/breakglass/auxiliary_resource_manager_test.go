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

package breakglass

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func newTestAuxiliaryResourceManager() *AuxiliaryResourceManager {
	logger := zap.NewNop().Sugar()
	return NewAuxiliaryResourceManager(logger, nil)
}

func TestNewAuxiliaryResourceManager(t *testing.T) {
	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, nil)

	assert.NotNil(t, mgr)
	assert.NotNil(t, mgr.log)
	assert.Nil(t, mgr.client) // client can be nil
}

func TestFilterEnabledResources_NoneEnabledByDefault(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	template := &v1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []v1alpha1.AuxiliaryResource{
			{Name: "netpol", Category: "network"},
			{Name: "rbac", Category: "rbac"},
		},
		// No defaults, required categories, or binding overrides
		AuxiliaryResourceDefaults: map[string]bool{},
	}

	enabled := mgr.filterEnabledResources(template, nil, nil)
	assert.Len(t, enabled, 0, "No resources should be enabled when no defaults are set")
}

func TestFilterEnabledResources_EnabledByDefault(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	template := &v1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []v1alpha1.AuxiliaryResource{
			{Name: "netpol", Category: "network"},
			{Name: "rbac", Category: "rbac"},
		},
		AuxiliaryResourceDefaults: map[string]bool{
			"netpol": true,
			"rbac":   false,
		},
	}

	enabled := mgr.filterEnabledResources(template, nil, nil)
	require.Len(t, enabled, 1)
	assert.Equal(t, "netpol", enabled[0].Name)
}

func TestFilterEnabledResources_RequiredCategory(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	template := &v1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []v1alpha1.AuxiliaryResource{
			{Name: "netpol", Category: "network-isolation"},
			{Name: "rbac", Category: "rbac"},
		},
		RequiredAuxiliaryResourceCategories: []string{"network-isolation"},
	}

	enabled := mgr.filterEnabledResources(template, nil, nil)
	require.Len(t, enabled, 1)
	assert.Equal(t, "netpol", enabled[0].Name)
}

func TestFilterEnabledResources_BindingOverrideEnables(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	template := &v1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []v1alpha1.AuxiliaryResource{
			{Name: "netpol", Category: "network"},
		},
	}

	binding := &v1alpha1.DebugSessionClusterBinding{
		Spec: v1alpha1.DebugSessionClusterBindingSpec{
			AuxiliaryResourceOverrides: map[string]bool{
				"network": true,
			},
		},
	}

	enabled := mgr.filterEnabledResources(template, binding, nil)
	require.Len(t, enabled, 1)
	assert.Equal(t, "netpol", enabled[0].Name)
}

func TestFilterEnabledResources_BindingCannotDisableRequired(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	template := &v1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []v1alpha1.AuxiliaryResource{
			{Name: "netpol", Category: "network-isolation"},
		},
		RequiredAuxiliaryResourceCategories: []string{"network-isolation"},
	}

	binding := &v1alpha1.DebugSessionClusterBinding{
		Spec: v1alpha1.DebugSessionClusterBindingSpec{
			AuxiliaryResourceOverrides: map[string]bool{
				"network-isolation": false, // Attempt to disable required category
			},
		},
	}

	enabled := mgr.filterEnabledResources(template, binding, nil)
	require.Len(t, enabled, 1, "Required category should not be disabled")
	assert.Equal(t, "netpol", enabled[0].Name)
}

func TestFilterEnabledResources_UserSelection(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	template := &v1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []v1alpha1.AuxiliaryResource{
			{Name: "netpol", Category: "network"},
			{Name: "monitoring", Category: "monitoring"},
		},
	}

	enabled := mgr.filterEnabledResources(template, nil, []string{"netpol"})
	require.Len(t, enabled, 1)
	assert.Equal(t, "netpol", enabled[0].Name)
}

func TestFilterEnabledResources_NilTemplate(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	enabled := mgr.filterEnabledResources(nil, nil, nil)
	assert.Nil(t, enabled)
}

func TestBuildRenderContext(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	session := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: v1alpha1.DebugSessionSpec{
			RequestedBy: "user@example.com",
			Cluster:     "prod-cluster",
			Reason:      "Debugging issue",
			TemplateRef: "test-template",
		},
	}

	template := &v1alpha1.DebugSessionTemplateSpec{
		DisplayName: "Test Template",
	}

	binding := &v1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-binding",
			Namespace: "team-a",
		},
	}

	ctx := mgr.buildRenderContext(session, template, binding, "target-ns")

	assert.Equal(t, "test-session", ctx.Session.Name)
	assert.Equal(t, "target-ns", ctx.Target.Namespace)
	assert.Equal(t, "prod-cluster", ctx.Target.ClusterName)
	assert.Equal(t, "Test Template", ctx.Template.DisplayName)
	assert.Equal(t, "test-binding", ctx.Binding.Name)
}

func TestRenderTemplate_SimpleTemplate(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	ctx := v1alpha1.AuxiliaryResourceContext{
		Session: v1alpha1.AuxiliaryResourceSessionContext{
			Name:   "debug-123",
			Reason: "test reason",
		},
		Target: v1alpha1.AuxiliaryResourceTargetContext{
			Namespace: "debug-ns",
		},
	}

	// Use lowercase JSON field names because toMap converts via JSON marshaling
	tmpl := []byte(`name: "debug-{{ .session.name }}-policy"
namespace: "{{ .target.namespace }}"`)

	result, err := mgr.renderTemplate(tmpl, ctx)
	require.NoError(t, err)

	assert.Contains(t, string(result), `name: "debug-debug-123-policy"`)
	assert.Contains(t, string(result), `namespace: "debug-ns"`)
}

func TestRenderTemplate_WithSprigFunctions(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	ctx := v1alpha1.AuxiliaryResourceContext{
		Session: v1alpha1.AuxiliaryResourceSessionContext{
			Name: "debug-session-abc123",
		},
	}

	// Use lowercase JSON field names
	tmpl := []byte(`upper: "{{ .session.name | upper }}"
truncated: "{{ .session.name | trunc 10 }}"
default: "{{ .session.reason | default "no-reason" }}"`)

	result, err := mgr.renderTemplate(tmpl, ctx)
	require.NoError(t, err)

	assert.Contains(t, string(result), `upper: "DEBUG-SESSION-ABC123"`)
	assert.Contains(t, string(result), `truncated: "debug-sess"`)
	assert.Contains(t, string(result), `default: "no-reason"`)
}

func TestRenderTemplate_InvalidTemplate(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	ctx := v1alpha1.AuxiliaryResourceContext{}

	// Invalid template syntax
	tmpl := []byte(`{{ .session.name | unknownFunction }}`)

	_, err := mgr.renderTemplate(tmpl, ctx)
	assert.Error(t, err)
}

func TestRenderTemplate_MissingField(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	ctx := v1alpha1.AuxiliaryResourceContext{
		Session: v1alpha1.AuxiliaryResourceSessionContext{},
	}

	// Use lowercase JSON field names
	tmpl := []byte(`name: "{{ .session.name }}"
namespace: "{{ .target.namespace }}"`)

	result, err := mgr.renderTemplate(tmpl, ctx)
	require.NoError(t, err)
	assert.Contains(t, string(result), `name: ""`)
}

func TestDeployAuxiliaryResources_NilTemplate(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	session := &v1alpha1.DebugSession{}

	statuses, err := mgr.DeployAuxiliaryResources(
		context.Background(),
		session,
		nil, // nil template
		nil,
		nil,
		"target-ns",
	)

	assert.NoError(t, err)
	assert.Nil(t, statuses)
}

func TestDeployAuxiliaryResources_EmptyResources(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	session := &v1alpha1.DebugSession{}
	template := &v1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []v1alpha1.AuxiliaryResource{},
	}

	statuses, err := mgr.DeployAuxiliaryResources(
		context.Background(),
		session,
		template,
		nil,
		nil,
		"target-ns",
	)

	assert.NoError(t, err)
	assert.Nil(t, statuses)
}

func TestCleanupAuxiliaryResources_NoResources(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	session := &v1alpha1.DebugSession{
		Status: v1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []v1alpha1.AuxiliaryResourceStatus{},
		},
	}

	err := mgr.CleanupAuxiliaryResources(context.Background(), session, nil)
	assert.NoError(t, err)
}

func TestCleanupAuxiliaryResources_AlreadyDeleted(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	session := &v1alpha1.DebugSession{
		Status: v1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []v1alpha1.AuxiliaryResourceStatus{
				{
					Name:    "netpol",
					Created: true,
					Deleted: true, // Already deleted
				},
			},
		},
	}

	err := mgr.CleanupAuxiliaryResources(context.Background(), session, nil)
	assert.NoError(t, err)
}

func TestAddAuxiliaryResourceToDeployedResources(t *testing.T) {
	session := &v1alpha1.DebugSession{
		Status: v1alpha1.DebugSessionStatus{
			DeployedResources: []v1alpha1.DeployedResourceRef{},
		},
	}

	status := v1alpha1.AuxiliaryResourceStatus{
		Name:         "netpol",
		Created:      true,
		APIVersion:   "networking.k8s.io/v1",
		Kind:         "NetworkPolicy",
		ResourceName: "debug-netpol",
		Namespace:    "debug-ns",
	}

	AddAuxiliaryResourceToDeployedResources(session, status)

	require.Len(t, session.Status.DeployedResources, 1)
	assert.Equal(t, "NetworkPolicy", session.Status.DeployedResources[0].Kind)
	assert.Equal(t, "debug-netpol", session.Status.DeployedResources[0].Name)
	assert.Equal(t, "debug-ns", session.Status.DeployedResources[0].Namespace)
	assert.Equal(t, "auxiliary:netpol", session.Status.DeployedResources[0].Source)
}

func TestAddAuxiliaryResourceToDeployedResources_NotCreated(t *testing.T) {
	session := &v1alpha1.DebugSession{
		Status: v1alpha1.DebugSessionStatus{
			DeployedResources: []v1alpha1.DeployedResourceRef{},
		},
	}

	status := v1alpha1.AuxiliaryResourceStatus{
		Name:    "netpol",
		Created: false, // Not created
	}

	AddAuxiliaryResourceToDeployedResources(session, status)

	assert.Len(t, session.Status.DeployedResources, 0, "Should not add resources that weren't created")
}

func TestAddAuxiliaryResourceToDeployedResources_Deduplication(t *testing.T) {
	session := &v1alpha1.DebugSession{
		Status: v1alpha1.DebugSessionStatus{
			DeployedResources: []v1alpha1.DeployedResourceRef{
				{
					Kind:      "NetworkPolicy",
					Name:      "debug-netpol",
					Namespace: "debug-ns",
				},
			},
		},
	}

	status := v1alpha1.AuxiliaryResourceStatus{
		Name:         "netpol",
		Created:      true,
		Kind:         "NetworkPolicy",
		ResourceName: "debug-netpol",
		Namespace:    "debug-ns",
	}

	AddAuxiliaryResourceToDeployedResources(session, status)

	assert.Len(t, session.Status.DeployedResources, 1, "Should not add duplicates")
}

func TestValidateAuxiliaryResources_ValidTemplate(t *testing.T) {
	auxResources := []v1alpha1.AuxiliaryResource{
		{
			Name:     "netpol",
			Category: "network",
			Template: runtime.RawExtension{Raw: []byte(`{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"test"}}`)},
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	assert.Empty(t, errs)
}

func TestValidateAuxiliaryResources_MissingName(t *testing.T) {
	auxResources := []v1alpha1.AuxiliaryResource{
		{
			Name:     "", // Missing name
			Category: "network",
			Template: runtime.RawExtension{Raw: []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"test"}}`)},
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Error(), "name is required")
}

func TestValidateAuxiliaryResources_MissingTemplate(t *testing.T) {
	auxResources := []v1alpha1.AuxiliaryResource{
		{
			Name:     "test",
			Category: "network",
			Template: runtime.RawExtension{}, // Missing template
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Error(), "template is required")
}

func TestValidateAuxiliaryResources_DuplicateNames(t *testing.T) {
	auxResources := []v1alpha1.AuxiliaryResource{
		{
			Name:     "same-name",
			Category: "network",
			Template: runtime.RawExtension{Raw: []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"test"}}`)},
		},
		{
			Name:     "same-name", // Duplicate
			Category: "rbac",
			Template: runtime.RawExtension{Raw: []byte(`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"test"}}`)},
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Error(), "duplicate")
}

func TestValidateAuxiliaryResources_MissingAPIVersionInTemplate(t *testing.T) {
	auxResources := []v1alpha1.AuxiliaryResource{
		{
			Name:     "test",
			Category: "network",
			Template: runtime.RawExtension{Raw: []byte(`{"kind":"ConfigMap","metadata":{"name":"test"}}`)},
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Error(), "apiVersion")
}

func TestValidateAuxiliaryResources_MissingKindInTemplate(t *testing.T) {
	auxResources := []v1alpha1.AuxiliaryResource{
		{
			Name:     "test",
			Category: "network",
			Template: runtime.RawExtension{Raw: []byte(`{"apiVersion":"v1","metadata":{"name":"test"}}`)},
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Error(), "kind")
}

func TestDeployResource_ConfigMap(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: v1alpha1.DebugSessionSpec{
			Cluster:     "prod",
			TemplateRef: "test-template",
		},
	}

	// Use lowercase JSON field names in template
	auxRes := v1alpha1.AuxiliaryResource{
		Name:     "test-config",
		Category: "configmap",
		Template: runtime.RawExtension{Raw: []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: "debug-{{ .session.name }}-config"
data:
  key: value`)},
		CreateBefore: true,
	}

	renderCtx := v1alpha1.AuxiliaryResourceContext{
		Session: v1alpha1.AuxiliaryResourceSessionContext{
			Name:      "test-session",
			Namespace: "breakglass-system",
			Cluster:   "prod",
		},
		Target: v1alpha1.AuxiliaryResourceTargetContext{
			Namespace:   "debug-ns",
			ClusterName: "prod",
		},
		Labels:      map[string]string{},
		Annotations: map[string]string{},
	}

	status, err := mgr.deployResource(
		context.Background(),
		fakeClient,
		"debug-ns",
		auxRes,
		renderCtx,
		session,
	)

	require.NoError(t, err)
	assert.True(t, status.Created)
	assert.Equal(t, "test-config", status.Name)
	assert.Equal(t, "ConfigMap", status.Kind)
	assert.Equal(t, "debug-test-session-config", status.ResourceName)
}
