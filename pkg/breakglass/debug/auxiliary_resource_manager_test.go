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

package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
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

func TestSetAuditManager(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	// Initially nil
	assert.Nil(t, mgr.auditManager)

	// After setting - note: we can't create a real audit.Manager without dependencies
	// so we're testing that the method exists and can be called
	mgr.SetAuditManager(nil) // SetAuditManager(nil) should work
	assert.Nil(t, mgr.auditManager)
}

func TestFilterEnabledResources_NoneEnabledByDefault(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{
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

	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{
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

	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{
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

	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{
			{Name: "netpol", Category: "network"},
		},
	}

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
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

	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{
			{Name: "netpol", Category: "network-isolation"},
		},
		RequiredAuxiliaryResourceCategories: []string{"network-isolation"},
	}

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
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

	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{
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

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			RequestedBy: "user@example.com",
			Cluster:     "prod-cluster",
			Reason:      "Debugging issue",
			TemplateRef: "test-template",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		DisplayName: "Test Template",
	}

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-binding",
			Namespace: "team-a",
		},
	}

	enabledResources := []breakglassv1alpha1.AuxiliaryResource{
		{Name: "resource-1", Category: "network"},
	}

	ctx := mgr.buildRenderContext(session, template, binding, "target-ns", enabledResources)

	assert.Equal(t, "test-session", ctx.Session.Name)
	assert.Equal(t, "target-ns", ctx.Target.Namespace)
	assert.Equal(t, "prod-cluster", ctx.Target.ClusterName)
	assert.Equal(t, "Test Template", ctx.Template.DisplayName)
	assert.Equal(t, "test-binding", ctx.Binding.Name)
	assert.Contains(t, ctx.EnabledResources, "resource-1")
	assert.NotEmpty(t, ctx.Now)
}

func TestRenderTemplate_SimpleTemplate(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	ctx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name:   "debug-123",
			Reason: "test reason",
		},
		Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
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

	ctx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
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

	ctx := breakglassv1alpha1.AuxiliaryResourceContext{}

	// Invalid template syntax
	tmpl := []byte(`{{ .session.name | unknownFunction }}`)

	_, err := mgr.renderTemplate(tmpl, ctx)
	assert.Error(t, err)
}

func TestRenderTemplate_MissingField(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	ctx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{},
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

	session := &breakglassv1alpha1.DebugSession{}

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

	session := &breakglassv1alpha1.DebugSession{}
	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{},
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

	session := &breakglassv1alpha1.DebugSession{
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{},
		},
	}

	err := mgr.CleanupAuxiliaryResources(context.Background(), session, nil)
	assert.NoError(t, err)
}

func TestCleanupAuxiliaryResources_AlreadyDeleted(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	session := &breakglassv1alpha1.DebugSession{
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
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
	session := &breakglassv1alpha1.DebugSession{
		Status: breakglassv1alpha1.DebugSessionStatus{
			DeployedResources: []breakglassv1alpha1.DeployedResourceRef{},
		},
	}

	status := breakglassv1alpha1.AuxiliaryResourceStatus{
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
	session := &breakglassv1alpha1.DebugSession{
		Status: breakglassv1alpha1.DebugSessionStatus{
			DeployedResources: []breakglassv1alpha1.DeployedResourceRef{},
		},
	}

	status := breakglassv1alpha1.AuxiliaryResourceStatus{
		Name:    "netpol",
		Created: false, // Not created
	}

	AddAuxiliaryResourceToDeployedResources(session, status)

	assert.Len(t, session.Status.DeployedResources, 0, "Should not add resources that weren't created")
}

func TestAddAuxiliaryResourceToDeployedResources_Deduplication(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		Status: breakglassv1alpha1.DebugSessionStatus{
			DeployedResources: []breakglassv1alpha1.DeployedResourceRef{
				{
					Kind:      "NetworkPolicy",
					Name:      "debug-netpol",
					Namespace: "debug-ns",
				},
			},
		},
	}

	status := breakglassv1alpha1.AuxiliaryResourceStatus{
		Name:         "netpol",
		Created:      true,
		Kind:         "NetworkPolicy",
		ResourceName: "debug-netpol",
		Namespace:    "debug-ns",
	}

	AddAuxiliaryResourceToDeployedResources(session, status)

	assert.Len(t, session.Status.DeployedResources, 1, "Should not add duplicates")
}

func TestAddAuxiliaryResourceToDeployedResources_WithAdditionalResources(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		Status: breakglassv1alpha1.DebugSessionStatus{
			DeployedResources: []breakglassv1alpha1.DeployedResourceRef{},
		},
	}

	// Status with additional resources from multi-document YAML
	status := breakglassv1alpha1.AuxiliaryResourceStatus{
		Name:         "network-bundle",
		Category:     "network",
		Created:      true,
		Kind:         "NetworkPolicy",
		APIVersion:   "networking.k8s.io/v1",
		ResourceName: "debug-netpol",
		Namespace:    "debug-ns",
		AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{
			{
				Kind:         "ServiceAccount",
				APIVersion:   "v1",
				ResourceName: "debug-sa",
				Namespace:    "debug-ns",
			},
			{
				Kind:         "Role",
				APIVersion:   "rbac.authorization.k8s.io/v1",
				ResourceName: "debug-role",
				Namespace:    "debug-ns",
			},
		},
	}

	AddAuxiliaryResourceToDeployedResources(session, status)

	// Should have 3 resources: primary + 2 additional
	require.Len(t, session.Status.DeployedResources, 3)

	// Verify primary resource
	assert.Equal(t, "NetworkPolicy", session.Status.DeployedResources[0].Kind)
	assert.Equal(t, "debug-netpol", session.Status.DeployedResources[0].Name)
	assert.Equal(t, "auxiliary:network-bundle", session.Status.DeployedResources[0].Source)

	// Verify additional resources
	assert.Equal(t, "ServiceAccount", session.Status.DeployedResources[1].Kind)
	assert.Equal(t, "debug-sa", session.Status.DeployedResources[1].Name)
	assert.Equal(t, "auxiliary:network-bundle", session.Status.DeployedResources[1].Source)

	assert.Equal(t, "Role", session.Status.DeployedResources[2].Kind)
	assert.Equal(t, "debug-role", session.Status.DeployedResources[2].Name)
	assert.Equal(t, "auxiliary:network-bundle", session.Status.DeployedResources[2].Source)
}

func TestValidateAuxiliaryResources_ValidTemplate(t *testing.T) {
	auxResources := []breakglassv1alpha1.AuxiliaryResource{
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
	auxResources := []breakglassv1alpha1.AuxiliaryResource{
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
	auxResources := []breakglassv1alpha1.AuxiliaryResource{
		{
			Name:     "test",
			Category: "network",
			Template: runtime.RawExtension{}, // Missing template
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Error(), "either template or templateString is required")
}

func TestValidateAuxiliaryResources_ValidWithTemplateObject(t *testing.T) {
	// Test that Template.Object is accepted as an alternative to Template.Raw
	// runtime.RawExtension can have either Raw or Object set
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-config",
		},
	}

	auxResources := []breakglassv1alpha1.AuxiliaryResource{
		{
			Name:     "test",
			Category: "config",
			Template: runtime.RawExtension{Object: cm},
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	assert.Empty(t, errs, "should accept Template.Object as valid")
}

func TestValidateAuxiliaryResources_ValidWithTemplateString(t *testing.T) {
	// Test that templateString is accepted
	auxResources := []breakglassv1alpha1.AuxiliaryResource{
		{
			Name:           "test",
			Category:       "config",
			TemplateString: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Session.Name }}-config",
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	assert.Empty(t, errs, "should accept templateString as valid")
}

func TestValidateAuxiliaryResources_DuplicateNames(t *testing.T) {
	auxResources := []breakglassv1alpha1.AuxiliaryResource{
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
	auxResources := []breakglassv1alpha1.AuxiliaryResource{
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
	auxResources := []breakglassv1alpha1.AuxiliaryResource{
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
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "prod",
			TemplateRef: "test-template",
		},
	}

	// Use lowercase JSON field names in template
	auxRes := breakglassv1alpha1.AuxiliaryResource{
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

	renderCtx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name:      "test-session",
			Namespace: "breakglass-system",
			Cluster:   "prod",
		},
		Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
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

func TestDeployResource_WithTemplateObject(t *testing.T) {
	// Test that Template.Object is correctly handled when deploying auxiliary resources
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "prod",
			TemplateRef: "test-template",
		},
	}

	// Create a ConfigMap as the Template.Object
	// Note: The template will be rendered as-is (no Go templating for Object)
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-object-config",
		},
		Data: map[string]string{
			"key": "value",
		},
	}

	auxRes := breakglassv1alpha1.AuxiliaryResource{
		Name:         "test-object",
		Category:     "configmap",
		Template:     runtime.RawExtension{Object: cm},
		CreateBefore: true,
	}

	renderCtx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name:      "test-session",
			Namespace: "breakglass-system",
			Cluster:   "prod",
		},
		Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
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
	assert.Equal(t, "test-object", status.Name)
	assert.Equal(t, "ConfigMap", status.Kind)
	assert.Equal(t, "test-object-config", status.ResourceName)
}

func TestDeployResource_MultiDocumentYAML(t *testing.T) {
	// Test that multi-document YAML templates correctly track all resources
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "prod",
			TemplateRef: "test-template",
		},
	}

	// Multi-document YAML template
	multiDocTemplate := `apiVersion: v1
kind: ConfigMap
metadata:
  name: config-1
data:
  key1: value1
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-2
data:
  key2: value2
---
apiVersion: v1
kind: Secret
metadata:
  name: secret-1
type: Opaque
stringData:
  password: test123`

	auxRes := breakglassv1alpha1.AuxiliaryResource{
		Name:           "multi-resource",
		Category:       "config",
		TemplateString: multiDocTemplate,
		CreateBefore:   true,
	}

	renderCtx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name:      "test-session",
			Namespace: "breakglass-system",
			Cluster:   "prod",
		},
		Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
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

	// Primary resource should be first document
	assert.Equal(t, "multi-resource", status.Name)
	assert.Equal(t, "ConfigMap", status.Kind)
	assert.Equal(t, "config-1", status.ResourceName)

	// Additional resources should be tracked
	require.Len(t, status.AdditionalResources, 2, "Should have 2 additional resources from multi-doc YAML")

	// Second document
	assert.Equal(t, "ConfigMap", status.AdditionalResources[0].Kind)
	assert.Equal(t, "config-2", status.AdditionalResources[0].ResourceName)
	assert.Equal(t, "debug-ns", status.AdditionalResources[0].Namespace)

	// Third document
	assert.Equal(t, "Secret", status.AdditionalResources[1].Kind)
	assert.Equal(t, "secret-1", status.AdditionalResources[1].ResourceName)
	assert.Equal(t, "debug-ns", status.AdditionalResources[1].Namespace)
}

func TestCleanupAuxiliaryResources_WithAdditionalResources(t *testing.T) {
	// Test that cleanup deletes additional resources from multi-document YAML
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	// Create the resources that will be cleaned up
	cm1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config-1",
			Namespace: "debug-ns",
		},
	}
	cm2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config-2",
			Namespace: "debug-ns",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm1, cm2).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "prod",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "multi-resource",
					Category:     "config",
					Created:      true,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "config-1",
					Namespace:    "debug-ns",
					AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{
						{
							Kind:         "ConfigMap",
							APIVersion:   "v1",
							ResourceName: "config-2",
							Namespace:    "debug-ns",
						},
					},
				},
			},
		},
	}

	err := mgr.CleanupAuxiliaryResources(context.Background(), session, fakeClient)
	require.NoError(t, err)

	// Verify primary resource deletion was tracked
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].Deleted)

	// Verify additional resource deletion was tracked
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].Deleted)

	// Verify resources are actually deleted
	err = fakeClient.Get(context.Background(), client.ObjectKey{Name: "config-1", Namespace: "debug-ns"}, &corev1.ConfigMap{})
	assert.True(t, apierrors.IsNotFound(err), "config-1 should be deleted")

	err = fakeClient.Get(context.Background(), client.ObjectKey{Name: "config-2", Namespace: "debug-ns"}, &corev1.ConfigMap{})
	assert.True(t, apierrors.IsNotFound(err), "config-2 should be deleted")
}

// ============================================================================
// Tests for toMap helper function
// ============================================================================

func TestToMap_ValidStruct(t *testing.T) {
	input := struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{
		Name:  "test",
		Value: 42,
	}

	result, err := toMap(input)
	require.NoError(t, err)
	assert.Equal(t, "test", result["name"])
	assert.Equal(t, float64(42), result["value"]) // JSON numbers become float64
}

func TestToMap_NestedStruct(t *testing.T) {
	input := struct {
		Outer string `json:"outer"`
		Inner struct {
			Name string `json:"name"`
		} `json:"inner"`
	}{
		Outer: "outer-value",
		Inner: struct {
			Name string `json:"name"`
		}{Name: "inner-name"},
	}

	result, err := toMap(input)
	require.NoError(t, err)
	assert.Equal(t, "outer-value", result["outer"])
	inner, ok := result["inner"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "inner-name", inner["name"])
}

func TestToMap_EmptyStruct(t *testing.T) {
	input := struct{}{}

	result, err := toMap(input)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

// ============================================================================
// Edge Case and Failure Tests for toMap
// ============================================================================

func TestToMap_NilInput(t *testing.T) {
	result, err := toMap(nil)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestToMap_ChannelFailsToMarshal(t *testing.T) {
	// Channels cannot be marshaled to JSON
	ch := make(chan int)
	_, err := toMap(ch)
	assert.Error(t, err, "channels should fail to marshal")
}

func TestToMap_FuncFailsToMarshal(t *testing.T) {
	// Functions cannot be marshaled to JSON
	fn := func() {}
	_, err := toMap(fn)
	assert.Error(t, err, "functions should fail to marshal")
}

// ============================================================================
// Edge Case Tests for RenderTemplate
// ============================================================================

func TestRenderTemplate_EmptyTemplate(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	ctx := breakglassv1alpha1.AuxiliaryResourceContext{}

	result, err := mgr.renderTemplate([]byte(""), ctx)
	require.NoError(t, err)
	assert.Equal(t, "", string(result))
}

func TestRenderTemplate_NilTemplate(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	ctx := breakglassv1alpha1.AuxiliaryResourceContext{}

	result, err := mgr.renderTemplate(nil, ctx)
	require.NoError(t, err)
	assert.Equal(t, "", string(result))
}

func TestRenderTemplate_MalformedBraces(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	ctx := breakglassv1alpha1.AuxiliaryResourceContext{}

	// Unclosed template braces
	tmpl := []byte(`name: "{{ .session.name"`)

	_, err := mgr.renderTemplate(tmpl, ctx)
	assert.Error(t, err, "malformed template should fail")
}

func TestRenderTemplate_NestedInvalidSyntax(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	ctx := breakglassv1alpha1.AuxiliaryResourceContext{}

	// Invalid nesting
	tmpl := []byte(`{{ if .session.name }}{{ end {{ end }}`)

	_, err := mgr.renderTemplate(tmpl, ctx)
	assert.Error(t, err, "invalid nesting should fail")
}

// ============================================================================
// Additional Edge Case Tests for FilterEnabledResources
// ============================================================================

func TestFilterEnabledResources_BindingAddsRequiredCategory(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{
			{Name: "res1", Category: "cat1", Template: runtime.RawExtension{}},
			{Name: "res2", Category: "cat2", Template: runtime.RawExtension{}},
		},
	}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			RequiredAuxiliaryResourceCategories: []string{"cat1"},
		},
	}
	result := mgr.filterEnabledResources(template, binding, nil)
	assert.Len(t, result, 1, "binding required category should be included")
	assert.Equal(t, "res1", result[0].Name)
}

func TestFilterEnabledResources_DefaultEnabled(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{
			{Name: "res1", Category: "cat1", Template: runtime.RawExtension{}},
			{Name: "res2", Category: "cat2", Template: runtime.RawExtension{}},
		},
		AuxiliaryResourceDefaults: map[string]bool{
			"res1": true,
			"res2": false,
		},
	}
	result := mgr.filterEnabledResources(template, nil, nil)
	assert.Len(t, result, 1, "only default-enabled resource should be included")
	assert.Equal(t, "res1", result[0].Name)
}

func TestFilterEnabledResources_NilBinding(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		RequiredAuxiliaryResourceCategories: []string{"security"},
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{
			{Name: "net-policy", Category: "security", Template: runtime.RawExtension{}},
		},
	}
	result := mgr.filterEnabledResources(template, nil, nil)
	assert.Len(t, result, 1, "nil binding should not affect required categories")
}

func TestFilterEnabledResources_EmptySelectedByUser(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{
			{Name: "res1", Category: "optional", Template: runtime.RawExtension{}},
		},
	}
	result := mgr.filterEnabledResources(template, nil, []string{})
	assert.Empty(t, result, "empty user selection should not include optional resources")
}

func TestValidateAuxiliaryResources_ValidTemplateString(t *testing.T) {
	auxResources := []breakglassv1alpha1.AuxiliaryResource{
		{
			Name:     "test-pvc",
			Category: "storage",
			TemplateString: `apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: test-{{ .session.name }}
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi`,
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	assert.Empty(t, errs, "valid templateString should not produce errors")
}

func TestValidateAuxiliaryResources_TemplateStringWithMultiDoc(t *testing.T) {
	auxResources := []breakglassv1alpha1.AuxiliaryResource{
		{
			Name:     "test-resources",
			Category: "storage",
			TemplateString: `apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: test-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
data:
  key: value`,
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	assert.Empty(t, errs, "multi-document templateString should be valid")
}

func TestValidateAuxiliaryResources_InvalidTemplateStringSyntax(t *testing.T) {
	auxResources := []breakglassv1alpha1.AuxiliaryResource{
		{
			Name:     "test-invalid",
			Category: "storage",
			TemplateString: `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .session.name`, // Unclosed action
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Error(), "invalid templateString")
}

func TestValidateAuxiliaryResources_MutuallyExclusiveTemplates(t *testing.T) {
	auxResources := []breakglassv1alpha1.AuxiliaryResource{
		{
			Name:           "test-both",
			Category:       "storage",
			Template:       runtime.RawExtension{Raw: []byte(`{"apiVersion":"v1","kind":"ConfigMap"}`)},
			TemplateString: `apiVersion: v1\nkind: Secret`,
		},
	}

	errs := ValidateAuxiliaryResources(auxResources)
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Error(), "mutually exclusive")
}

func TestBuildVarsFromSession(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	tests := []struct {
		name     string
		session  *breakglassv1alpha1.DebugSession
		template *breakglassv1alpha1.DebugSessionTemplateSpec
		expected map[string]string
	}{
		{
			name: "no variables",
			session: &breakglassv1alpha1.DebugSession{
				Spec: breakglassv1alpha1.DebugSessionSpec{},
			},
			template: &breakglassv1alpha1.DebugSessionTemplateSpec{},
			expected: map[string]string{},
		},
		{
			name: "user provided values",
			session: &breakglassv1alpha1.DebugSession{
				Spec: breakglassv1alpha1.DebugSessionSpec{
					ExtraDeployValues: map[string]apiextensionsv1.JSON{
						"pvcSize":      {Raw: []byte(`"50Gi"`)},
						"createPvc":    {Raw: []byte(`true`)},
						"replicaCount": {Raw: []byte(`3`)},
					},
				},
			},
			template: &breakglassv1alpha1.DebugSessionTemplateSpec{},
			expected: map[string]string{
				"pvcSize":      "50Gi",
				"createPvc":    "true",
				"replicaCount": "3",
			},
		},
		{
			name: "defaults from template",
			session: &breakglassv1alpha1.DebugSession{
				Spec: breakglassv1alpha1.DebugSessionSpec{},
			},
			template: &breakglassv1alpha1.DebugSessionTemplateSpec{
				ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariable{
					{Name: "pvcSize", Default: &apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)}},
					{Name: "enabled", Default: &apiextensionsv1.JSON{Raw: []byte(`false`)}},
				},
			},
			expected: map[string]string{
				"pvcSize": "10Gi",
				"enabled": "false",
			},
		},
		{
			name: "user values override defaults",
			session: &breakglassv1alpha1.DebugSession{
				Spec: breakglassv1alpha1.DebugSessionSpec{
					ExtraDeployValues: map[string]apiextensionsv1.JSON{
						"pvcSize": {Raw: []byte(`"100Gi"`)}, // Override default
					},
				},
			},
			template: &breakglassv1alpha1.DebugSessionTemplateSpec{
				ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariable{
					{Name: "pvcSize", Default: &apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)}},
					{Name: "enabled", Default: &apiextensionsv1.JSON{Raw: []byte(`true`)}},
				},
			},
			expected: map[string]string{
				"pvcSize": "100Gi",
				"enabled": "true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mgr.buildVarsFromSession(tt.session, tt.template)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractJSONValue(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "string value",
			input:    []byte(`"hello world"`),
			expected: "hello world",
		},
		{
			name:     "boolean true",
			input:    []byte(`true`),
			expected: "true",
		},
		{
			name:     "boolean false",
			input:    []byte(`false`),
			expected: "false",
		},
		{
			name:     "integer",
			input:    []byte(`42`),
			expected: "42",
		},
		{
			name:     "float",
			input:    []byte(`3.14`),
			expected: "3.14",
		},
		{
			name:     "string array",
			input:    []byte(`["a","b","c"]`),
			expected: "a,b,c",
		},
		{
			name:     "empty string",
			input:    []byte(`""`),
			expected: "",
		},
		{
			name:     "empty input",
			input:    []byte{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractJSONValue(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildRenderContext_VarsAndMetadata(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "prod-cluster",
			RequestedBy: "user@example.com",
			Reason:      "Testing",
			TemplateRef: "test-template",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"pvcSize":      {Raw: []byte(`"50Gi"`)},
				"storageClass": {Raw: []byte(`"fast-storage"`)},
			},
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		DisplayName: "Test Template",
		ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariable{
			{Name: "pvcSize", Default: &apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)}},
			{Name: "region", Default: &apiextensionsv1.JSON{Raw: []byte(`"eu-west-1"`)}},
		},
	}

	enabledResources := []breakglassv1alpha1.AuxiliaryResource{
		{Name: "pvc"},
		{Name: "config"},
	}

	ctx := mgr.buildRenderContext(session, template, nil, "target-ns", enabledResources)

	// Verify Vars
	assert.Equal(t, "50Gi", ctx.Vars["pvcSize"]) // User override
	assert.Equal(t, "fast-storage", ctx.Vars["storageClass"])
	assert.Equal(t, "eu-west-1", ctx.Vars["region"]) // Default value

	// Verify EnabledResources
	assert.Contains(t, ctx.EnabledResources, "pvc")
	assert.Contains(t, ctx.EnabledResources, "config")

	// Verify Now is set
	assert.NotEmpty(t, ctx.Now)
}

func TestCheckAuxiliaryResourcesReadiness_NoResources(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	session := &breakglassv1alpha1.DebugSession{
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: nil, // No resources
		},
	}

	allReady, err := mgr.CheckAuxiliaryResourcesReadiness(context.Background(), session, nil)

	require.NoError(t, err)
	assert.True(t, allReady)
}

func TestCheckAuxiliaryResourcesReadiness_AlreadyReady(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	readyAt := "2024-01-01T00:00:00Z"
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "test-cm",
					Created:      true,
					Ready:        true,
					ReadyAt:      &readyAt,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "test-cm",
					Namespace:    "default",
				},
			},
		},
	}

	allReady, err := mgr.CheckAuxiliaryResourcesReadiness(context.Background(), session, nil)

	require.NoError(t, err)
	assert.True(t, allReady)
}

func TestCheckAuxiliaryResourcesReadiness_NotCreated(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:    "test-cm",
					Created: false, // Not created
				},
			},
		},
	}

	allReady, err := mgr.CheckAuxiliaryResourcesReadiness(context.Background(), session, nil)

	require.NoError(t, err)
	assert.True(t, allReady) // Not created resources don't block readiness
}

func TestCheckAuxiliaryResourcesReadiness_Deleted(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()

	deletedAt := "2024-01-01T00:00:00Z"
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "test-cm",
					Created:      true,
					Ready:        false,
					Deleted:      true,
					DeletedAt:    &deletedAt,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "test-cm",
					Namespace:    "default",
				},
			},
		},
	}

	allReady, err := mgr.CheckAuxiliaryResourcesReadiness(context.Background(), session, nil)

	require.NoError(t, err)
	assert.True(t, allReady) // Deleted resources don't block readiness
}

func TestCheckAuxiliaryResourcesReadiness_ConfigMapReady(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Create a ConfigMap in the fake client
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cm",
			Namespace: "default",
		},
		Data: map[string]string{
			"key": "value",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	mgr := newTestAuxiliaryResourceManager()
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "test-cm",
					Created:      true,
					Ready:        false,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "test-cm",
					Namespace:    "default",
				},
			},
		},
	}

	allReady, err := mgr.CheckAuxiliaryResourcesReadiness(ctx, session, fakeClient)

	require.NoError(t, err)
	assert.True(t, allReady)

	// Verify status was updated
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].Ready)
	assert.NotNil(t, session.Status.AuxiliaryResourceStatuses[0].ReadyAt)
	assert.Equal(t, "Current", session.Status.AuxiliaryResourceStatuses[0].ReadinessStatus)
}

func TestCheckAuxiliaryResourcesReadiness_ResourceNotFound(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Empty fake client - resource doesn't exist
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	mgr := newTestAuxiliaryResourceManager()
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "missing-cm",
					Created:      true,
					Ready:        false,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "missing-cm",
					Namespace:    "default",
				},
			},
		},
	}

	allReady, err := mgr.CheckAuxiliaryResourcesReadiness(ctx, session, fakeClient)

	require.NoError(t, err)
	assert.False(t, allReady)

	// Status should show NotFound
	assert.False(t, session.Status.AuxiliaryResourceStatuses[0].Ready)
	assert.Equal(t, "NotFound", session.Status.AuxiliaryResourceStatuses[0].ReadinessStatus)
}

func TestCheckAuxiliaryResourcesReadiness_MixedStates(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Create one ConfigMap
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ready-cm",
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	mgr := newTestAuxiliaryResourceManager()
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "ready-cm",
					Created:      true,
					Ready:        false,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "ready-cm",
					Namespace:    "default",
				},
				{
					Name:         "missing-cm",
					Created:      true,
					Ready:        false,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "missing-cm",
					Namespace:    "default",
				},
			},
		},
	}

	allReady, err := mgr.CheckAuxiliaryResourcesReadiness(ctx, session, fakeClient)

	require.NoError(t, err)
	assert.False(t, allReady) // One resource is not found

	// First should be ready
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].Ready)
	assert.Equal(t, "Current", session.Status.AuxiliaryResourceStatuses[0].ReadinessStatus)

	// Second should be not found
	assert.False(t, session.Status.AuxiliaryResourceStatuses[1].Ready)
	assert.Equal(t, "NotFound", session.Status.AuxiliaryResourceStatuses[1].ReadinessStatus)
}

func TestParseGVK(t *testing.T) {
	tests := []struct {
		name          string
		apiVersion    string
		kind          string
		expectedGroup string
		expectedVer   string
		expectedKind  string
		expectError   bool
	}{
		{
			name:          "core v1 resource",
			apiVersion:    "v1",
			kind:          "ConfigMap",
			expectedGroup: "",
			expectedVer:   "v1",
			expectedKind:  "ConfigMap",
		},
		{
			name:          "apps/v1 resource",
			apiVersion:    "apps/v1",
			kind:          "Deployment",
			expectedGroup: "apps",
			expectedVer:   "v1",
			expectedKind:  "Deployment",
		},
		{
			name:          "custom resource",
			apiVersion:    "breakglass.t-caas.telekom.com/v1alpha1",
			kind:          "DebugSession",
			expectedGroup: "breakglass.t-caas.telekom.com",
			expectedVer:   "v1alpha1",
			expectedKind:  "DebugSession",
		},
		{
			name:          "batch/v1 resource",
			apiVersion:    "batch/v1",
			kind:          "Job",
			expectedGroup: "batch",
			expectedVer:   "v1",
			expectedKind:  "Job",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gvk, err := parseGVK(tt.apiVersion, tt.kind)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedGroup, gvk.Group)
			assert.Equal(t, tt.expectedVer, gvk.Version)
			assert.Equal(t, tt.expectedKind, gvk.Kind)
		})
	}
}

// ============================================================================
// Multi-Document YAML Edge Cases and Failure Handling Tests
// ============================================================================

func TestDeployResource_MultiDocumentYAML_EmptyDocuments(t *testing.T) {
	// Test that empty documents (whitespace only) are skipped
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "prod",
			TemplateRef: "test-template",
		},
	}

	// Template with empty documents (only whitespace between separators)
	multiDocWithEmpty := `apiVersion: v1
kind: ConfigMap
metadata:
  name: config-1
data:
  key1: value1
---

---
   
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-2
data:
  key2: value2`

	auxRes := breakglassv1alpha1.AuxiliaryResource{
		Name:           "empty-doc-test",
		Category:       "config",
		TemplateString: multiDocWithEmpty,
		CreateBefore:   true,
	}

	renderCtx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name:      "test-session",
			Namespace: "breakglass-system",
			Cluster:   "prod",
		},
		Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
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

	// Should only have 2 resources (empty documents should be skipped)
	assert.Equal(t, "ConfigMap", status.Kind)
	assert.Equal(t, "config-1", status.ResourceName)
	require.Len(t, status.AdditionalResources, 1, "Should skip empty documents")
	assert.Equal(t, "config-2", status.AdditionalResources[0].ResourceName)
}

func TestDeployResource_MultiDocumentYAML_InvalidSecondDocument(t *testing.T) {
	// Test failure when second document is invalid YAML
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "prod",
			TemplateRef: "test-template",
		},
	}

	// Second document has invalid YAML (indentation error)
	invalidSecondDoc := `apiVersion: v1
kind: ConfigMap
metadata:
  name: valid-config
data:
  key1: value1
---
apiVersion: v1
kind: ConfigMap
metadata:
name: invalid - no indentation
  nested: wrong`

	auxRes := breakglassv1alpha1.AuxiliaryResource{
		Name:           "invalid-doc-test",
		Category:       "config",
		TemplateString: invalidSecondDoc,
		CreateBefore:   true,
	}

	renderCtx := breakglassv1alpha1.AuxiliaryResourceContext{
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

	// Should fail on second document
	require.Error(t, err)
	assert.Contains(t, err.Error(), "doc 2")
	assert.Contains(t, status.Error, "YAML parsing failed")
}

func TestDeployResource_MultiDocumentYAML_ConditionalAllExcluded(t *testing.T) {
	// Test when all documents are conditionally excluded
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "prod",
			TemplateRef: "test-template",
		},
	}

	// All documents are conditionally excluded
	conditionalTemplate := `{{- if eq .vars.createConfig "true" }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-1
{{- end }}
---
{{- if eq .vars.createSecret "true" }}
apiVersion: v1
kind: Secret
metadata:
  name: secret-1
{{- end }}`

	auxRes := breakglassv1alpha1.AuxiliaryResource{
		Name:           "conditional-test",
		Category:       "config",
		TemplateString: conditionalTemplate,
		CreateBefore:   true,
	}

	renderCtx := breakglassv1alpha1.AuxiliaryResourceContext{
		Vars: map[string]string{
			"createConfig": "false",
			"createSecret": "false",
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

	// Should succeed but not create anything
	require.NoError(t, err)
	assert.False(t, status.Created, "Should not be created when all documents are excluded")
	assert.Empty(t, status.Kind)
	assert.Empty(t, status.ResourceName)
	assert.Empty(t, status.AdditionalResources)
}

func TestDeployResource_MultiDocumentYAML_PartialConditional(t *testing.T) {
	// Test when some documents are conditionally excluded
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "prod",
			TemplateRef: "test-template",
		},
	}

	// First and third documents included, second excluded
	conditionalTemplate := `apiVersion: v1
kind: ConfigMap
metadata:
  name: config-always
data:
  key: value
---
{{- if eq .vars.createOptional "true" }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-optional
{{- end }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-also-always
data:
  key: value`

	auxRes := breakglassv1alpha1.AuxiliaryResource{
		Name:           "partial-conditional-test",
		Category:       "config",
		TemplateString: conditionalTemplate,
		CreateBefore:   true,
	}

	renderCtx := breakglassv1alpha1.AuxiliaryResourceContext{
		Vars: map[string]string{
			"createOptional": "false",
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

	// Should have primary + 1 additional (skipping the excluded one)
	assert.Equal(t, "config-always", status.ResourceName)
	require.Len(t, status.AdditionalResources, 1, "Should skip conditionally excluded document")
	assert.Equal(t, "config-also-always", status.AdditionalResources[0].ResourceName)
}

func TestDeployResource_NoTemplateDefinedError(t *testing.T) {
	// Test error when neither templateString nor template is defined
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "prod",
		},
	}

	// No template defined
	auxRes := breakglassv1alpha1.AuxiliaryResource{
		Name:     "no-template",
		Category: "config",
		// Neither TemplateString nor Template is set
	}

	renderCtx := breakglassv1alpha1.AuxiliaryResourceContext{}

	status, err := mgr.deployResource(
		context.Background(),
		fakeClient,
		"debug-ns",
		auxRes,
		renderCtx,
		session,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no template defined")
	assert.Contains(t, status.Error, "no template defined")
}

func TestDeployResource_TemplateRenderingError(t *testing.T) {
	// Test error when template rendering fails
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "prod",
		},
	}

	// Invalid template syntax
	auxRes := breakglassv1alpha1.AuxiliaryResource{
		Name:           "bad-template",
		Category:       "config",
		TemplateString: `{{ .invalid.syntax | unknownFunc }}`, // unknownFunc doesn't exist
	}

	renderCtx := breakglassv1alpha1.AuxiliaryResourceContext{}

	status, err := mgr.deployResource(
		context.Background(),
		fakeClient,
		"debug-ns",
		auxRes,
		renderCtx,
		session,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "templateString")
	assert.Contains(t, status.Error, "template rendering failed")
}

func TestCleanupAuxiliaryResources_PartialFailure(t *testing.T) {
	// Test cleanup when deleting one resource fails but others succeed
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	// Only create config-1 (config-2 and config-3 will fail to delete because they don't exist)
	// But NotFound errors are handled gracefully
	cm1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config-1",
			Namespace: "debug-ns",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm1).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "prod",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "multi-resource",
					Category:     "config",
					Created:      true,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "config-1",
					Namespace:    "debug-ns",
					AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{
						{
							Kind:         "ConfigMap",
							APIVersion:   "v1",
							ResourceName: "config-2", // Doesn't exist
							Namespace:    "debug-ns",
						},
						{
							Kind:         "ConfigMap",
							APIVersion:   "v1",
							ResourceName: "config-3", // Doesn't exist
							Namespace:    "debug-ns",
						},
					},
				},
			},
		},
	}

	// Cleanup should handle missing resources gracefully (NotFound is not an error)
	err := mgr.CleanupAuxiliaryResources(context.Background(), session, fakeClient)
	require.NoError(t, err, "NotFound errors should be handled gracefully")

	// All should be marked as deleted
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].Deleted)
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].Deleted)
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[1].Deleted)
}

func TestCleanupAuxiliaryResources_SkipsAlreadyDeleted(t *testing.T) {
	// Test that cleanup skips resources already marked as deleted
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	deletedAt := "2024-01-01T00:00:00Z"
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "prod",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "already-deleted",
					Category:     "config",
					Created:      true,
					Deleted:      true, // Already deleted
					DeletedAt:    &deletedAt,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "config-1",
					Namespace:    "debug-ns",
					AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{
						{
							Kind:         "ConfigMap",
							APIVersion:   "v1",
							ResourceName: "config-2",
							Namespace:    "debug-ns",
							Deleted:      true, // Already deleted
						},
					},
				},
			},
		},
	}

	err := mgr.CleanupAuxiliaryResources(context.Background(), session, fakeClient)
	require.NoError(t, err)

	// Should remain marked as deleted with original timestamp
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].Deleted)
	assert.Equal(t, &deletedAt, session.Status.AuxiliaryResourceStatuses[0].DeletedAt)
}

func TestCheckAuxiliaryResourcesReadiness_WithAdditionalResources_AllReady(t *testing.T) {
	// Test readiness checking when all additional resources are ready
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Create all ConfigMaps
	cm1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config-1",
			Namespace: "default",
		},
	}
	cm2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config-2",
			Namespace: "default",
		},
	}
	cm3 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config-3",
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm1, cm2, cm3).
		Build()

	mgr := newTestAuxiliaryResourceManager()
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "multi-resource",
					Created:      true,
					Ready:        false,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "config-1",
					Namespace:    "default",
					AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{
						{
							Kind:         "ConfigMap",
							APIVersion:   "v1",
							ResourceName: "config-2",
							Namespace:    "default",
						},
						{
							Kind:         "ConfigMap",
							APIVersion:   "v1",
							ResourceName: "config-3",
							Namespace:    "default",
						},
					},
				},
			},
		},
	}

	allReady, err := mgr.CheckAuxiliaryResourcesReadiness(ctx, session, fakeClient)

	require.NoError(t, err)
	assert.True(t, allReady)

	// Primary should be ready
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].Ready)
	assert.Equal(t, "Current", session.Status.AuxiliaryResourceStatuses[0].ReadinessStatus)

	// Additional resources should be ready
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].Ready)
	assert.Equal(t, "Current", session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].ReadinessStatus)
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[1].Ready)
	assert.Equal(t, "Current", session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[1].ReadinessStatus)
}

func TestCheckAuxiliaryResourcesReadiness_WithAdditionalResources_SomeNotReady(t *testing.T) {
	// Test readiness checking when some additional resources are not found
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Only create config-1 (config-2 doesn't exist)
	cm1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config-1",
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm1).
		Build()

	mgr := newTestAuxiliaryResourceManager()
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "multi-resource",
					Created:      true,
					Ready:        false,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "config-1",
					Namespace:    "default",
					AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{
						{
							Kind:         "ConfigMap",
							APIVersion:   "v1",
							ResourceName: "config-2", // Doesn't exist
							Namespace:    "default",
						},
					},
				},
			},
		},
	}

	allReady, err := mgr.CheckAuxiliaryResourcesReadiness(ctx, session, fakeClient)

	require.NoError(t, err)
	assert.False(t, allReady, "Should not be ready when additional resource is missing")

	// Primary should be ready
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].Ready)
	assert.Equal(t, "Current", session.Status.AuxiliaryResourceStatuses[0].ReadinessStatus)

	// Additional resource should not be ready
	assert.False(t, session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].Ready)
	assert.Equal(t, "NotFound", session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].ReadinessStatus)
}

func TestCheckAuxiliaryResourcesReadiness_AdditionalResourceAlreadyDeleted(t *testing.T) {
	// Test readiness checking when additional resource is marked as deleted
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	mgr := newTestAuxiliaryResourceManager()
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "multi-resource",
					Created:      true,
					Ready:        true,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "config-1",
					Namespace:    "default",
					AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{
						{
							Kind:         "ConfigMap",
							APIVersion:   "v1",
							ResourceName: "config-2",
							Namespace:    "default",
							Deleted:      true, // Already deleted - should be skipped
						},
					},
				},
			},
		},
	}

	allReady, err := mgr.CheckAuxiliaryResourcesReadiness(ctx, session, fakeClient)

	require.NoError(t, err)
	assert.True(t, allReady, "Deleted additional resources should not block readiness")
}

func TestDeployResource_MultiDocumentYAML_DifferentKinds(t *testing.T) {
	// Test multi-document with different resource kinds
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "prod",
			TemplateRef: "test-template",
		},
	}

	// Multi-document with ServiceAccount, ConfigMap, and Secret
	multiKindTemplate := `apiVersion: v1
kind: ServiceAccount
metadata:
  name: debug-sa
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: debug-config
data:
  key: value
---
apiVersion: v1
kind: Secret
metadata:
  name: debug-secret
type: Opaque
stringData:
  password: secret123`

	auxRes := breakglassv1alpha1.AuxiliaryResource{
		Name:           "multi-kind-test",
		Category:       "rbac",
		TemplateString: multiKindTemplate,
		CreateBefore:   true,
	}

	renderCtx := breakglassv1alpha1.AuxiliaryResourceContext{
		Labels:      map[string]string{"test": "label"},
		Annotations: map[string]string{"test": "annotation"},
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

	// Primary resource
	assert.Equal(t, "ServiceAccount", status.Kind)
	assert.Equal(t, "debug-sa", status.ResourceName)

	// Additional resources with different kinds
	require.Len(t, status.AdditionalResources, 2)
	assert.Equal(t, "ConfigMap", status.AdditionalResources[0].Kind)
	assert.Equal(t, "debug-config", status.AdditionalResources[0].ResourceName)
	assert.Equal(t, "Secret", status.AdditionalResources[1].Kind)
	assert.Equal(t, "debug-secret", status.AdditionalResources[1].ResourceName)

	// Verify all have the same namespace
	assert.Equal(t, "debug-ns", status.Namespace)
	assert.Equal(t, "debug-ns", status.AdditionalResources[0].Namespace)
	assert.Equal(t, "debug-ns", status.AdditionalResources[1].Namespace)
}
