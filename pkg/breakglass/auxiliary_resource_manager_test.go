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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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

	enabledResources := []v1alpha1.AuxiliaryResource{
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
	assert.Contains(t, errs[0].Error(), "either template or templateString is required")
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
	ctx := v1alpha1.AuxiliaryResourceContext{}

	result, err := mgr.renderTemplate([]byte(""), ctx)
	require.NoError(t, err)
	assert.Equal(t, "", string(result))
}

func TestRenderTemplate_NilTemplate(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	ctx := v1alpha1.AuxiliaryResourceContext{}

	result, err := mgr.renderTemplate(nil, ctx)
	require.NoError(t, err)
	assert.Equal(t, "", string(result))
}

func TestRenderTemplate_MalformedBraces(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	ctx := v1alpha1.AuxiliaryResourceContext{}

	// Unclosed template braces
	tmpl := []byte(`name: "{{ .session.name"`)

	_, err := mgr.renderTemplate(tmpl, ctx)
	assert.Error(t, err, "malformed template should fail")
}

func TestRenderTemplate_NestedInvalidSyntax(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	ctx := v1alpha1.AuxiliaryResourceContext{}

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
	template := &v1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []v1alpha1.AuxiliaryResource{
			{Name: "res1", Category: "cat1", Template: runtime.RawExtension{}},
			{Name: "res2", Category: "cat2", Template: runtime.RawExtension{}},
		},
	}
	binding := &v1alpha1.DebugSessionClusterBinding{
		Spec: v1alpha1.DebugSessionClusterBindingSpec{
			RequiredAuxiliaryResourceCategories: []string{"cat1"},
		},
	}
	result := mgr.filterEnabledResources(template, binding, nil)
	assert.Len(t, result, 1, "binding required category should be included")
	assert.Equal(t, "res1", result[0].Name)
}

func TestFilterEnabledResources_DefaultEnabled(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	template := &v1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []v1alpha1.AuxiliaryResource{
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
	template := &v1alpha1.DebugSessionTemplateSpec{
		RequiredAuxiliaryResourceCategories: []string{"security"},
		AuxiliaryResources: []v1alpha1.AuxiliaryResource{
			{Name: "net-policy", Category: "security", Template: runtime.RawExtension{}},
		},
	}
	result := mgr.filterEnabledResources(template, nil, nil)
	assert.Len(t, result, 1, "nil binding should not affect required categories")
}

func TestFilterEnabledResources_EmptySelectedByUser(t *testing.T) {
	mgr := newTestAuxiliaryResourceManager()
	template := &v1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources: []v1alpha1.AuxiliaryResource{
			{Name: "res1", Category: "optional", Template: runtime.RawExtension{}},
		},
	}
	result := mgr.filterEnabledResources(template, nil, []string{})
	assert.Empty(t, result, "empty user selection should not include optional resources")
}

func TestValidateAuxiliaryResources_ValidTemplateString(t *testing.T) {
	auxResources := []v1alpha1.AuxiliaryResource{
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
	auxResources := []v1alpha1.AuxiliaryResource{
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
	auxResources := []v1alpha1.AuxiliaryResource{
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
	auxResources := []v1alpha1.AuxiliaryResource{
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
		session  *v1alpha1.DebugSession
		template *v1alpha1.DebugSessionTemplateSpec
		expected map[string]string
	}{
		{
			name: "no variables",
			session: &v1alpha1.DebugSession{
				Spec: v1alpha1.DebugSessionSpec{},
			},
			template: &v1alpha1.DebugSessionTemplateSpec{},
			expected: map[string]string{},
		},
		{
			name: "user provided values",
			session: &v1alpha1.DebugSession{
				Spec: v1alpha1.DebugSessionSpec{
					ExtraDeployValues: map[string]apiextensionsv1.JSON{
						"pvcSize":      {Raw: []byte(`"50Gi"`)},
						"createPvc":    {Raw: []byte(`true`)},
						"replicaCount": {Raw: []byte(`3`)},
					},
				},
			},
			template: &v1alpha1.DebugSessionTemplateSpec{},
			expected: map[string]string{
				"pvcSize":      "50Gi",
				"createPvc":    "true",
				"replicaCount": "3",
			},
		},
		{
			name: "defaults from template",
			session: &v1alpha1.DebugSession{
				Spec: v1alpha1.DebugSessionSpec{},
			},
			template: &v1alpha1.DebugSessionTemplateSpec{
				ExtraDeployVariables: []v1alpha1.ExtraDeployVariable{
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
			session: &v1alpha1.DebugSession{
				Spec: v1alpha1.DebugSessionSpec{
					ExtraDeployValues: map[string]apiextensionsv1.JSON{
						"pvcSize": {Raw: []byte(`"100Gi"`)}, // Override default
					},
				},
			},
			template: &v1alpha1.DebugSessionTemplateSpec{
				ExtraDeployVariables: []v1alpha1.ExtraDeployVariable{
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

	session := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: v1alpha1.DebugSessionSpec{
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

	template := &v1alpha1.DebugSessionTemplateSpec{
		DisplayName: "Test Template",
		ExtraDeployVariables: []v1alpha1.ExtraDeployVariable{
			{Name: "pvcSize", Default: &apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)}},
			{Name: "region", Default: &apiextensionsv1.JSON{Raw: []byte(`"eu-west-1"`)}},
		},
	}

	enabledResources := []v1alpha1.AuxiliaryResource{
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
