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

package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCleanupDeployedResources_GenericInventory(t *testing.T) {
	scheme := testScheme()
	session := newTestDebugSession("cleanup-generic", "template", "cluster", "user@example.com")
	resources := []struct {
		apiVersion string
		kind       string
		name       string
		namespace  string
	}{
		{apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", name: "debug-policy", namespace: "debug"},
		{apiVersion: "v1", kind: "PersistentVolumeClaim", name: "debug-data", namespace: "debug"},
		{apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role", name: "debug-role", namespace: "debug"},
		{apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", name: "debug-binding", namespace: "debug"},
	}
	objects := make([]*unstructured.Unstructured, 0, len(resources))
	for _, resource := range resources {
		object := &unstructured.Unstructured{}
		object.SetAPIVersion(resource.apiVersion)
		object.SetKind(resource.kind)
		object.SetName(resource.name)
		object.SetNamespace(resource.namespace)
		objects = append(objects, object)
		session.Status.DeployedResources = append(session.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
			APIVersion: resource.apiVersion,
			Kind:       resource.kind,
			Name:       resource.name,
			Namespace:  resource.namespace,
			Source:     "pod-template",
		})
	}
	targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		objects[0], objects[1], objects[2], objects[3],
	).Build()

	controller := &DebugSessionController{log: zap.NewNop().Sugar()}
	err := controller.cleanupDeployedResources(context.Background(), session, targetClient, false, false)
	require.NoError(t, err)
	assert.Empty(t, session.Status.DeployedResources)
	for _, resource := range resources {
		object := &unstructured.Unstructured{}
		object.SetAPIVersion(resource.apiVersion)
		object.SetKind(resource.kind)
		err = targetClient.Get(context.Background(), types.NamespacedName{Name: resource.name, Namespace: resource.namespace}, object)
		assert.Error(t, err)
	}
}

func TestMergeDeployedResourceRefsPreservesConcurrentInventoryAndUID(t *testing.T) {
	current := []breakglassv1alpha1.DeployedResourceRef{{
		APIVersion: "v1", Kind: "Pod", Name: "existing", Namespace: "debug", UID: "current-uid",
	}}
	desired := []breakglassv1alpha1.DeployedResourceRef{
		{APIVersion: "v1", Kind: "Pod", Name: "existing", Namespace: "debug", UID: "stale-uid"},
		{APIVersion: "v1", Kind: "ConfigMap", Name: "new", Namespace: "debug", UID: "new-uid"},
	}

	merged := mergeDeployedResourceRefs(current, desired)
	require.Len(t, merged, 2)
	assert.Equal(t, "current-uid", merged[0].UID, "a concurrent authoritative UID must win")
	assert.Equal(t, "new-uid", merged[1].UID)
}

func TestMergeCleanupStatusTrackersPreservesConcurrentEntries(t *testing.T) {
	auxiliary := mergeAuxiliaryResourceStatuses(
		[]breakglassv1alpha1.AuxiliaryResourceStatus{{Name: "concurrent", ResourceName: "one"}},
		[]breakglassv1alpha1.AuxiliaryResourceStatus{{Name: "local", ResourceName: "two"}},
	)
	require.Len(t, auxiliary, 2)

	podTemplate := mergePodTemplateResourceStatuses(
		[]breakglassv1alpha1.PodTemplateResourceStatus{{APIVersion: "v1", Kind: "ConfigMap", ResourceName: "concurrent"}},
		[]breakglassv1alpha1.PodTemplateResourceStatus{{APIVersion: "v1", Kind: "ConfigMap", ResourceName: "local"}},
	)
	require.Len(t, podTemplate, 2)
}

func TestCleanupDeployedResourcesRetainsAuxiliaryRefWithoutStatusMetadata(t *testing.T) {
	session := newTestDebugSession("cleanup-unknown-aux", "template", "cluster", "user@example.com")
	session.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{{
		APIVersion: "v1", Kind: "ConfigMap", Name: "unknown", Namespace: "debug", Source: "auxiliary:unknown",
	}}
	targetClient := fake.NewClientBuilder().WithScheme(testScheme()).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	err := controller.cleanupDeployedResources(context.Background(), session, targetClient, false, false)
	require.Error(t, err)
	require.Len(t, session.Status.DeployedResources, 1)
	assert.Contains(t, err.Error(), "missing auxiliary cleanup status")
}

func TestAddDeployedResourceIfMissingFillsUIDInStatusSlice(t *testing.T) {
	status := &breakglassv1alpha1.DebugSessionStatus{
		DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
			APIVersion: "v1", Kind: "Pod", Name: "debug", Namespace: "default",
		}},
	}
	addDeployedResourceIfMissing(status, breakglassv1alpha1.DeployedResourceRef{
		APIVersion: "v1", Kind: "Pod", Name: "debug", Namespace: "default", UID: "pod-uid",
	})
	require.Len(t, status.DeployedResources, 1)
	assert.Equal(t, "pod-uid", status.DeployedResources[0].UID)
}

func TestAddAuxiliaryResourceToDeployedResourcesFromClientCapturesUID(t *testing.T) {
	object := &unstructured.Unstructured{}
	object.SetAPIVersion("v1")
	object.SetKind("ConfigMap")
	object.SetName("debug-config")
	object.SetNamespace("debug")
	object.SetUID(types.UID("config-uid"))
	targetClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(object).Build()
	session := newTestDebugSession("cleanup-aux-uid", "template", "cluster", "user@example.com")

	AddAuxiliaryResourceToDeployedResourcesFromClient(context.Background(), targetClient, session,
		breakglassv1alpha1.AuxiliaryResourceStatus{
			Name: "config", Created: true, APIVersion: "v1", Kind: "ConfigMap",
			ResourceName: "debug-config", Namespace: "debug",
		})

	require.Len(t, session.Status.DeployedResources, 1)
	assert.Equal(t, "config-uid", session.Status.DeployedResources[0].UID)
}

func TestResidualResourceIdentitiesIncludesUID(t *testing.T) {
	got := residualResourceIdentities([]breakglassv1alpha1.DeployedResourceRef{{
		Kind: "PersistentVolumeClaim", Name: "debug-data", Namespace: "debug", UID: "uid-1",
	}})
	assert.Equal(t, "debug/PersistentVolumeClaim/debug-data (uid=uid-1)", got)
}
