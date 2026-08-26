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

	controller := &DebugSessionController{}
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

func TestResidualResourceIdentitiesIncludesUID(t *testing.T) {
	got := residualResourceIdentities([]breakglassv1alpha1.DeployedResourceRef{{
		Kind: "PersistentVolumeClaim", Name: "debug-data", Namespace: "debug", UID: "uid-1",
	}})
	assert.Equal(t, "debug/PersistentVolumeClaim/debug-data (uid=uid-1)", got)
}
