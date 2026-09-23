// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestApplyUnstructuredPolicyExceptionHTTP(t *testing.T) {
	gvk := schema.GroupVersionKind{Group: "policies.kyverno.io", Version: "v1", Kind: "PolicyException"}
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{gvk.GroupVersion()})
	mapper.Add(gvk, meta.RESTScopeNamespace)
	var stored map[string]interface{}
	patches := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/apis/policies.kyverno.io/v1/namespaces/t-caas-security/policyexceptions/debug-session", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && stored == nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}`))
			return
		}
		if r.Method == http.MethodPatch {
			patches++
			require.Equal(t, "application/apply-patch+yaml", r.Header.Get("Content-Type"))
			require.Equal(t, FieldOwnerController, r.URL.Query().Get("fieldManager"))
			require.Equal(t, "true", r.URL.Query().Get("force"))
			require.NoError(t, json.NewDecoder(r.Body).Decode(&stored))
			require.Equal(t, gvk.GroupVersion().String(), stored["apiVersion"])
			require.Equal(t, gvk.Kind, stored["kind"])
			stored["metadata"].(map[string]interface{})["managedFields"] = []interface{}{map[string]interface{}{
				"manager": FieldOwnerController, "operation": "Apply", "apiVersion": gvk.GroupVersion().String(), "fieldsType": "FieldsV1",
				"fieldsV1": map[string]interface{}{"f:spec": map[string]interface{}{"f:policyRefs": map[string]interface{}{}}},
			}}
		} else {
			require.Equal(t, http.MethodGet, r.Method)
		}
		require.NoError(t, json.NewEncoder(w).Encode(stored))
	}))
	defer server.Close()
	c, err := client.New(&rest.Config{Host: server.URL}, client.Options{Mapper: mapper})
	require.NoError(t, err)
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": gvk.GroupVersion().String(), "kind": gvk.Kind,
		"metadata": map[string]interface{}{"name": "debug-session", "namespace": "t-caas-security"},
		"spec":     map[string]interface{}{"policyRefs": []interface{}{map[string]interface{}{"name": "reviewed-policy", "kind": "ValidatingPolicy"}}},
	}}
	result, err := PatchApplyUnstructured(context.Background(), c, obj)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultCreated, result)
	require.Equal(t, 1, patches)
	result, err = PatchApplyUnstructured(context.Background(), c, obj)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultSkipped, result)
	require.Equal(t, 1, patches)
	require.NoError(t, unstructured.SetNestedSlice(obj.Object, []interface{}{map[string]interface{}{"name": "second-reviewed-policy", "kind": "ValidatingPolicy"}}, "spec", "policyRefs"))
	result, err = PatchApplyUnstructured(context.Background(), c, obj)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultPatched, result)
	require.Equal(t, 2, patches)
}
