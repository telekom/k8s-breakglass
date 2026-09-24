// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	kptr "k8s.io/utils/ptr"

	"github.com/stretchr/testify/require"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	"sigs.k8s.io/yaml"
)

func TestAuxiliaryLifecycleFlagsSurviveDefaultedSnapshotRoundTrip(t *testing.T) {
	for _, crdName := range []string{"debugsessiontemplates", "debugsessions"} {
		t.Run(crdName, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(crdBasesDir(), "breakglass.t-caas.telekom.com_"+crdName+".yaml"))
			require.NoError(t, err)
			var crd apiextensionsv1.CustomResourceDefinition
			require.NoError(t, yaml.Unmarshal(data, &crd))
			properties := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties
			parent := properties["spec"]
			if crdName == "debugsessions" {
				parent = properties["status"].Properties["resolvedTemplate"]
			}
			resourceSchema := parent.Properties["auxiliaryResources"].Items.Schema
			require.NotNil(t, resourceSchema)
			var internal apiextensions.JSONSchemaProps
			require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(resourceSchema, &internal, nil))
			structural, err := structuralschema.NewStructural(&internal)
			require.NoError(t, err)
			for _, tc := range []struct {
				name string
				raw  string
				want bool
			}{
				{"omitted defaults true", `{"name":"policy","template":null}`, true},
				{"explicit false stays false", `{"name":"policy","template":null,"createBefore":false,"deleteAfter":false}`, false},
				{"explicit true stays true", `{"name":"policy","createBefore":true,"deleteAfter":true}`, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var object map[string]interface{}
					require.NoError(t, json.Unmarshal([]byte(tc.raw), &object))
					defaulting.Default(object, structural)
					wire, err := json.Marshal(object)
					require.NoError(t, err)
					var typed AuxiliaryResource
					require.NoError(t, json.Unmarshal(wire, &typed))
					// The controller copies this typed value into resolvedTemplate,
					// serializes status, then the API applies the same CRD defaults.
					wire, err = json.Marshal(typed)
					require.NoError(t, err)
					object = nil
					require.NoError(t, json.Unmarshal(wire, &object))
					defaulting.Default(object, structural)
					require.Equal(t, tc.want, object["createBefore"])
					require.Equal(t, tc.want, object["deleteAfter"])
				})
			}
		})
	}
}

func TestAuxiliaryLifecycleFlagsTypedPresence(t *testing.T) {
	omitted, err := json.Marshal(AuxiliaryResource{Name: "policy"})
	require.NoError(t, err)
	require.JSONEq(t, `{"name":"policy","template":null}`, string(omitted))

	explicit, err := json.Marshal(AuxiliaryResource{Name: "policy", CreateBefore: kptr.To(false), DeleteAfter: kptr.To(false)})
	require.NoError(t, err)
	require.JSONEq(t, `{"name":"policy","template":null,"createBefore":false,"deleteAfter":false}`, string(explicit))
}
