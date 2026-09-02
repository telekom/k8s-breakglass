// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"encoding/json"
	"testing"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestTemplateVarsPreservedBeforeSerialization(t *testing.T) {
	for _, value := range []string{"registry/image:v1", "alice@example.com", "a,b", "worker-1\nhostNetwork: true", "---\nfoo", "a\u2028b"} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		session := &breakglassv1alpha1.DebugSession{Spec: breakglassv1alpha1.DebugSessionSpec{ExtraDeployValues: map[string]apiextensionsv1.JSON{"value": {Raw: raw}}}}
		spec := &breakglassv1alpha1.DebugSessionTemplateSpec{}
		pod := (&DebugSessionController{}).buildVarsFromSession(session, spec)
		auxiliary := (&AuxiliaryResourceManager{}).buildVarsFromSession(session, spec)
		if pod["value"] != value || auxiliary["value"] != value {
			t.Fatalf("input corrupted: pod=%q auxiliary=%q want=%q", pod["value"], auxiliary["value"], value)
		}
		session.Spec.ExtraDeployValues = nil
		spec.ExtraDeployVariables = []breakglassv1alpha1.ExtraDeployVariable{{Name: "value", Default: &apiextensionsv1.JSON{Raw: raw}}}
		if (&DebugSessionController{}).buildVarsFromSession(session, spec)["value"] != value || (&AuxiliaryResourceManager{}).buildVarsFromSession(session, spec)["value"] != value {
			t.Fatal("default corrupted")
		}
	}
}
