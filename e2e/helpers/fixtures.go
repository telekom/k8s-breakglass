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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// NewValidDebugSessionTemplate returns a minimal auto-approved E2E template
// with every field required by the selected mode.
func NewValidDebugSessionTemplate(name, displayName, cluster string, mode breakglassv1alpha1.DebugSessionTemplateMode, podTemplateName string) *breakglassv1alpha1.DebugSessionTemplate {
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: displayName,
			Mode:        mode,
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{
				Clusters: []string{cluster},
				Groups:   []string{"*"},
			},
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &breakglassv1alpha1.AutoApproveConfig{Clusters: []string{cluster}},
			},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
			},
		},
	}
	switch mode {
	case breakglassv1alpha1.DebugSessionModeWorkload:
		replicas := int32(1)
		template.Spec.PodTemplateRef = &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName}
		template.Spec.WorkloadType = breakglassv1alpha1.DebugWorkloadDeployment
		template.Spec.Replicas = &replicas
	case breakglassv1alpha1.DebugSessionModeKubectlDebug:
		template.Spec.KubectlDebug = &breakglassv1alpha1.KubectlDebugConfig{}
	}
	return template
}

var (
	fixtureScheme  *runtime.Scheme
	fixtureDecoder runtime.Decoder
)

func init() {
	fixtureScheme = runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(fixtureScheme)
	fixtureDecoder = serializer.NewCodecFactory(fixtureScheme).UniversalDeserializer()
}

// FixturesDir returns the path to the fixtures directory.
// It searches relative to the test file location.
func FixturesDir() string {
	// Try common paths
	paths := []string{
		"fixtures",
		"../fixtures",
		"e2e/fixtures",
		"../../e2e/fixtures",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}

	// Default to fixtures in current directory
	return "fixtures"
}
