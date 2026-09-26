// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestSessionUIDRenderContextIgnoresUserVariables(t *testing.T) {
	for _, uid := range []types.UID{"trusted-session-uid", ""} {
		t.Run(string(uid), func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", UID: uid}, Spec: breakglassv1alpha1.DebugSessionSpec{ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"uid": {Raw: []byte(`"spoofed"`)}, "session": {Raw: []byte(`{"uid":"spoofed"}`)}, "session.uid": {Raw: []byte(`"spoofed"`)},
			}}}
			template := &breakglassv1alpha1.DebugSessionTemplate{}
			manager := newTestAuxiliaryResourceManager()
			controller := &DebugSessionController{}
			contexts := map[string]breakglassv1alpha1.AuxiliaryResourceContext{
				"auxiliary": manager.buildRenderContext(session, &template.Spec, nil, "target", nil),
				"pod":       controller.buildPodRenderContext(session, template),
			}
			for name, ctx := range contexts {
				t.Run(name, func(t *testing.T) {
					rendered, err := NewTemplateRenderer().RenderTemplateString(`{{ required "session UID required" .session.uid | yamlQuote }}`, ctx)
					if uid == "" {
						require.ErrorContains(t, err, "session UID required")
					} else {
						require.NoError(t, err)
						require.Equal(t, strconv.Quote(string(uid)), string(rendered))
					}
					require.Equal(t, "spoofed", ctx.Vars["uid"], "Keep user data isolated under vars")
				})
			}
		})
	}
}

func TestRenderedJobSessionUIDWinsAnnotationMerges(t *testing.T) {
	for name, manifest := range map[string]string{
		"Pod": `apiVersion: v1
kind: Pod
metadata:
  annotations:
    breakglass.t-caas.telekom.com/source-session-uid: {{ required "session UID required" .session.uid | yamlQuote }}
spec:
  restartPolicy: Never
  containers:
    - name: debug
      image: busybox
`,
		"Job": `apiVersion: batch/v1
kind: Job
spec:
  template:
    metadata:
      annotations:
        breakglass.t-caas.telekom.com/source-session-uid: {{ required "session UID required" .session.uid | yamlQuote }}
    spec:
      restartPolicy: Never
      containers:
        - name: debug
          image: busybox
`,
	} {
		t.Run(name, func(t *testing.T) {
			controller, session, template, _ := newDeploymentFenceFixture(t)
			session.UID = "trusted-session-uid"
			session.Annotations = map[string]string{sourceSessionUIDAnnotation: "spoofed-session"}
			session.Spec.ExtraDeployValues = map[string]apiextensionsv1.JSON{"uid": {Raw: []byte(`"spoofed-variable"`)}, "session": {Raw: []byte(`{"uid":"spoofed-variable"}`)}}
			template.Spec.Annotations = map[string]string{sourceSessionUIDAnnotation: "spoofed-template"}
			template.Spec.WorkloadType = breakglassv1alpha1.DebugWorkloadJob
			template.Spec.PodTemplateString = ""
			binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{Annotations: map[string]string{sourceSessionUIDAnnotation: "spoofed-binding"}}}
			podTemplate := &breakglassv1alpha1.DebugPodTemplate{Spec: breakglassv1alpha1.DebugPodTemplateSpec{TemplateString: manifest}}
			workload, _, err := controller.buildWorkload(session, template, binding, podTemplate, "target")
			require.NoError(t, err)
			job, ok := workload.(*batchv1.Job)
			require.True(t, ok)
			require.Equal(t, string(session.UID), job.Annotations[sourceSessionUIDAnnotation])
			require.Equal(t, string(session.UID), job.Spec.Template.Annotations[sourceSessionUIDAnnotation])
		})
	}
}
