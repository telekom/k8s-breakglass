// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestInjectMOTDEnvReplacesTemplateValues(t *testing.T) {
	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "shell", Env: []corev1.EnvVar{{Name: "KEEP", Value: "1"}, {Name: motdEnvName, Value: "spoofed"}}},
			{Name: "sidecar"},
		},
		InitContainers: []corev1.Container{{Name: "init"}},
	}
	injectMOTDEnv(spec, &breakglassv1alpha1.MessageOfTheDay{Message: "Purpose: test\nTerminate: bgctl", RunbookURL: "https://example.com/rb#x"})

	assert.Equal(t, []corev1.EnvVar{
		{Name: "KEEP", Value: "1"},
		{Name: motdEnvName, Value: "Purpose: test\nTerminate: bgctl"},
		{Name: runbookURLEnvName, Value: "https://example.com/rb#x"},
	}, spec.Containers[0].Env)
	assert.Equal(t, []corev1.EnvVar{
		{Name: motdEnvName, Value: "Purpose: test\nTerminate: bgctl"},
		{Name: runbookURLEnvName, Value: "https://example.com/rb#x"},
	}, spec.Containers[1].Env)
	assert.Empty(t, spec.InitContainers[0].Env, "init containers have no interactive shell")

	injectMOTDEnv(spec, &breakglassv1alpha1.MessageOfTheDay{Message: "no link"})
	assert.Equal(t, []corev1.EnvVar{{Name: "KEEP", Value: "1"}, {Name: motdEnvName, Value: "no link"}}, spec.Containers[0].Env,
		"a re-render without a runbook URL must not keep a stale one")
}

func TestInjectMOTDEnvWithoutMOTDKeepsSpec(t *testing.T) {
	spec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "shell"}}}
	injectMOTDEnv(spec, nil)
	injectMOTDEnv(nil, &breakglassv1alpha1.MessageOfTheDay{Message: "x"})
	assert.Empty(t, spec.Containers[0].Env)
}

func TestTemplateAndBindingResponsesExposeEffectiveMOTD(t *testing.T) {
	templateMOTD := &breakglassv1alpha1.MessageOfTheDay{Message: "template", RunbookURL: "https://example.com/rb#template"}
	bindingMOTD := &breakglassv1alpha1.MessageOfTheDay{Message: "persona", RunbookURL: "https://example.com/rb#persona"}
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{MOTD: templateMOTD}}
	withMOTD := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "persona", Namespace: "ns"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{MOTD: bindingMOTD}}
	withoutMOTD := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "ns"}}
	controller := &DebugSessionAPIController{log: zaptest.NewLogger(t).Sugar()}

	resp := controller.buildTemplateResponse(template, debugTemplateRequester{}, nil, 0, nil)
	assert.Equal(t, templateMOTD, resp.MOTD)
	payload, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.Contains(t, string(payload), `"motd":{"message":"template","runbookURL":"https://example.com/rb#template"}`)

	detail := controller.buildClusterDetailWithBindings(template, []*breakglassv1alpha1.DebugSessionClusterBinding{withMOTD, withoutMOTD}, &breakglassv1alpha1.ClusterConfig{}, debugTemplateRequester{})
	require.Len(t, detail.BindingOptions, 2)
	assert.Equal(t, bindingMOTD, detail.MOTD)
	assert.Equal(t, bindingMOTD, detail.BindingOptions[0].MOTD)
	assert.Equal(t, templateMOTD, detail.BindingOptions[1].MOTD)

	direct := controller.buildClusterDetailWithBindings(template, nil, &breakglassv1alpha1.ClusterConfig{}, debugTemplateRequester{})
	assert.Equal(t, templateMOTD, direct.MOTD)
}

func TestBuildWorkloadExportsEffectiveMOTD(t *testing.T) {
	for name, manifest := range map[string]string{
		"Pod": `apiVersion: v1
kind: Pod
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
    spec:
      restartPolicy: Never
      containers:
        - name: debug
          image: busybox
`,
	} {
		t.Run(name, func(t *testing.T) {
			controller, session, template, _ := newDeploymentFenceFixture(t)
			session.UID = "session-uid"
			template.Spec.WorkloadType = breakglassv1alpha1.DebugWorkloadJob
			template.Spec.PodTemplateString = ""
			template.Spec.MOTD = &breakglassv1alpha1.MessageOfTheDay{Message: "template", RunbookURL: "https://example.com/rb#template"}
			binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				MOTD: &breakglassv1alpha1.MessageOfTheDay{Message: "logs-only job", RunbookURL: "https://example.com/rb#job"},
			}}
			podTemplate := &breakglassv1alpha1.DebugPodTemplate{Spec: breakglassv1alpha1.DebugPodTemplateSpec{TemplateString: manifest}}
			workload, _, err := controller.buildWorkload(session, template, binding, podTemplate, "target")
			require.NoError(t, err)
			job, ok := workload.(*batchv1.Job)
			require.True(t, ok)
			assert.Contains(t, job.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{Name: motdEnvName, Value: "logs-only job"})
			assert.Contains(t, job.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{Name: runbookURLEnvName, Value: "https://example.com/rb#job"})
		})
	}
}
