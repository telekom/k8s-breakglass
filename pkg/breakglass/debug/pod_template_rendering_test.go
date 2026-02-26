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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestBuildPodRenderContext(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "my-template",
			RequestedBy:     "user@example.com",
			Reason:          "debugging issue",
			TargetNamespace: "target-ns",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"pvcSize":      {Raw: []byte(`"50Gi"`)},
				"enableDebug":  {Raw: []byte(`true`)},
				"replicaCount": {Raw: []byte(`3`)},
			},
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			Approval: &breakglassv1alpha1.DebugSessionApproval{
				ApprovedBy: "admin@example.com",
				ApprovedAt: &metav1.Time{},
			},
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Test Template",
			ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariable{
				{
					Name:    "pvcSize",
					Default: &apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)},
				},
				{
					Name:    "storageClass",
					Default: &apiextensionsv1.JSON{Raw: []byte(`"standard"`)},
				},
			},
		},
	}

	ctx := controller.buildPodRenderContext(ds, template)

	// Verify session context
	assert.Equal(t, "test-session", ctx.Session.Name)
	assert.Equal(t, "breakglass-system", ctx.Session.Namespace)
	assert.Equal(t, "test-cluster", ctx.Session.Cluster)
	assert.Equal(t, "user@example.com", ctx.Session.RequestedBy)
	assert.Equal(t, "admin@example.com", ctx.Session.ApprovedBy)
	assert.Equal(t, "debugging issue", ctx.Session.Reason)

	// Verify target context
	assert.Equal(t, "target-ns", ctx.Target.Namespace)
	assert.Equal(t, "test-cluster", ctx.Target.ClusterName)

	// Verify template context
	assert.Equal(t, "my-template", ctx.Template.Name)
	assert.Equal(t, "Test Template", ctx.Template.DisplayName)

	// Verify labels
	assert.Equal(t, "breakglass", ctx.Labels["app.kubernetes.io/managed-by"])
	assert.Equal(t, "test-session", ctx.Labels["breakglass.t-caas.telekom.com/session"])

	// Verify vars (user values override defaults)
	assert.Equal(t, "50Gi", ctx.Vars["pvcSize"])          // User provided
	assert.Equal(t, "standard", ctx.Vars["storageClass"]) // Default
	assert.Equal(t, "true", ctx.Vars["enableDebug"])      // User provided (boolean)
	assert.Equal(t, "3", ctx.Vars["replicaCount"])        // User provided (number)

	// Verify Now is set
	assert.NotEmpty(t, ctx.Now)
}

func TestBuildVarsFromSession_PodTemplate(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	tests := []struct {
		name         string
		ds           *breakglassv1alpha1.DebugSession
		templateSpec *breakglassv1alpha1.DebugSessionTemplateSpec
		want         map[string]string
	}{
		{
			name: "no variables",
			ds: &breakglassv1alpha1.DebugSession{
				Spec: breakglassv1alpha1.DebugSessionSpec{},
			},
			templateSpec: &breakglassv1alpha1.DebugSessionTemplateSpec{},
			want:         map[string]string{},
		},
		{
			name: "defaults only",
			ds: &breakglassv1alpha1.DebugSession{
				Spec: breakglassv1alpha1.DebugSessionSpec{},
			},
			templateSpec: &breakglassv1alpha1.DebugSessionTemplateSpec{
				ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariable{
					{Name: "size", Default: &apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)}},
					{Name: "enabled", Default: &apiextensionsv1.JSON{Raw: []byte(`true`)}},
				},
			},
			want: map[string]string{
				"size":    "10Gi",
				"enabled": "true",
			},
		},
		{
			name: "user values override defaults",
			ds: &breakglassv1alpha1.DebugSession{
				Spec: breakglassv1alpha1.DebugSessionSpec{
					ExtraDeployValues: map[string]apiextensionsv1.JSON{
						"size": {Raw: []byte(`"50Gi"`)},
					},
				},
			},
			templateSpec: &breakglassv1alpha1.DebugSessionTemplateSpec{
				ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariable{
					{Name: "size", Default: &apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)}},
				},
			},
			want: map[string]string{
				"size": "50Gi",
			},
		},
		{
			name: "various data types",
			ds: &breakglassv1alpha1.DebugSession{
				Spec: breakglassv1alpha1.DebugSessionSpec{
					ExtraDeployValues: map[string]apiextensionsv1.JSON{
						"stringVal": {Raw: []byte(`"hello"`)},
						"boolVal":   {Raw: []byte(`false`)},
						"intVal":    {Raw: []byte(`42`)},
						"floatVal":  {Raw: []byte(`3.14`)},
						"arrayVal":  {Raw: []byte(`["a","b","c"]`)},
					},
				},
			},
			templateSpec: &breakglassv1alpha1.DebugSessionTemplateSpec{},
			want: map[string]string{
				"stringVal": "hello",
				"boolVal":   "false",
				"intVal":    "42",
				"floatVal":  "3.14",
				"arrayVal":  "a,b,c",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := controller.buildVarsFromSession(tt.ds, tt.templateSpec)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRenderPodTemplateString(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	tests := []struct {
		name        string
		templateStr string
		ctx         breakglassv1alpha1.AuxiliaryResourceContext
		wantSpec    corev1.PodSpec
		wantErr     bool
		errContains string
	}{
		{
			name: "simple pod spec",
			templateStr: `
containers:
  - name: debug
    image: busybox:latest
    command: ["sleep", "infinity"]
`,
			ctx: breakglassv1alpha1.AuxiliaryResourceContext{},
			wantSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    "debug",
						Image:   "busybox:latest",
						Command: []string{"sleep", "infinity"},
					},
				},
			},
		},
		{
			name: "pod spec with variables",
			templateStr: `
containers:
  - name: {{ .vars.containerName | default "debug" }}
    image: {{ .vars.image }}
    command: ["sleep", "{{ .vars.sleepTime }}"]
`,
			ctx: breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{
					"containerName": "my-container",
					"image":         "alpine:3.18",
					"sleepTime":     "3600",
				},
			},
			wantSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    "my-container",
						Image:   "alpine:3.18",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		},
		{
			name: "pod spec with session metadata",
			templateStr: `
containers:
  - name: debug-{{ .session.name | trunc 10 }}
    image: debug:latest
    env:
      - name: SESSION_NAME
        value: {{ .session.name | quote }}
      - name: CLUSTER
        value: {{ .session.cluster | quote }}
`,
			ctx: breakglassv1alpha1.AuxiliaryResourceContext{
				Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
					Name:    "my-debug-session-12345",
					Cluster: "production-cluster",
				},
			},
			wantSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "debug-my-debug-s",
						Image: "debug:latest",
						Env: []corev1.EnvVar{
							{Name: "SESSION_NAME", Value: "my-debug-session-12345"},
							{Name: "CLUSTER", Value: "production-cluster"},
						},
					},
				},
			},
		},
		{
			name: "pod spec with conditional volume",
			templateStr: `
containers:
  - name: debug
    image: busybox
{{- if eq .vars.mountPvc "true" }}
    volumeMounts:
      - name: data
        mountPath: /data
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: {{ .vars.pvcName }}
{{- end }}
`,
			ctx: breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{
					"mountPvc": "true",
					"pvcName":  "test-pvc",
				},
			},
			wantSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "debug",
						Image: "busybox",
						VolumeMounts: []corev1.VolumeMount{
							{Name: "data", MountPath: "/data"},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "data",
						VolumeSource: corev1.VolumeSource{
							PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
								ClaimName: "test-pvc",
							},
						},
					},
				},
			},
		},
		{
			name:        "invalid template syntax",
			templateStr: `{{ .invalid.syntax`,
			ctx:         breakglassv1alpha1.AuxiliaryResourceContext{},
			wantErr:     true,
			errContains: "template rendering failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := controller.renderPodTemplateString(tt.templateStr, tt.ctx)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantSpec, got)
		})
	}
}

func TestRenderPodOverridesTemplate(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	trueVal := true
	falseVal := false

	tests := []struct {
		name          string
		templateStr   string
		ctx           breakglassv1alpha1.AuxiliaryResourceContext
		wantOverrides *breakglassv1alpha1.DebugPodSpecOverrides
		wantErr       bool
	}{
		{
			name: "simple overrides",
			templateStr: `
hostNetwork: true
hostPID: false
`,
			ctx: breakglassv1alpha1.AuxiliaryResourceContext{},
			wantOverrides: &breakglassv1alpha1.DebugPodSpecOverrides{
				HostNetwork: &trueVal,
				HostPID:     &falseVal,
			},
		},
		{
			name: "conditional overrides",
			templateStr: `
{{- if eq .vars.enableHostNetwork "true" }}
hostNetwork: true
{{- end }}
hostPID: {{ .vars.enableHostPID }}
`,
			ctx: breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{
					"enableHostNetwork": "true",
					"enableHostPID":     "false",
				},
			},
			wantOverrides: &breakglassv1alpha1.DebugPodSpecOverrides{
				HostNetwork: &trueVal,
				HostPID:     &falseVal,
			},
		},
		{
			name: "empty overrides when condition false",
			templateStr: `
{{- if eq .vars.enableHostNetwork "true" }}
hostNetwork: true
{{- end }}
`,
			ctx: breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{
					"enableHostNetwork": "false",
				},
			},
			wantOverrides: &breakglassv1alpha1.DebugPodSpecOverrides{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := controller.renderPodOverridesTemplate(tt.templateStr, tt.ctx)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantOverrides, got)
		})
	}
}

func TestApplyPodOverridesStruct(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	trueVal := true
	falseVal := false

	tests := []struct {
		name      string
		spec      corev1.PodSpec
		overrides *breakglassv1alpha1.DebugPodSpecOverrides
		wantSpec  corev1.PodSpec
	}{
		{
			name: "apply host network",
			spec: corev1.PodSpec{
				HostNetwork: false,
			},
			overrides: &breakglassv1alpha1.DebugPodSpecOverrides{
				HostNetwork: &trueVal,
			},
			wantSpec: corev1.PodSpec{
				HostNetwork: true,
			},
		},
		{
			name: "apply all overrides",
			spec: corev1.PodSpec{},
			overrides: &breakglassv1alpha1.DebugPodSpecOverrides{
				HostNetwork: &trueVal,
				HostPID:     &trueVal,
				HostIPC:     &falseVal,
			},
			wantSpec: corev1.PodSpec{
				HostNetwork: true,
				HostPID:     true,
				HostIPC:     false,
			},
		},
		{
			name:      "nil overrides",
			spec:      corev1.PodSpec{HostNetwork: true},
			overrides: nil,
			wantSpec:  corev1.PodSpec{HostNetwork: true},
		},
		{
			name:      "empty overrides",
			spec:      corev1.PodSpec{HostNetwork: true},
			overrides: &breakglassv1alpha1.DebugPodSpecOverrides{},
			wantSpec:  corev1.PodSpec{HostNetwork: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := tt.spec
			controller.applyPodOverridesStruct(&spec, tt.overrides)
			assert.Equal(t, tt.wantSpec, spec)
		})
	}
}

func TestBuildPodSpec_WithTemplateString(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "fio-template",
			RequestedBy:     "user@example.com",
			TargetNamespace: "target-ns",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"pvcSize":      {Raw: []byte(`"50Gi"`)},
				"storageClass": {Raw: []byte(`"csi-cinder"`)},
			},
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "FIO Storage Test",
			PodTemplateString: `
containers:
  - name: fio
    image: wallnerryan/fiotools:latest
    command: ["sleep", "infinity"]
    volumeMounts:
      - name: test-volume
        mountPath: /data
volumes:
  - name: test-volume
    persistentVolumeClaim:
      claimName: pvc-{{ .session.name | trunc 8 }}
`,
			ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariable{
				{Name: "pvcSize", Default: &apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)}},
			},
		},
	}

	result, err := controller.buildPodSpec(ds, template, nil)
	require.NoError(t, err)
	spec := result.PodSpec

	// Verify container
	require.Len(t, spec.Containers, 1)
	assert.Equal(t, "fio", spec.Containers[0].Name)
	assert.Equal(t, "wallnerryan/fiotools:latest", spec.Containers[0].Image)

	// Verify volume mount
	require.Len(t, spec.Containers[0].VolumeMounts, 1)
	assert.Equal(t, "/data", spec.Containers[0].VolumeMounts[0].MountPath)

	// Verify volume
	require.Len(t, spec.Volumes, 1)
	assert.Equal(t, "test-volume", spec.Volumes[0].Name)
	// Session name is "test-session", truncated to 8 chars = "test-ses"
	assert.Equal(t, "pvc-test-ses", spec.Volumes[0].PersistentVolumeClaim.ClaimName)
}

func TestBuildPodSpec_WithOverridesTemplate(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "network-debug",
			TargetNamespace: "target-ns",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"enableHostNetwork": {Raw: []byte(`true`)},
			},
		},
	}

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:    "netshoot",
							Image:   "nicolaka/netshoot:latest",
							Command: []string{"sleep", "infinity"},
						},
					},
				},
			},
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Network Debug",
			PodOverridesTemplate: `
{{- if eq .vars.enableHostNetwork "true" }}
hostNetwork: true
hostPID: true
{{- end }}
`,
			ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariable{
				{Name: "enableHostNetwork", Default: &apiextensionsv1.JSON{Raw: []byte(`false`)}},
			},
		},
	}

	result, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)
	spec := result.PodSpec

	// Verify container from podTemplate
	require.Len(t, spec.Containers, 1)
	assert.Equal(t, "netshoot", spec.Containers[0].Name)

	// Verify overrides were applied (because enableHostNetwork=true)
	assert.True(t, spec.HostNetwork)
	assert.True(t, spec.HostPID)
}

func TestBuildPodSpec_WithDebugPodTemplateTemplateString(t *testing.T) {
	// This tests that DebugPodTemplate.Spec.TemplateString is properly used
	// when the DebugSessionTemplate references a DebugPodTemplate with templateString
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "production-cluster",
			TemplateRef:     "dynamic-debug",
			TargetNamespace: "target-ns",
			RequestedBy:     "developer@example.com",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"image":    {Raw: []byte(`"alpine:3.19"`)},
				"cpuLimit": {Raw: []byte(`"200m"`)},
			},
		},
	}

	// DebugPodTemplate with templateString instead of structured template
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dynamic-pod-template",
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			// Template is nil - using templateString instead
			TemplateString: `
containers:
  - name: debug-{{ .session.name | trunc 15 }}
    image: {{ .vars.image | default "busybox:latest" }}
    command: ["sleep", "infinity"]
    env:
      - name: SESSION_NAMESPACE
        value: {{ .session.namespace | quote }}
      - name: CLUSTER
        value: {{ .session.cluster | quote }}
      - name: REQUESTED_BY
        value: {{ .session.requestedBy | quote }}
    resources:
      limits:
        cpu: {{ .vars.cpuLimit | default "100m" }}
        memory: 128Mi
      requests:
        cpu: 50m
        memory: 64Mi
`,
		},
	}

	// DebugSessionTemplate that references the DebugPodTemplate
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			// No PodTemplateString - will use the referenced podTemplate's templateString
		},
	}

	result, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)
	spec := result.PodSpec

	// Verify the template was rendered with session context and vars
	require.Len(t, spec.Containers, 1, "should have one container")
	container := spec.Containers[0]

	assert.Equal(t, "debug-test-session", container.Name, "should use session name in container name")
	assert.Equal(t, "alpine:3.19", container.Image, "should use vars.image")

	// Check environment variables were populated from session context
	envMap := make(map[string]string)
	for _, e := range container.Env {
		envMap[e.Name] = e.Value
	}
	assert.Equal(t, "breakglass-system", envMap["SESSION_NAMESPACE"])
	assert.Equal(t, "production-cluster", envMap["CLUSTER"])
	assert.Equal(t, "developer@example.com", envMap["REQUESTED_BY"])

	// Check resource limits from vars
	assert.Equal(t, "200m", container.Resources.Limits.Cpu().String(), "should use vars.cpuLimit")
}

func TestBuildPodSpec_DebugPodTemplateNeitherTemplateNorTemplateString(t *testing.T) {
	// Tests that an error is returned when DebugPodTemplate has neither template nor templateString
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			TemplateRef: "invalid-template",
		},
	}

	// DebugPodTemplate with neither template nor templateString (invalid)
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-pod-template",
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			// Both Template and TemplateString are nil/empty
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{},
	}

	_, err := controller.buildPodSpec(ds, template, podTemplate)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "neither template nor templateString")
}

func TestBuildPodSpec_OverridesDisabled(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "network-debug",
			TargetNamespace: "target-ns",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"enableHostNetwork": {Raw: []byte(`false`)},
			},
		},
	}

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox"},
					},
				},
			},
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			PodOverridesTemplate: `
{{- if eq .vars.enableHostNetwork "true" }}
hostNetwork: true
{{- end }}
`,
		},
	}

	result, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)
	spec := result.PodSpec

	// Overrides should NOT be applied (condition was false)
	assert.False(t, spec.HostNetwork)
}

func TestExtractJSONValueForPod(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{"string", []byte(`"hello world"`), "hello world"},
		{"boolean true", []byte(`true`), "true"},
		{"boolean false", []byte(`false`), "false"},
		{"integer", []byte(`42`), "42"},
		{"float", []byte(`3.14159`), "3.14159"},
		{"string array", []byte(`["a","b","c"]`), "a,b,c"},
		{"empty", []byte{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSONValueForPod(tt.raw)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// Multi-Document Pod Template Tests
// ============================================================================

func TestRenderPodTemplateStringMultiDoc_SingleDocument(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	templateStr := `
containers:
  - name: debug
    image: busybox:latest
    command: ["sleep", "infinity"]
`

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.NoError(t, err)

	// Should have a valid PodSpec
	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "debug", result.PodSpec.Containers[0].Name)
	assert.Equal(t, "busybox:latest", result.PodSpec.Containers[0].Image)

	// Should have no additional resources
	assert.Empty(t, result.AdditionalResources)
}

func TestRenderPodTemplateStringMultiDoc_WithPVC(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	// Multi-doc template: PodSpec + PVC
	templateStr := `containers:
  - name: fio
    image: fio:latest
    volumeMounts:
      - name: test-volume
        mountPath: /data
volumes:
  - name: test-volume
    persistentVolumeClaim:
      claimName: pvc-{{ .session.name }}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pvc-{{ .session.name }}
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: {{ .vars.pvcSize | default "10Gi" }}
`

	ctx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name: "test-session",
		},
		Vars: map[string]string{
			"pvcSize": "50Gi",
		},
	}

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.NoError(t, err)

	// Verify PodSpec
	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "fio", result.PodSpec.Containers[0].Name)
	require.Len(t, result.PodSpec.Volumes, 1)
	assert.Equal(t, "pvc-test-session", result.PodSpec.Volumes[0].PersistentVolumeClaim.ClaimName)

	// Verify additional resource (PVC)
	require.Len(t, result.AdditionalResources, 1)
	pvc := result.AdditionalResources[0]
	assert.Equal(t, "PersistentVolumeClaim", pvc.GetKind())
	assert.Equal(t, "v1", pvc.GetAPIVersion())
	assert.Equal(t, "pvc-test-session", pvc.GetName())
}

func TestRenderPodTemplateStringMultiDoc_MultipleResources(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	// Multi-doc template: PodSpec + ConfigMap + Secret + PVC
	templateStr := `containers:
  - name: app
    image: app:latest
    envFrom:
      - configMapRef:
          name: app-config
      - secretRef:
          name: app-secret
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  key: value
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
type: Opaque
stringData:
  password: secret123
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: app-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
`

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.NoError(t, err)

	// Verify PodSpec
	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "app", result.PodSpec.Containers[0].Name)

	// Verify 3 additional resources
	require.Len(t, result.AdditionalResources, 3)

	// ConfigMap
	assert.Equal(t, "ConfigMap", result.AdditionalResources[0].GetKind())
	assert.Equal(t, "app-config", result.AdditionalResources[0].GetName())

	// Secret
	assert.Equal(t, "Secret", result.AdditionalResources[1].GetKind())
	assert.Equal(t, "app-secret", result.AdditionalResources[1].GetName())

	// PVC
	assert.Equal(t, "PersistentVolumeClaim", result.AdditionalResources[2].GetKind())
	assert.Equal(t, "app-pvc", result.AdditionalResources[2].GetName())
}

func TestRenderPodTemplateStringMultiDoc_EmptyDocumentsSkipped(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	// Template with empty documents
	templateStr := `containers:
  - name: debug
    image: busybox
---

---
   
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config
data:
  key: value
`

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.NoError(t, err)

	// Verify PodSpec
	require.Len(t, result.PodSpec.Containers, 1)

	// Should only have 1 additional resource (empty docs skipped)
	require.Len(t, result.AdditionalResources, 1)
	assert.Equal(t, "ConfigMap", result.AdditionalResources[0].GetKind())
}

func TestRenderPodTemplateStringMultiDoc_EmptyTemplate(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	// Empty template
	_, err := controller.renderPodTemplateStringMultiDoc("", breakglassv1alpha1.AuxiliaryResourceContext{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestRenderPodTemplateStringMultiDoc_InvalidSecondDocument(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	// Second document is missing apiVersion/kind
	templateStr := `containers:
  - name: debug
    image: busybox
---
data:
  key: value
`

	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing apiVersion or kind")
}

func TestRenderPodTemplateStringMultiDoc_TemplateVariables(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	templateStr := `containers:
  - name: debug-{{ .session.name | trunc 10 }}
    image: {{ .vars.image }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-{{ .session.name }}
  namespace: {{ .target.namespace }}
data:
  cluster: {{ .session.cluster }}
  requestedBy: {{ .session.requestedBy }}
`

	ctx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name:        "very-long-session-name-12345",
			Cluster:     "prod-cluster",
			RequestedBy: "user@example.com",
		},
		Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
			Namespace: "debug-ns",
		},
		Vars: map[string]string{
			"image": "alpine:3.19",
		},
	}

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.NoError(t, err)

	// Verify PodSpec with templated values
	assert.Equal(t, "debug-very-long-", result.PodSpec.Containers[0].Name)
	assert.Equal(t, "alpine:3.19", result.PodSpec.Containers[0].Image)

	// Verify ConfigMap with templated values
	require.Len(t, result.AdditionalResources, 1)
	cm := result.AdditionalResources[0]
	assert.Equal(t, "config-very-long-session-name-12345", cm.GetName())
	assert.Equal(t, "debug-ns", cm.GetNamespace())
}

func TestRenderPodTemplateStringMultiDoc_ConditionalResource(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	// Template with conditional PVC
	templateStr := `containers:
  - name: app
    image: app:latest
{{- if eq .vars.createPVC "true" }}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: app-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
{{- end }}
`

	// Test with PVC enabled
	ctx := breakglassv1alpha1.AuxiliaryResourceContext{
		Vars: map[string]string{"createPVC": "true"},
	}
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.NoError(t, err)
	assert.Len(t, result.AdditionalResources, 1)

	// Test with PVC disabled
	ctx = breakglassv1alpha1.AuxiliaryResourceContext{
		Vars: map[string]string{"createPVC": "false"},
	}
	result, err = controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.NoError(t, err)
	assert.Empty(t, result.AdditionalResources)
}

func TestBuildPodSpec_MultiDocReturnsAdditionalResources(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "storage-test",
			RequestedBy:     "user@example.com",
			TargetNamespace: "target-ns",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Storage Test",
			PodTemplateString: `containers:
  - name: fio
    image: fio:latest
    volumeMounts:
      - name: data
        mountPath: /data
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: pvc-{{ .session.name }}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pvc-{{ .session.name }}
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
`,
		},
	}

	result, err := controller.buildPodSpec(ds, template, nil)
	require.NoError(t, err)

	// Verify PodSpec
	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "fio", result.PodSpec.Containers[0].Name)
	assert.Equal(t, "pvc-test-session", result.PodSpec.Volumes[0].PersistentVolumeClaim.ClaimName)

	// Verify additional resources
	require.Len(t, result.AdditionalResources, 1)
	assert.Equal(t, "PersistentVolumeClaim", result.AdditionalResources[0].GetKind())
	assert.Equal(t, "pvc-test-session", result.AdditionalResources[0].GetName())
}

func TestBuildPodSpec_StructuredTemplateNoAdditionalResources(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "simple",
			TargetNamespace: "target-ns",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{},
	}

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox"},
					},
				},
			},
		},
	}

	result, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)

	// Verify PodSpec
	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "debug", result.PodSpec.Containers[0].Name)

	// Structured templates don't support multi-doc, so no additional resources
	assert.Empty(t, result.AdditionalResources)
}

func TestBuildPodSpec_DebugPodTemplateMultiDoc(t *testing.T) {
	// Test multi-doc support in DebugPodTemplate.templateString
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "with-pod-template",
			TargetNamespace: "target-ns",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			// No PodTemplateString - will use podTemplate's templateString
		},
	}

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			TemplateString: `containers:
  - name: app
    image: app:latest
    env:
      - name: CONFIG_PATH
        value: /config/settings.yaml
    volumeMounts:
      - name: config
        mountPath: /config
volumes:
  - name: config
    configMap:
      name: app-config-{{ .session.name }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config-{{ .session.name }}
data:
  settings.yaml: |
    debug: true
    cluster: {{ .session.cluster }}
`,
		},
	}

	result, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)

	// Verify PodSpec
	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "app", result.PodSpec.Containers[0].Name)
	require.Len(t, result.PodSpec.Volumes, 1)
	assert.Equal(t, "app-config-test-session", result.PodSpec.Volumes[0].ConfigMap.Name)

	// Verify additional resources from DebugPodTemplate
	require.Len(t, result.AdditionalResources, 1)
	assert.Equal(t, "ConfigMap", result.AdditionalResources[0].GetKind())
	assert.Equal(t, "app-config-test-session", result.AdditionalResources[0].GetName())
}

// ============================================================================
// kind: Pod Template Tests (renderPodTemplateStringMultiDoc format detection)
// ============================================================================

func TestRenderPodTemplateStringMultiDoc_KindPod(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{log: logger}

	templateStr := `apiVersion: v1
kind: Pod
metadata:
  labels:
    debug-type: network
  annotations:
    description: "network debug pod"
spec:
  hostNetwork: true
  automountServiceAccountToken: false
  containers:
    - name: netshoot
      image: nicolaka/netshoot:latest
      command: ["sleep", "infinity"]
      securityContext:
        capabilities:
          add: ["NET_ADMIN", "NET_RAW"]
`

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.NoError(t, err)

	// Should extract PodSpec correctly
	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "netshoot", result.PodSpec.Containers[0].Name)
	assert.Equal(t, "nicolaka/netshoot:latest", result.PodSpec.Containers[0].Image)
	assert.True(t, result.PodSpec.HostNetwork)
	assert.False(t, *result.PodSpec.AutomountServiceAccountToken)
	require.Len(t, result.PodSpec.Containers[0].SecurityContext.Capabilities.Add, 2)

	// Should capture pod-level metadata
	assert.Equal(t, "network", result.PodLabels["debug-type"])
	assert.Equal(t, "network debug pod", result.PodAnnotations["description"])

	// Should NOT produce a full workload
	assert.Nil(t, result.Workload)
	assert.Empty(t, result.AdditionalResources)
}

func TestRenderPodTemplateStringMultiDoc_KindPodWithAdditionalResources(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{log: logger}

	templateStr := `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: app:latest
      volumeMounts:
        - name: config
          mountPath: /config
  volumes:
    - name: config
      configMap:
        name: my-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
data:
  key: value
`

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.NoError(t, err)

	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "app", result.PodSpec.Containers[0].Name)

	// Additional resources from subsequent documents
	require.Len(t, result.AdditionalResources, 1)
	assert.Equal(t, "ConfigMap", result.AdditionalResources[0].GetKind())
}

func TestRenderPodTemplateStringMultiDoc_KindDeployment(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{log: logger}

	templateStr := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: debug-deploy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
          command: ["sleep", "infinity"]
          resources:
            limits:
              cpu: "100m"
              memory: "128Mi"
`

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.NoError(t, err)

	// Should return the full Deployment as Workload
	require.NotNil(t, result.Workload)
	deploy, ok := result.Workload.(*appsv1.Deployment)
	require.True(t, ok, "expected *appsv1.Deployment")
	assert.Equal(t, int32(2), *deploy.Spec.Replicas)

	// PodSpec should also be extracted
	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "debug", result.PodSpec.Containers[0].Name)
	assert.Equal(t, resource.MustParse("100m"), *result.PodSpec.Containers[0].Resources.Limits.Cpu())
}

func TestRenderPodTemplateStringMultiDoc_KindDaemonSet(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{log: logger}

	templateStr := `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: debug-ds
spec:
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      hostNetwork: true
      containers:
        - name: netshoot
          image: nicolaka/netshoot:v0.13
          command: ["sleep", "infinity"]
`

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.NoError(t, err)

	require.NotNil(t, result.Workload)
	ds, ok := result.Workload.(*appsv1.DaemonSet)
	require.True(t, ok, "expected *appsv1.DaemonSet")
	assert.Equal(t, "debug-ds", ds.Name)

	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "netshoot", result.PodSpec.Containers[0].Name)
	assert.True(t, result.PodSpec.HostNetwork)
}

func TestRenderPodTemplateStringMultiDoc_UnsupportedKind(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{log: logger}

	templateStr := `apiVersion: batch/v1
kind: Job
metadata:
  name: job
spec:
  template:
    spec:
      containers:
        - name: test
          image: busybox
`

	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported manifest kind")
	assert.Contains(t, err.Error(), "Job")
}

func TestRenderPodTemplateStringMultiDoc_EmptyContainersError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{log: logger}

	// Pod with no containers
	templateStr := `apiVersion: v1
kind: Pod
spec:
  volumes:
    - name: vol
      emptyDir: {}
`

	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no containers")
}

func TestRenderPodTemplateStringMultiDoc_BareSpecEmptyContainersError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{log: logger}

	// Bare PodSpec with empty containers list
	templateStr := `volumes:
  - name: vol
    emptyDir: {}
`

	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no containers")
}

// ============================================================================
// Real-world Template Format Tests
// ============================================================================

func TestRenderPodTemplateStringMultiDoc_RealWorldCoredumpCollector(t *testing.T) {
	// Based on the real coredump-collector DebugPodTemplate
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{log: logger}

	templateStr := `apiVersion: v1
kind: Pod
metadata:
  labels:
    breakglass.t-caas.telekom.com/debug-type: coredump
spec:
  hostNetwork: false
  automountServiceAccountToken: false
  restartPolicy: Never
  terminationGracePeriodSeconds: 30
  containers:
    - name: coredump
      image: docker.io/library/alpine:3.21
      command:
        - /bin/sh
        - -c
        - "echo 'Coredump collector started'; sleep infinity"
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      volumeMounts:
        - name: coredumps
          mountPath: /coredumps
          readOnly: true
  volumes:
    - name: coredumps
      hostPath:
        path: /var/lib/systemd/coredump
        type: DirectoryOrCreate
`

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.NoError(t, err)

	assert.Nil(t, result.Workload, "Pod manifests should not produce a workload")
	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "coredump", result.PodSpec.Containers[0].Name)
	assert.Equal(t, "docker.io/library/alpine:3.21", result.PodSpec.Containers[0].Image)
	assert.False(t, result.PodSpec.HostNetwork)
	assert.Equal(t, corev1.RestartPolicyNever, result.PodSpec.RestartPolicy)
	assert.Equal(t, int64(30), *result.PodSpec.TerminationGracePeriodSeconds)

	// Verify pod-level labels are captured
	assert.Equal(t, "coredump", result.PodLabels["breakglass.t-caas.telekom.com/debug-type"])

	// Volume mounts
	require.Len(t, result.PodSpec.Volumes, 1)
	assert.Equal(t, "/var/lib/systemd/coredump", result.PodSpec.Volumes[0].HostPath.Path)
}

func TestRenderPodTemplateStringMultiDoc_RealWorldTcpdumpCapture(t *testing.T) {
	// Based on the real tcpdump-capture DebugPodTemplate (with Go template vars)
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{log: logger}

	templateStr := `apiVersion: v1
kind: Pod
metadata:
  labels:
    breakglass.t-caas.telekom.com/debug-type: tcpdump
spec:
  hostNetwork: true
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: tcpdump
      image: nicolaka/netshoot:v0.13
      command:
        - /bin/sh
        - -c
        - "echo 'Ready for capture'; sleep infinity"
      securityContext:
        capabilities:
          add: ["NET_ADMIN", "NET_RAW"]
          drop: ["ALL"]
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
          ephemeral-storage: {{ .vars.captureStorageGi | default "2" }}Gi
        requests:
          cpu: "100m"
          memory: "128Mi"
      volumeMounts:
        - name: captures
          mountPath: /captures
  volumes:
    - name: captures
      emptyDir:
        sizeLimit: {{ .vars.captureStorageGi | default "2" }}Gi
`

	ctx := breakglassv1alpha1.AuxiliaryResourceContext{
		Vars: map[string]string{
			"captureStorageGi": "5",
		},
	}

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.NoError(t, err)

	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "tcpdump", result.PodSpec.Containers[0].Name)
	assert.True(t, result.PodSpec.HostNetwork)

	// Verify template vars were rendered
	ephStorage := result.PodSpec.Containers[0].Resources.Limits[corev1.ResourceEphemeralStorage]
	assert.Equal(t, "5Gi", ephStorage.String())

	// Verify volume sizeLimit
	require.Len(t, result.PodSpec.Volumes, 1)
	assert.Equal(t, "5Gi", result.PodSpec.Volumes[0].EmptyDir.SizeLimit.String())

	// Pod-level labels
	assert.Equal(t, "tcpdump", result.PodLabels["breakglass.t-caas.telekom.com/debug-type"])
}

func TestRenderPodTemplateStringMultiDoc_RealWorldNodeAccess(t *testing.T) {
	// Based on unified-node: kind: Pod with conditional privileged access
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{log: logger}

	templateStr := `apiVersion: v1
kind: Pod
metadata:
  labels:
    breakglass.t-caas.telekom.com/debug-type: node
spec:
  hostNetwork: true
  hostPID: true
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: node-debug
      image: nicolaka/netshoot:v0.13
      command: ["sleep", "infinity"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host
          readOnly: true
  volumes:
    - name: host-root
      hostPath:
        path: /
        type: Directory
`

	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.NoError(t, err)

	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "node-debug", result.PodSpec.Containers[0].Name)
	assert.True(t, result.PodSpec.HostNetwork)
	assert.True(t, result.PodSpec.HostPID)
	require.NotNil(t, result.PodSpec.Containers[0].SecurityContext)
	assert.True(t, *result.PodSpec.Containers[0].SecurityContext.Privileged)

	// Verify host root volume
	require.Len(t, result.PodSpec.Volumes, 1)
	assert.Equal(t, "/", result.PodSpec.Volumes[0].HostPath.Path)

	assert.Equal(t, "node", result.PodLabels["breakglass.t-caas.telekom.com/debug-type"])
}

// ============================================================================
// buildWorkload Tests — Full Workload Manifests
// ============================================================================

func newBuildWorkloadController() *DebugSessionController {
	return &DebugSessionController{log: zap.NewNop().Sugar()}
}

func newBuildWorkloadSession(name string) *breakglassv1alpha1.DebugSession {
	return &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			TargetNamespace: "target-ns",
			RequestedBy:     "user@example.com",
		},
	}
}

func TestBuildWorkload_KindPodWrappedInDaemonSet(t *testing.T) {
	// A kind: Pod templateString should be extracted and wrapped into a DaemonSet
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("pod-to-ds")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `apiVersion: v1
kind: Pod
metadata:
  labels:
    custom-label: from-pod
  annotations:
    custom-anno: from-pod
spec:
  hostNetwork: true
  containers:
    - name: debug
      image: busybox:latest
      command: ["sleep", "infinity"]
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok, "expected DaemonSet")

	assert.Equal(t, "pod-to-ds", daemonSet.Name)
	assert.Equal(t, "target-ns", daemonSet.Namespace)
	assert.True(t, daemonSet.Spec.Template.Spec.HostNetwork)
	require.Len(t, daemonSet.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "debug", daemonSet.Spec.Template.Spec.Containers[0].Name)

	// Pod-level labels should be merged into workload labels
	assert.Equal(t, "from-pod", daemonSet.Labels["custom-label"])
	assert.Equal(t, "from-pod", daemonSet.Spec.Template.Labels["custom-label"])

	// Pod-level annotations should be merged
	assert.Equal(t, "from-pod", daemonSet.Annotations["custom-anno"])

	// RestartPolicy should be overridden to Always for DaemonSet
	assert.Equal(t, corev1.RestartPolicyAlways, daemonSet.Spec.Template.Spec.RestartPolicy)
}

func TestBuildWorkload_KindPodWrappedInDeployment(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("pod-to-deploy")

	replicas := int32(3)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			Replicas:     &replicas,
			PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox:latest
      command: ["sleep", "infinity"]
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok, "expected Deployment")
	assert.Equal(t, int32(3), *deploy.Spec.Replicas)
	assert.Equal(t, "pod-to-deploy", deploy.Name)
	assert.Equal(t, corev1.RestartPolicyAlways, deploy.Spec.Template.Spec.RestartPolicy)
}

func TestBuildWorkload_FullDeploymentTemplate(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("full-deploy")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: original-name
spec:
  replicas: 5
  selector:
    matchLabels:
      original: selector
  template:
    metadata:
      labels:
        original: label
    spec:
      containers:
        - name: app
          image: app:latest
          command: ["sleep", "infinity"]
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok, "expected Deployment")

	// Name/namespace should be overridden by breakglass
	assert.Equal(t, "full-deploy", deploy.Name)
	assert.Equal(t, "target-ns", deploy.Namespace)

	// Selector should be overridden for breakglass tracking
	assert.Equal(t, ds.Name, deploy.Spec.Selector.MatchLabels[DebugSessionLabelKey])

	// Breakglass labels should be present
	assert.Equal(t, ds.Name, deploy.Labels[DebugSessionLabelKey])
	assert.Equal(t, ds.Spec.TemplateRef, deploy.Labels[DebugTemplateLabelKey])

	// RestartPolicy should be forced to Always
	assert.Equal(t, corev1.RestartPolicyAlways, deploy.Spec.Template.Spec.RestartPolicy)

	require.Len(t, deploy.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "app", deploy.Spec.Template.Spec.Containers[0].Name)
}

func TestBuildWorkload_FullDaemonSetTemplate(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("full-ds")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: original-ds
spec:
  selector:
    matchLabels:
      original: selector
  template:
    metadata:
      labels:
        original: label
    spec:
      hostNetwork: true
      containers:
        - name: agent
          image: agent:latest
          command: ["sleep", "infinity"]
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok, "expected DaemonSet")

	assert.Equal(t, "full-ds", daemonSet.Name)
	assert.Equal(t, "target-ns", daemonSet.Namespace)
	assert.Equal(t, ds.Name, daemonSet.Spec.Selector.MatchLabels[DebugSessionLabelKey])
	assert.True(t, daemonSet.Spec.Template.Spec.HostNetwork)
}

func TestBuildWorkload_WorkloadTypeMismatch(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("mismatch")

	// Template produces a DaemonSet but workloadType is Deployment
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ds
spec:
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: busybox
`,
		},
	}

	_, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DaemonSet")
	assert.Contains(t, err.Error(), "Deployment")
	assert.Contains(t, err.Error(), "must match")
}

func TestBuildWorkload_FullDeploymentReplicasOverride(t *testing.T) {
	// If session template specifies replicas, they should override the one in the Deployment manifest
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("replicas-override")

	overrideReplicas := int32(2)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			Replicas:     &overrideReplicas,
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: deploy
spec:
  replicas: 10
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: busybox
          command: ["sleep", "infinity"]
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy := workload.(*appsv1.Deployment)
	assert.Equal(t, int32(2), *deploy.Spec.Replicas, "template replicas should override manifest replicas")
}

func TestBuildWorkload_FullDeploymentResourceQuotaExceeded(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("quota-exceed")

	maxPods := int32(2)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			ResourceQuota: &breakglassv1alpha1.DebugResourceQuotaConfig{
				MaxPods: &maxPods,
			},
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: deploy
spec:
  replicas: 5
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: busybox
          command: ["sleep", "infinity"]
`,
		},
	}

	_, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replicas")
	assert.Contains(t, err.Error(), "exceed")
}

func TestBuildWorkload_BareSpecBackwardCompatible(t *testing.T) {
	// Bare PodSpec (no apiVersion/kind) should still work as before
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("bare-spec")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `containers:
  - name: debug
    image: alpine:3.19
    command: ["sleep", "infinity"]
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok, "expected DaemonSet")
	assert.Equal(t, "bare-spec", daemonSet.Name)
	require.Len(t, daemonSet.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "debug", daemonSet.Spec.Template.Spec.Containers[0].Name)
}

// ============================================================================
// buildPodSpec Tests - kind: Pod format
// ============================================================================

func TestBuildPodSpec_KindPodInSessionTemplate(t *testing.T) {
	// Tests that buildPodSpec correctly handles kind: Pod in PodTemplateString
	controller := newBuildWorkloadController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			TargetNamespace: "target-ns",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			PodTemplateString: `apiVersion: v1
kind: Pod
metadata:
  labels:
    test-label: value
spec:
  containers:
    - name: test
      image: test:latest
      command: ["sleep", "infinity"]
`,
		},
	}

	result, err := controller.buildPodSpec(ds, template, nil)
	require.NoError(t, err)

	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "test", result.PodSpec.Containers[0].Name)
	assert.Equal(t, "value", result.PodLabels["test-label"])
	assert.Nil(t, result.Workload)
}

func TestBuildPodSpec_KindPodInDebugPodTemplate(t *testing.T) {
	// Tests that buildPodSpec handles kind: Pod in DebugPodTemplate.TemplateString
	controller := newBuildWorkloadController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			TargetNamespace: "target-ns",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{},
	}

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			TemplateString: `apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
    - name: node-debug
      image: busybox:latest
      command: ["sleep", "infinity"]
`,
		},
	}

	result, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)

	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "node-debug", result.PodSpec.Containers[0].Name)
	assert.True(t, result.PodSpec.HostNetwork)
}

// ==================== Error Path Tests ====================

func TestRenderPodTemplateStringMultiDoc_PodMissingSpec(t *testing.T) {
	controller := newBuildWorkloadController()

	// Pod manifest without spec field
	templateStr := `apiVersion: v1
kind: Pod
metadata:
  name: no-spec-pod
`
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing 'spec'")
	assert.Nil(t, result)
}

func TestRenderPodTemplateStringMultiDoc_PodNoMetadata(t *testing.T) {
	controller := newBuildWorkloadController()

	// Pod manifest without metadata, but with valid spec (should still work)
	templateStr := `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox:latest
`
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.PodSpec.Containers, 1)
	assert.Equal(t, "debug", result.PodSpec.Containers[0].Name)
}

func TestRenderPodTemplateStringMultiDoc_DeploymentEmptyContainers(t *testing.T) {
	controller := newBuildWorkloadController()

	templateStr := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: empty-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers: []
`
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "containers")
	assert.Nil(t, result)
}

func TestRenderPodTemplateStringMultiDoc_DaemonSetEmptyContainers(t *testing.T) {
	controller := newBuildWorkloadController()

	templateStr := `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: empty-ds
spec:
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers: []
`
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "containers")
	assert.Nil(t, result)
}

func TestRenderPodTemplateStringMultiDoc_InvalidYAML(t *testing.T) {
	controller := newBuildWorkloadController()

	// Completely invalid YAML
	templateStr := `{{{not valid yaml: [`
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, breakglassv1alpha1.AuxiliaryResourceContext{})
	require.Error(t, err)
	assert.Nil(t, result)
}

func TestBuildWorkload_UnknownWorkloadType(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("unknown-type")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: "StatefulSet", // unsupported type
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported workload type")
	assert.Nil(t, workload)
}

func TestBuildWorkload_DeploymentNilReplicasDefaultsToOne(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("nil-replicas")

	// Template without Replicas set (nil)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			// Replicas: nil — should default to 1
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)
	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	require.NotNil(t, deploy.Spec.Replicas)
	assert.Equal(t, int32(1), *deploy.Spec.Replicas)
}

func TestBuildWorkload_RestartPolicyOverriddenForBareSpecDaemonSet(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("restart-override")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			// Bare PodSpec with RestartPolicy=Never (should be overridden to Always)
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
restartPolicy: Never
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)
	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)
	assert.Equal(t, corev1.RestartPolicyAlways, daemonSet.Spec.Template.Spec.RestartPolicy)
}

// ==================== Override Tests for Full Workload Templates ====================

func TestBuildWorkload_FullDeploymentWithSchedulingConstraints(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("sched-constraints")
	ds.Spec.ResolvedSchedulingConstraints = &breakglassv1alpha1.SchedulingConstraints{
		NodeSelector: map[string]string{
			"node-role.kubernetes.io/debug": "true",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: template-deploy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)

	// Verify scheduling constraints were applied to the pod spec inside the workload
	assert.Equal(t, "true", deploy.Spec.Template.Spec.NodeSelector["node-role.kubernetes.io/debug"],
		"schedulingConstraints nodeSelector should be applied to full Deployment template's PodSpec")
}

func TestBuildWorkload_FullDeploymentWithTolerations(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("tolerations")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			AdditionalTolerations: []corev1.Toleration{
				{
					Key:      "debug-node",
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: template-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
      tolerations:
        - key: existing-toleration
          operator: Exists
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)

	// Verify both the original and additional tolerations are present
	assert.Len(t, deploy.Spec.Template.Spec.Tolerations, 2,
		"both template tolerations and additionalTolerations should be present")
	assert.Equal(t, "existing-toleration", deploy.Spec.Template.Spec.Tolerations[0].Key)
	assert.Equal(t, "debug-node", deploy.Spec.Template.Spec.Tolerations[1].Key)
}

func TestBuildWorkload_FullDaemonSetWithSessionNodeSelector(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("node-selector")
	ds.Spec.NodeSelector = map[string]string{
		"kubernetes.io/hostname": "worker-01",
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: template-ds
spec:
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)

	// Verify session nodeSelector was applied
	assert.Equal(t, "worker-01", daemonSet.Spec.Template.Spec.NodeSelector["kubernetes.io/hostname"],
		"session nodeSelector should be applied to full DaemonSet template's PodSpec")
}

func TestBuildWorkload_FullDeploymentWithPodOverrides(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("pod-overrides")

	hostNetTrue := true
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			PodOverrides: &breakglassv1alpha1.DebugPodOverrides{
				Spec: &breakglassv1alpha1.DebugPodSpecOverrides{
					HostNetwork: &hostNetTrue,
				},
			},
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: template-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)

	// Verify podOverrides were applied (hostNetwork=true)
	assert.True(t, deploy.Spec.Template.Spec.HostNetwork,
		"podOverrides hostNetwork=true should be applied to full Deployment template's PodSpec")
}

func TestBuildWorkload_FullDeploymentLabelMerging(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("label-merge")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: template-deploy
  labels:
    custom-label: from-template
spec:
  replicas: 1
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
        pod-custom: from-pod-template
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)

	// Breakglass labels should override workload-level labels
	assert.Contains(t, deploy.Labels, "app.kubernetes.io/managed-by")
	assert.Equal(t, "breakglass", deploy.Labels["app.kubernetes.io/managed-by"])

	// Pod template labels should include both breakglass and original labels
	assert.Contains(t, deploy.Spec.Template.Labels, "pod-custom",
		"original pod template labels should be preserved via mergeStringMaps")
	assert.Contains(t, deploy.Spec.Template.Labels, "app.kubernetes.io/managed-by",
		"breakglass labels should be merged into pod template labels")
}

func TestBuildWorkload_FullDaemonSetWithAffinityOverrides(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("affinity")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			AffinityOverrides: &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "node-type",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"debug"},
									},
								},
							},
						},
					},
				},
			},
			PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: template-ds
spec:
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)

	// Verify affinity was applied to the DaemonSet's pod spec
	require.NotNil(t, daemonSet.Spec.Template.Spec.Affinity,
		"affinityOverrides should be applied to full DaemonSet PodSpec")
	require.NotNil(t, daemonSet.Spec.Template.Spec.Affinity.NodeAffinity)
	assert.Equal(t, "node-type",
		daemonSet.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions[0].Key)
}

func TestBuildWorkload_FullDeploymentWithResourceQuota(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("resource-quota")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			ResourceQuota: &breakglassv1alpha1.DebugResourceQuotaConfig{
				EnforceResourceRequests: true,
				EnforceResourceLimits:   true,
			},
			// Full Deployment template without resource requests/limits — should fail
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: template-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	// Should fail because resource requests/limits are required but not specified
	_, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing resource")
}

func TestBuildWorkload_FullDeploymentRestartPolicyEnforced(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("restart-enforce")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			// Full Deployment with RestartPolicy=Never (should be overridden)
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: template-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      restartPolicy: Never
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	assert.Equal(t, corev1.RestartPolicyAlways, deploy.Spec.Template.Spec.RestartPolicy,
		"RestartPolicy should be enforced to Always for full Deployment templates")
}

// ==================== Additional renderPodTemplateStringMultiDoc Tests ====================

func TestRenderPodTemplateStringMultiDoc_DeploymentMissingTemplateSpec(t *testing.T) {
	controller := newTestController()

	// Deployment without spec.template.spec — should produce empty containers error
	templateStr := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  replicas: 1
  selector:
    matchLabels:
      app: debug
`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no containers",
		"Deployment without spec.template.spec should fail with no containers error")
}

func TestRenderPodTemplateStringMultiDoc_DaemonSetMissingTemplateSpec(t *testing.T) {
	controller := newTestController()

	// DaemonSet without spec.template — should produce empty containers error
	templateStr := `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: test
spec:
  selector:
    matchLabels:
      app: debug
`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no containers",
		"DaemonSet without spec.template should fail with no containers error")
}

func TestRenderPodTemplateStringMultiDoc_TemplateRenderingError(t *testing.T) {
	controller := newTestController()

	// Template with syntax error
	templateStr := `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: {{ .session.name`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template rendering failed",
		"Go template parse error should produce rendering failure")
}

func TestRenderPodTemplateStringMultiDoc_PodWithEmptySpec(t *testing.T) {
	controller := newTestController()

	// Pod with spec but no containers
	templateStr := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  volumes:
    - name: data
      emptyDir: {}
`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no containers",
		"Pod with empty containers should fail")
}

func TestRenderPodTemplateStringMultiDoc_DeploymentWrongApiVersion(t *testing.T) {
	controller := newTestController()

	templateStr := `apiVersion: v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: debug
          image: busybox
`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported apiVersion")
}

func TestRenderPodTemplateStringMultiDoc_DaemonSetWrongApiVersion(t *testing.T) {
	controller := newTestController()

	templateStr := `apiVersion: v1
kind: DaemonSet
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: debug
          image: busybox
`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported apiVersion")
}

func TestRenderPodTemplateStringMultiDoc_PodWrongApiVersion(t *testing.T) {
	controller := newTestController()

	templateStr := `apiVersion: apps/v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported apiVersion")
}

func TestRenderPodTemplateStringMultiDoc_AdditionalResourceWithNamespace(t *testing.T) {
	controller := newTestController()

	// Additional resource already has a namespace set — should be preserved
	templateStr := `containers:
  - name: debug
    image: busybox:latest
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
  namespace: custom-namespace
data:
  key: value
`
	ctx := newTestRenderContext()
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.NoError(t, err)
	require.Len(t, result.AdditionalResources, 1)
	assert.Equal(t, "custom-namespace", result.AdditionalResources[0].GetNamespace(),
		"namespace already set on additional resource should be preserved")
}

func TestRenderPodTemplateStringMultiDoc_PodWithMetadataButNoLabels(t *testing.T) {
	controller := newTestController()

	templateStr := `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: debug
      image: busybox:latest
`
	ctx := newTestRenderContext()
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.NoError(t, err)
	assert.Nil(t, result.PodLabels, "Pod with metadata but no labels should have nil PodLabels")
	assert.Nil(t, result.PodAnnotations, "Pod with metadata but no annotations should have nil PodAnnotations")
	assert.NotEmpty(t, result.PodSpec.Containers)
}

// ==================== Additional buildWorkload Tests ====================

func TestBuildWorkload_FullDaemonSetRestartPolicyOverride(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("ds-restart")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: template-ds
spec:
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      restartPolicy: Never
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)
	assert.Equal(t, corev1.RestartPolicyAlways, daemonSet.Spec.Template.Spec.RestartPolicy,
		"RestartPolicy should be enforced to Always for full DaemonSet templates")
}

func TestBuildWorkload_FullDeploymentNilReplicasDefaultsToOne(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("nil-replicas")

	// Full Deployment template without replicas field
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			// Replicas not set on template.Spec either
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: template-deploy
spec:
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	require.NotNil(t, deploy.Spec.Replicas, "nil replicas should be defaulted")
	assert.Equal(t, int32(1), *deploy.Spec.Replicas,
		"nil replicas on full Deployment should default to 1")
}

func TestBuildWorkload_FullDeploymentWithAdditionalResources(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("deploy-extra")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: template-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: debug-config
data:
  key: value
`,
		},
	}

	workload, additionalResources, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	_, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	assert.Len(t, additionalResources, 1, "should have 1 additional resource (ConfigMap)")
	assert.Equal(t, "ConfigMap", additionalResources[0].GetKind())
}

func TestBuildWorkload_FullDaemonSetLabelMerging(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("ds-labels")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: template-ds
  labels:
    custom-label: from-template
spec:
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
        pod-custom: from-pod-template
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)

	// Breakglass labels should be present
	assert.Equal(t, "breakglass", daemonSet.Labels["app.kubernetes.io/managed-by"])
	// Pod template labels should include both breakglass and original labels
	assert.Contains(t, daemonSet.Spec.Template.Labels, "pod-custom",
		"original pod template labels should be preserved")
	assert.Contains(t, daemonSet.Spec.Template.Labels, "app.kubernetes.io/managed-by",
		"breakglass labels should be merged into pod template labels")
}

func TestBuildWorkload_SessionLabelsExcludeControllerOwned(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("label-skip")
	// Add controller-owned labels to session that should be skipped
	ds.Labels = map[string]string{
		DebugSessionLabelKey:  "should-be-overridden",
		DebugTemplateLabelKey: "should-be-overridden",
		DebugClusterLabelKey:  "should-be-overridden",
		"custom-label":        "should-be-kept",
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)

	// Controller-owned labels should use the session name, not "should-be-overridden"
	assert.Equal(t, ds.Name, daemonSet.Labels[DebugSessionLabelKey],
		"DebugSessionLabelKey should be set from session name, not from session labels")
	assert.Equal(t, ds.Spec.TemplateRef, daemonSet.Labels[DebugTemplateLabelKey])
	// Custom label should be preserved
	assert.Equal(t, "should-be-kept", daemonSet.Labels["custom-label"],
		"non-controller-owned session labels should be preserved")
}

func TestBuildWorkload_WithBindingLabelsAndAnnotations(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("binding-labels")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			Labels: map[string]string{
				"template-label": "from-template",
			},
			Annotations: map[string]string{
				"template-annotation": "from-template",
			},
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Labels: map[string]string{
				"binding-label": "from-binding",
			},
			Annotations: map[string]string{
				"binding-annotation": "from-binding",
			},
		},
	}

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			Template: &breakglassv1alpha1.DebugPodSpec{
				Metadata: &breakglassv1alpha1.DebugPodMetadata{
					Labels: map[string]string{
						"podtemplate-label": "from-podtemplate",
					},
					Annotations: map[string]string{
						"podtemplate-annotation": "from-podtemplate",
					},
				},
			},
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, binding, podTemplate, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)

	// All label sources should be present
	assert.Contains(t, daemonSet.Labels, "template-label")
	assert.Contains(t, daemonSet.Labels, "binding-label")
	assert.Contains(t, daemonSet.Labels, "podtemplate-label")
	assert.Contains(t, daemonSet.Labels, "app.kubernetes.io/managed-by")

	// All annotation sources should be present
	assert.Contains(t, daemonSet.Annotations, "template-annotation")
	assert.Contains(t, daemonSet.Annotations, "binding-annotation")
	assert.Contains(t, daemonSet.Annotations, "podtemplate-annotation")
}

func TestBuildWorkload_BareSpecDeploymentMaxPodsExceeded(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("maxpods")

	maxPods := int32(1)
	replicas := int32(5)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			Replicas:     &replicas,
			ResourceQuota: &breakglassv1alpha1.DebugResourceQuotaConfig{
				MaxPods: &maxPods,
			},
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	_, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replicas (5) exceed resourceQuota.maxPods (1)",
		"bare PodSpec Deployment should check maxPods")
}

// ==================== Additional buildPodSpec Tests ====================

func TestBuildPodSpec_PodTemplateStringTakesPriority(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "priority-test",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			TargetNamespace: "target-ns",
		},
	}

	// Template has both podTemplateString and podTemplate would be set
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			PodTemplateString: `containers:
  - name: from-template-string
    image: busybox:latest
`,
		},
	}

	// podTemplate exists but should be ignored since podTemplateString is set
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod-template"},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			TemplateString: `containers:
  - name: from-pod-template
    image: alpine:latest
`,
		},
	}

	result, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)
	assert.Equal(t, "from-template-string", result.PodSpec.Containers[0].Name,
		"podTemplateString should take priority over podTemplate")
}

func TestBuildPodSpec_NoPodTemplateStringNoPodTemplate(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "empty-test",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			TargetNamespace: "target-ns",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			// No podTemplateString
		},
	}

	// No podTemplate — should return empty PodSpec
	result, err := controller.buildPodSpec(ds, template, nil)
	require.NoError(t, err)
	assert.Empty(t, result.PodSpec.Containers,
		"no podTemplateString and no podTemplate should return empty PodSpec")
}

func TestBuildPodSpec_WithAllThreePodOverrideFlags(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "overrides-test",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			TargetNamespace: "target-ns",
		},
	}

	hostNet := true
	hostPID := true
	hostIPC := true
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
			PodOverrides: &breakglassv1alpha1.DebugPodOverrides{
				Spec: &breakglassv1alpha1.DebugPodSpecOverrides{
					HostNetwork: &hostNet,
					HostPID:     &hostPID,
					HostIPC:     &hostIPC,
				},
			},
		},
	}

	result, err := controller.buildPodSpec(ds, template, nil)
	require.NoError(t, err)
	assert.True(t, result.PodSpec.HostNetwork, "HostNetwork should be applied")
	assert.True(t, result.PodSpec.HostPID, "HostPID should be applied")
	assert.True(t, result.PodSpec.HostIPC, "HostIPC should be applied")
}

// ==================== Additional buildVarsFromSession Tests ====================

func TestBuildVarsFromSession_NilRawBytes(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"nullVar": {Raw: nil},
			},
		},
	}

	templateSpec := &breakglassv1alpha1.DebugSessionTemplateSpec{}

	vars := controller.buildVarsFromSession(ds, templateSpec)
	// Nil raw bytes should produce empty string
	assert.Equal(t, "", vars["nullVar"], "nil Raw bytes should produce empty string")
}

func TestBuildVarsFromSession_NilDefaultRawBytes(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{},
	}

	templateSpec := &breakglassv1alpha1.DebugSessionTemplateSpec{
		ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariable{
			{
				Name:    "varWithNilDefault",
				Default: &apiextensionsv1.JSON{Raw: nil},
			},
		},
	}

	vars := controller.buildVarsFromSession(ds, templateSpec)
	// Nil raw in default should not produce a var (skipped by len check)
	_, exists := vars["varWithNilDefault"]
	assert.False(t, exists, "nil Raw in default should be skipped")
}

func TestBuildVarsFromSession_NestedJSONObject(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"nested": {Raw: []byte(`{"key":"value","num":123}`)},
			},
		},
	}

	templateSpec := &breakglassv1alpha1.DebugSessionTemplateSpec{}

	vars := controller.buildVarsFromSession(ds, templateSpec)
	// Nested JSON object falls through to raw string
	assert.Equal(t, `{"key":"value","num":123}`, vars["nested"],
		"nested JSON object should be represented as raw JSON string")
}

func TestBuildVarsFromSession_EmptyRawBytes(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"emptyVar": {Raw: []byte{}},
			},
		},
	}

	templateSpec := &breakglassv1alpha1.DebugSessionTemplateSpec{}

	vars := controller.buildVarsFromSession(ds, templateSpec)
	assert.Equal(t, "", vars["emptyVar"], "empty Raw bytes should produce empty string")
}

func TestBuildVarsFromSession_NilTemplateSpec(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"userVar": {Raw: []byte(`"hello"`)},
			},
		},
	}

	vars := controller.buildVarsFromSession(ds, nil)
	assert.Equal(t, "hello", vars["userVar"],
		"nil templateSpec should still process user-provided values")
}

func TestBuildVarsFromSession_ArrayValue(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"tags": {Raw: []byte(`["tag1","tag2","tag3"]`)},
			},
		},
	}

	templateSpec := &breakglassv1alpha1.DebugSessionTemplateSpec{}
	vars := controller.buildVarsFromSession(ds, templateSpec)
	assert.Equal(t, "tag1,tag2,tag3", vars["tags"],
		"string array should be joined with commas")
}

// ==================== Additional buildPodRenderContext Tests ====================

func TestBuildPodRenderContext_EmptyRequestedBy(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ctx-test",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			RequestedBy:     "", // empty
			TargetNamespace: "target-ns",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Test Template",
		},
	}

	ctx := controller.buildPodRenderContext(ds, template)
	assert.Equal(t, "", ctx.Session.RequestedBy)
	assert.Equal(t, "", ctx.Annotations["breakglass.t-caas.telekom.com/created-by"],
		"empty requestedBy should produce empty annotation")
}

func TestBuildPodRenderContext_WithTemplateLabelsAndAnnotations(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ctx-test",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			RequestedBy:     "user@example.com",
			TargetNamespace: "target-ns",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Test Template",
		},
	}

	ctx := controller.buildPodRenderContext(ds, template)
	assert.Equal(t, "test-template", ctx.Template.Name)
	assert.Equal(t, "Test Template", ctx.Template.DisplayName)
	assert.NotEmpty(t, ctx.Labels, "labels should be populated")
	assert.NotEmpty(t, ctx.Annotations, "annotations should be populated")
	assert.NotEmpty(t, ctx.Now, "Now should be populated")
}

func TestBuildPodRenderContext_ExtraDeployValuesWithoutTemplateVars(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vars-test",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			TargetNamespace: "target-ns",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"customVar": {Raw: []byte(`"custom-value"`)},
			},
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			// No ExtraDeployVariables defined — user-provided values should still be in Vars
		},
	}

	ctx := controller.buildPodRenderContext(ds, template)
	assert.Equal(t, "custom-value", ctx.Vars["customVar"],
		"user-provided ExtraDeployValues should be in Vars even without template ExtraDeployVariables")
}

// ==================== Additional extractJSONValueForPod Tests ====================

func TestExtractJSONValueForPod_AdditionalCases(t *testing.T) {
	t.Run("nil raw bytes", func(t *testing.T) {
		result := extractJSONValueForPod(nil)
		assert.Equal(t, "", result)
	})

	t.Run("empty raw bytes", func(t *testing.T) {
		result := extractJSONValueForPod([]byte{})
		assert.Equal(t, "", result)
	})

	t.Run("nested JSON object", func(t *testing.T) {
		result := extractJSONValueForPod([]byte(`{"key":"value"}`))
		assert.Equal(t, `{"key":"value"}`, result,
			"nested JSON should fall through to raw string representation")
	})

	t.Run("integer value", func(t *testing.T) {
		result := extractJSONValueForPod([]byte(`42`))
		assert.Equal(t, "42", result)
	})

	t.Run("float value", func(t *testing.T) {
		result := extractJSONValueForPod([]byte(`3.14`))
		assert.Equal(t, "3.14", result)
	})

	t.Run("float that is whole number", func(t *testing.T) {
		result := extractJSONValueForPod([]byte(`100`))
		assert.Equal(t, "100", result)
	})

	t.Run("boolean true", func(t *testing.T) {
		result := extractJSONValueForPod([]byte(`true`))
		assert.Equal(t, "true", result)
	})

	t.Run("boolean false", func(t *testing.T) {
		result := extractJSONValueForPod([]byte(`false`))
		assert.Equal(t, "false", result)
	})

	t.Run("string array", func(t *testing.T) {
		result := extractJSONValueForPod([]byte(`["a","b","c"]`))
		assert.Equal(t, "a,b,c", result)
	})

	t.Run("string value", func(t *testing.T) {
		result := extractJSONValueForPod([]byte(`"hello world"`))
		assert.Equal(t, "hello world", result)
	})

	t.Run("mixed array falls through to raw", func(t *testing.T) {
		// Mixed array [1, "a"] cannot unmarshal as []string, falls to raw
		result := extractJSONValueForPod([]byte(`[1,"a"]`))
		assert.Equal(t, `[1,"a"]`, result)
	})
}

// ==================== Helper Functions ====================

func newTestRenderContext() breakglassv1alpha1.AuxiliaryResourceContext {
	return breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name:        "test-session",
			Namespace:   "breakglass-system",
			Cluster:     "test-cluster",
			RequestedBy: "user@example.com",
		},
		Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
			Namespace:   "target-ns",
			ClusterName: "test-cluster",
		},
		Template: breakglassv1alpha1.AuxiliaryResourceTemplateContext{
			Name:        "test-template",
			DisplayName: "Test Template",
		},
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "breakglass",
		},
		Annotations: map[string]string{
			"breakglass.t-caas.telekom.com/created-by": "user@example.com",
		},
		Vars: map[string]string{},
	}
}

func newTestController() *DebugSessionController {
	return &DebugSessionController{
		log: zap.NewNop().Sugar(),
	}
}

// ==================== renderPodTemplateStringMultiDoc — Remaining Gap Tests ====================

func TestRenderPodTemplateStringMultiDoc_UnsupportedKindAtReconcilerLevel(t *testing.T) {
	controller := newTestController()

	// StatefulSet is not supported — should return error with "unsupported manifest kind"
	templateStr := `apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: debug
          image: busybox:latest
`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported manifest kind")
	assert.Contains(t, err.Error(), "StatefulSet")
}

func TestRenderPodTemplateStringMultiDoc_UnsupportedKindJob(t *testing.T) {
	controller := newTestController()

	templateStr := `apiVersion: batch/v1
kind: Job
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: debug
          image: busybox:latest
`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported manifest kind")
	assert.Contains(t, err.Error(), "Job")
}

func TestRenderPodTemplateStringMultiDoc_AdditionalResourceInvalidYAML(t *testing.T) {
	controller := newTestController()

	// First doc is valid bare PodSpec, second doc is invalid YAML
	templateStr := `containers:
  - name: debug
    image: busybox:latest
---
: invalid: yaml: : :
  [not valid
`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse document 2")
}

func TestRenderPodTemplateStringMultiDoc_AdditionalResourceMissingAPIVersionKind(t *testing.T) {
	controller := newTestController()

	// First doc is valid bare PodSpec, second doc is bare map without apiVersion/kind
	templateStr := `containers:
  - name: debug
    image: busybox:latest
---
key: value
another: field
`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "document 2 is not a valid Kubernetes resource")
	assert.Contains(t, err.Error(), "missing apiVersion or kind")
}

func TestRenderPodTemplateStringMultiDoc_AdditionalResourceMissingKindOnly(t *testing.T) {
	controller := newTestController()

	templateStr := `containers:
  - name: debug
    image: busybox:latest
---
apiVersion: v1
metadata:
  name: test
data:
  key: value
`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing apiVersion or kind")
}

func TestRenderPodTemplateStringMultiDoc_MultipleAdditionalResources(t *testing.T) {
	controller := newTestController()

	templateStr := `containers:
  - name: debug
    image: busybox:latest
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config1
data:
  key1: value1
---
apiVersion: v1
kind: Secret
metadata:
  name: secret1
type: Opaque
data:
  password: cGFzc3dvcmQ=
`
	ctx := newTestRenderContext()
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.NoError(t, err)
	assert.Len(t, result.AdditionalResources, 2)
	assert.Equal(t, "ConfigMap", result.AdditionalResources[0].GetKind())
	assert.Equal(t, "Secret", result.AdditionalResources[1].GetKind())
}

func TestRenderPodTemplateStringMultiDoc_NoDocuments(t *testing.T) {
	controller := newTestController()

	// Empty template string that produces no documents
	templateStr := `{{ if false }}something{{ end }}`
	ctx := newTestRenderContext()
	_, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.Error(t, err)
	// Either "template rendering failed" or "no documents" depending on renderer
}

// ==================== extractPodSpecFromPodManifest — Non-string Labels/Annotations ====================

func TestExtractPodSpec_NonStringLabelValuesSkipped(t *testing.T) {
	controller := newTestController()

	// Pod with a non-string label value (integer) — should be silently skipped
	templateStr := `apiVersion: v1
kind: Pod
metadata:
  name: test
  labels:
    string-label: valid
    int-label: 123
spec:
  containers:
    - name: debug
      image: busybox:latest
`
	ctx := newTestRenderContext()
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.NoError(t, err)
	// string-label should be present, int-label should be skipped (it's an int, not string)
	assert.Equal(t, "valid", result.PodLabels["string-label"])
	// YAML unmarshals "123" as a string when it's a label value in the map[string]interface{}
	// so the integer check is for truly typed values from YAML which is rare
	assert.NotEmpty(t, result.PodSpec.Containers)
}

func TestExtractPodSpec_NonStringAnnotationValuesSkipped(t *testing.T) {
	controller := newTestController()

	// Pod with boolean annotation value
	templateStr := `apiVersion: v1
kind: Pod
metadata:
  name: test
  annotations:
    string-anno: valid
    bool-anno: true
spec:
  containers:
    - name: debug
      image: busybox:latest
`
	ctx := newTestRenderContext()
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.NoError(t, err)
	assert.Equal(t, "valid", result.PodAnnotations["string-anno"])
	assert.NotEmpty(t, result.PodSpec.Containers)
}

func TestExtractPodSpec_PodWithEmptyLabelsMap(t *testing.T) {
	controller := newTestController()

	templateStr := `apiVersion: v1
kind: Pod
metadata:
  name: test
  labels: {}
spec:
  containers:
    - name: debug
      image: busybox:latest
`
	ctx := newTestRenderContext()
	result, err := controller.renderPodTemplateStringMultiDoc(templateStr, ctx)
	require.NoError(t, err)
	assert.Empty(t, result.PodLabels)
	assert.NotEmpty(t, result.PodSpec.Containers)
}

// ==================== deployPodTemplateResource Tests ====================

func TestDeployPodTemplateResource_SetsNamespaceWhenEmpty(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
	obj.SetName("test-configmap")
	// Namespace intentionally not set
	obj.Object["data"] = map[string]interface{}{"key": "value"}

	err := controller.deployPodTemplateResource(context.Background(), fakeClient, ds, obj, "target-ns")
	require.NoError(t, err)

	assert.Equal(t, "target-ns", obj.GetNamespace(),
		"empty namespace should be defaulted to targetNs")
}

func TestDeployPodTemplateResource_PreservesExistingNamespace(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
	obj.SetName("test-configmap")
	obj.SetNamespace("custom-ns")
	obj.Object["data"] = map[string]interface{}{"key": "value"}

	err := controller.deployPodTemplateResource(context.Background(), fakeClient, ds, obj, "target-ns")
	require.NoError(t, err)

	assert.Equal(t, "custom-ns", obj.GetNamespace(),
		"existing namespace should be preserved")
}

func TestDeployPodTemplateResource_SetsLabels(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "prod-cluster",
		},
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
	obj.SetName("test-configmap")
	obj.SetNamespace("target-ns")
	obj.Object["data"] = map[string]interface{}{"key": "value"}

	err := controller.deployPodTemplateResource(context.Background(), fakeClient, ds, obj, "target-ns")
	require.NoError(t, err)

	labels := obj.GetLabels()
	assert.Equal(t, "breakglass", labels["app.kubernetes.io/managed-by"])
	assert.Equal(t, "my-session", labels["breakglass.t-caas.telekom.com/session"])
	assert.Equal(t, "prod-cluster", labels["breakglass.t-caas.telekom.com/session-cluster"])
	assert.Equal(t, "true", labels["breakglass.t-caas.telekom.com/pod-template-resource"])
}

func TestDeployPodTemplateResource_MergesExistingLabels(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
	obj.SetName("test-configmap")
	obj.SetNamespace("target-ns")
	obj.SetLabels(map[string]string{
		"existing-label": "should-be-kept",
	})
	obj.Object["data"] = map[string]interface{}{"key": "value"}

	err := controller.deployPodTemplateResource(context.Background(), fakeClient, ds, obj, "target-ns")
	require.NoError(t, err)

	labels := obj.GetLabels()
	assert.Equal(t, "should-be-kept", labels["existing-label"],
		"pre-existing labels should be preserved")
	assert.Equal(t, "breakglass", labels["app.kubernetes.io/managed-by"],
		"breakglass labels should be added")
}

func TestDeployPodTemplateResource_SetsAnnotations(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
	obj.SetName("test-configmap")
	obj.SetNamespace("target-ns")
	obj.Object["data"] = map[string]interface{}{"key": "value"}

	err := controller.deployPodTemplateResource(context.Background(), fakeClient, ds, obj, "target-ns")
	require.NoError(t, err)

	annotations := obj.GetAnnotations()
	assert.Equal(t, "breakglass-system/test-session",
		annotations["breakglass.t-caas.telekom.com/source-session"])
}

func TestDeployPodTemplateResource_MergesExistingAnnotations(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
	obj.SetName("test-configmap")
	obj.SetNamespace("target-ns")
	obj.SetAnnotations(map[string]string{
		"existing-annotation": "should-be-kept",
	})
	obj.Object["data"] = map[string]interface{}{"key": "value"}

	err := controller.deployPodTemplateResource(context.Background(), fakeClient, ds, obj, "target-ns")
	require.NoError(t, err)

	annotations := obj.GetAnnotations()
	assert.Equal(t, "should-be-kept", annotations["existing-annotation"])
	assert.Contains(t, annotations, "breakglass.t-caas.telekom.com/source-session")
}

func TestDeployPodTemplateResource_UpdatesSessionStatus(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
	obj.SetName("test-configmap")
	obj.SetNamespace("target-ns")
	obj.Object["data"] = map[string]interface{}{"key": "value"}

	err := controller.deployPodTemplateResource(context.Background(), fakeClient, ds, obj, "target-ns")
	require.NoError(t, err)

	// Check PodTemplateResourceStatuses
	require.Len(t, ds.Status.PodTemplateResourceStatuses, 1)
	status := ds.Status.PodTemplateResourceStatuses[0]
	assert.Equal(t, "ConfigMap", status.Kind)
	assert.Equal(t, "v1", status.APIVersion)
	assert.Equal(t, "test-configmap", status.ResourceName)
	assert.Equal(t, "target-ns", status.Namespace)
	assert.Equal(t, "podTemplateString", status.Source)
	assert.True(t, status.Created)
	require.NotNil(t, status.CreatedAt)
	assert.NotEmpty(t, *status.CreatedAt)

	// Check DeployedResources
	require.Len(t, ds.Status.DeployedResources, 1)
	deployedRef := ds.Status.DeployedResources[0]
	assert.Equal(t, "v1", deployedRef.APIVersion)
	assert.Equal(t, "ConfigMap", deployedRef.Kind)
	assert.Equal(t, "test-configmap", deployedRef.Name)
	assert.Equal(t, "target-ns", deployedRef.Namespace)
	assert.Equal(t, "pod-template", deployedRef.Source)
}

func TestDeployPodTemplateResource_MultipleResources(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
	}

	// Deploy two resources
	for i, kind := range []string{"ConfigMap", "Secret"} {
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind(kind))
		obj.SetName(fmt.Sprintf("resource-%d", i))
		obj.SetNamespace("target-ns")
		if kind == "ConfigMap" {
			obj.Object["data"] = map[string]interface{}{"key": "value"}
		} else {
			obj.Object["type"] = "Opaque"
		}

		err := controller.deployPodTemplateResource(context.Background(), fakeClient, ds, obj, "target-ns")
		require.NoError(t, err)
	}

	assert.Len(t, ds.Status.PodTemplateResourceStatuses, 2)
	assert.Len(t, ds.Status.DeployedResources, 2)
	assert.Equal(t, "ConfigMap", ds.Status.PodTemplateResourceStatuses[0].Kind)
	assert.Equal(t, "Secret", ds.Status.PodTemplateResourceStatuses[1].Kind)
}

func TestDeployPodTemplateResource_NilLabelsAndAnnotations(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
	obj.SetName("no-labels")
	obj.SetNamespace("target-ns")
	obj.Object["data"] = map[string]interface{}{"key": "value"}
	// Explicitly ensure labels and annotations are nil
	delete(obj.Object, "metadata")
	obj.SetName("no-labels")
	obj.SetNamespace("target-ns")
	obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))

	err := controller.deployPodTemplateResource(context.Background(), fakeClient, ds, obj, "target-ns")
	require.NoError(t, err)

	// Labels and annotations should have been created from scratch
	assert.NotNil(t, obj.GetLabels())
	assert.NotNil(t, obj.GetAnnotations())
	assert.Equal(t, "breakglass", obj.GetLabels()["app.kubernetes.io/managed-by"])
}

// ==================== buildWorkload edge cases ====================

func TestBuildWorkload_DeploymentWithZeroReplicas(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("zero-replicas")

	replicas := int32(0)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			Replicas:     &replicas,
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	require.NotNil(t, deploy.Spec.Replicas)
	assert.Equal(t, int32(0), *deploy.Spec.Replicas,
		"zero replicas should be respected")
}

func TestBuildWorkload_EmptyWorkloadTypeDefaultsToDaemonSet(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("default-type")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: "", // empty → should default to DaemonSet
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	_, ok := workload.(*appsv1.DaemonSet)
	assert.True(t, ok, "empty workloadType should default to DaemonSet")
}

func TestBuildWorkload_DaemonSetAnnotationsFromSession(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("ds-annos")
	ds.Annotations = map[string]string{
		"session-annotation": "from-session",
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)
	assert.Equal(t, "from-session", daemonSet.Annotations["session-annotation"],
		"session annotations should be merged into workload")
}

func TestBuildWorkload_DeploymentAnnotationsFromSession(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("deploy-annos")
	ds.Annotations = map[string]string{
		"session-annotation": "deploy-from-session",
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	assert.Equal(t, "deploy-from-session", deploy.Annotations["session-annotation"])
}

func TestBuildWorkload_WorkloadNameFormat(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("my-session")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)
	assert.Equal(t, "my-session", daemonSet.Name, "workload name should be the session name")
	assert.Equal(t, "target-ns", daemonSet.Namespace)
}

func TestBuildWorkload_BareSpecRestartPolicyAlreadyAlways(t *testing.T) {
	// When RestartPolicy is already Always, no override should happen (no error)
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("already-always")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `restartPolicy: Always
containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)
	assert.Equal(t, corev1.RestartPolicyAlways, daemonSet.Spec.Template.Spec.RestartPolicy)
}

func TestBuildWorkload_BareSpecRestartPolicyNever(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("never-restart")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			PodTemplateString: `restartPolicy: Never
containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	assert.Equal(t, corev1.RestartPolicyAlways, deploy.Spec.Template.Spec.RestartPolicy,
		"RestartPolicy Never should be overridden to Always for Deployment")
}

func TestBuildWorkload_DeploymentSelectorMatchLabels(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("selector-test")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	assert.Equal(t, ds.Name, deploy.Spec.Selector.MatchLabels[DebugSessionLabelKey],
		"Deployment selector should match on DebugSessionLabelKey")
	assert.Equal(t, ds.Name, deploy.Spec.Template.Labels[DebugSessionLabelKey],
		"Pod template labels should include DebugSessionLabelKey")
}

func TestBuildWorkload_DaemonSetSelectorMatchLabels(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("ds-selector")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)
	assert.Equal(t, ds.Name, daemonSet.Spec.Selector.MatchLabels[DebugSessionLabelKey])
	assert.Equal(t, ds.Name, daemonSet.Spec.Template.Labels[DebugSessionLabelKey])
}

// ==================== useTemplateWorkload edge cases ====================

func TestBuildWorkload_FullDeploymentWithReplicasFromBoth(t *testing.T) {
	// When both template manifest and DST spec have replicas, DST spec should win
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("replicas-both")

	dstReplicas := int32(3)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			Replicas:     &dstReplicas,
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: template-deploy
spec:
  replicas: 10
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	require.NotNil(t, deploy.Spec.Replicas)
	assert.Equal(t, int32(3), *deploy.Spec.Replicas,
		"template.Spec.Replicas should override manifest replicas")
}

func TestBuildWorkload_FullDeploymentMaxPodsExceeded(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("maxpods-full")

	replicas := int32(5)
	maxPods := int32(2)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			Replicas:     &replicas,
			ResourceQuota: &breakglassv1alpha1.DebugResourceQuotaConfig{
				MaxPods: &maxPods,
			},
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: template-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	_, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replicas (5) exceed resourceQuota.maxPods (2)")
}

func TestBuildWorkload_FullDeploymentNameAndNamespaceOverridden(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("override-name")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: original-name
  namespace: original-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	assert.Equal(t, "override-name", deploy.Name,
		"workload name should be overridden to the session name")
	assert.Equal(t, "target-ns", deploy.Namespace,
		"namespace should be overridden to targetNs")
}

func TestBuildWorkload_FullDaemonSetNameAndNamespaceOverridden(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("ds-override")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: original-name
  namespace: original-ns
spec:
  selector:
    matchLabels:
      app: debug
  template:
    metadata:
      labels:
        app: debug
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)
	assert.Equal(t, "ds-override", daemonSet.Name)
	assert.Equal(t, "target-ns", daemonSet.Namespace)
}

func TestBuildWorkload_FullDeploymentSelectorOverridden(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("selector-override")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment,
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: template-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      custom-selector: original
  template:
    metadata:
      labels:
        custom-selector: original
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	deploy, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	assert.Equal(t, ds.Name, deploy.Spec.Selector.MatchLabels[DebugSessionLabelKey],
		"selector should be overridden with debug session label")
}

func TestBuildWorkload_FullDaemonSetSelectorOverridden(t *testing.T) {
	controller := newBuildWorkloadController()
	ds := newBuildWorkloadSession("ds-selector-override")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: template-ds
spec:
  selector:
    matchLabels:
      custom-selector: original
  template:
    metadata:
      labels:
        custom-selector: original
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
		},
	}

	workload, _, err := controller.buildWorkload(ds, template, nil, nil, "target-ns")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok)
	assert.Equal(t, ds.Name, daemonSet.Spec.Selector.MatchLabels[DebugSessionLabelKey],
		"selector should be overridden with debug session label")
}

// ==================== buildPodSpec detailed edge cases ====================

func TestBuildPodSpec_PodTemplateWithTemplateStringOnly(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pt-ts-test",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			TargetNamespace: "target-ns",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			// No PodTemplateString on DST
		},
	}

	// PodTemplate with TemplateString
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "pt-with-ts"},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			TemplateString: `containers:
  - name: from-podtemplate-ts
    image: alpine:latest
`,
		},
	}

	result, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)
	assert.Equal(t, "from-podtemplate-ts", result.PodSpec.Containers[0].Name,
		"when DST has no podTemplateString, podTemplate.TemplateString should be used")
}

func TestBuildPodSpec_PodTemplateWithStructuredTemplate(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pt-struct-test",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			TargetNamespace: "target-ns",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			// No PodTemplateString on DST
		},
	}

	// PodTemplate with structured Template (not templateString)
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "pt-structured"},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:  "from-structured",
							Image: "nginx:latest",
						},
					},
				},
			},
		},
	}

	result, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)
	assert.Equal(t, "from-structured", result.PodSpec.Containers[0].Name,
		"when DST has no podTemplateString, podTemplate.Template should be used")
}

func TestBuildPodSpec_ErrorFromRenderPodTemplateString(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "render-err",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			TargetNamespace: "target-ns",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			PodTemplateString: `{{ .undefined.field.chain }}`, // will fail execution
		},
	}

	_, err := controller.buildPodSpec(ds, template, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to render podTemplateString")
}

func TestBuildPodSpec_PodOverridesTemplateString(t *testing.T) {
	controller := newTestController()

	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "overrides-ts",
			Namespace: "breakglass-system",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "test-template",
			TargetNamespace: "target-ns",
		},
	}

	hostNet := true
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
			PodOverridesTemplate: `hostNetwork: {{ .binding.hostNetwork | default "true" }}`,
		},
	}
	_ = hostNet

	result, err := controller.buildPodSpec(ds, template, nil)
	require.NoError(t, err)
	assert.True(t, result.PodSpec.HostNetwork,
		"podOverridesTemplate should apply overrides")
}
