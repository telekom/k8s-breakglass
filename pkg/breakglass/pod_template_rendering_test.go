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

package breakglass

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildPodRenderContext(t *testing.T) {
	logger := zap.NewNop().Sugar()
	controller := &DebugSessionController{
		log: logger,
	}

	ds := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: v1alpha1.DebugSessionSpec{
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
		Status: v1alpha1.DebugSessionStatus{
			Approval: &v1alpha1.DebugSessionApproval{
				ApprovedBy: "admin@example.com",
				ApprovedAt: &metav1.Time{},
			},
		},
	}

	template := &v1alpha1.DebugSessionTemplate{
		Spec: v1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Test Template",
			ExtraDeployVariables: []v1alpha1.ExtraDeployVariable{
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
		ds           *v1alpha1.DebugSession
		templateSpec *v1alpha1.DebugSessionTemplateSpec
		want         map[string]string
	}{
		{
			name: "no variables",
			ds: &v1alpha1.DebugSession{
				Spec: v1alpha1.DebugSessionSpec{},
			},
			templateSpec: &v1alpha1.DebugSessionTemplateSpec{},
			want:         map[string]string{},
		},
		{
			name: "defaults only",
			ds: &v1alpha1.DebugSession{
				Spec: v1alpha1.DebugSessionSpec{},
			},
			templateSpec: &v1alpha1.DebugSessionTemplateSpec{
				ExtraDeployVariables: []v1alpha1.ExtraDeployVariable{
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
			ds: &v1alpha1.DebugSession{
				Spec: v1alpha1.DebugSessionSpec{
					ExtraDeployValues: map[string]apiextensionsv1.JSON{
						"size": {Raw: []byte(`"50Gi"`)},
					},
				},
			},
			templateSpec: &v1alpha1.DebugSessionTemplateSpec{
				ExtraDeployVariables: []v1alpha1.ExtraDeployVariable{
					{Name: "size", Default: &apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)}},
				},
			},
			want: map[string]string{
				"size": "50Gi",
			},
		},
		{
			name: "various data types",
			ds: &v1alpha1.DebugSession{
				Spec: v1alpha1.DebugSessionSpec{
					ExtraDeployValues: map[string]apiextensionsv1.JSON{
						"stringVal": {Raw: []byte(`"hello"`)},
						"boolVal":   {Raw: []byte(`false`)},
						"intVal":    {Raw: []byte(`42`)},
						"floatVal":  {Raw: []byte(`3.14`)},
						"arrayVal":  {Raw: []byte(`["a","b","c"]`)},
					},
				},
			},
			templateSpec: &v1alpha1.DebugSessionTemplateSpec{},
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
		ctx         v1alpha1.AuxiliaryResourceContext
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
			ctx: v1alpha1.AuxiliaryResourceContext{},
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
			ctx: v1alpha1.AuxiliaryResourceContext{
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
			ctx: v1alpha1.AuxiliaryResourceContext{
				Session: v1alpha1.AuxiliaryResourceSessionContext{
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
			ctx: v1alpha1.AuxiliaryResourceContext{
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
			ctx:         v1alpha1.AuxiliaryResourceContext{},
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
		ctx           v1alpha1.AuxiliaryResourceContext
		wantOverrides *v1alpha1.DebugPodSpecOverrides
		wantErr       bool
	}{
		{
			name: "simple overrides",
			templateStr: `
hostNetwork: true
hostPID: false
`,
			ctx: v1alpha1.AuxiliaryResourceContext{},
			wantOverrides: &v1alpha1.DebugPodSpecOverrides{
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
			ctx: v1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{
					"enableHostNetwork": "true",
					"enableHostPID":     "false",
				},
			},
			wantOverrides: &v1alpha1.DebugPodSpecOverrides{
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
			ctx: v1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{
					"enableHostNetwork": "false",
				},
			},
			wantOverrides: &v1alpha1.DebugPodSpecOverrides{},
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
		overrides *v1alpha1.DebugPodSpecOverrides
		wantSpec  corev1.PodSpec
	}{
		{
			name: "apply host network",
			spec: corev1.PodSpec{
				HostNetwork: false,
			},
			overrides: &v1alpha1.DebugPodSpecOverrides{
				HostNetwork: &trueVal,
			},
			wantSpec: corev1.PodSpec{
				HostNetwork: true,
			},
		},
		{
			name: "apply all overrides",
			spec: corev1.PodSpec{},
			overrides: &v1alpha1.DebugPodSpecOverrides{
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
			overrides: &v1alpha1.DebugPodSpecOverrides{},
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

	ds := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: v1alpha1.DebugSessionSpec{
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

	template := &v1alpha1.DebugSessionTemplate{
		Spec: v1alpha1.DebugSessionTemplateSpec{
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
			ExtraDeployVariables: []v1alpha1.ExtraDeployVariable{
				{Name: "pvcSize", Default: &apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)}},
			},
		},
	}

	spec, err := controller.buildPodSpec(ds, template, nil)
	require.NoError(t, err)

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

	ds := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: v1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "network-debug",
			TargetNamespace: "target-ns",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"enableHostNetwork": {Raw: []byte(`true`)},
			},
		},
	}

	podTemplate := &v1alpha1.DebugPodTemplate{
		Spec: v1alpha1.DebugPodTemplateSpec{
			Template: &v1alpha1.DebugPodSpec{
				Spec: v1alpha1.DebugPodSpecInner{
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

	template := &v1alpha1.DebugSessionTemplate{
		Spec: v1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Network Debug",
			PodOverridesTemplate: `
{{- if eq .vars.enableHostNetwork "true" }}
hostNetwork: true
hostPID: true
{{- end }}
`,
			ExtraDeployVariables: []v1alpha1.ExtraDeployVariable{
				{Name: "enableHostNetwork", Default: &apiextensionsv1.JSON{Raw: []byte(`false`)}},
			},
		},
	}

	spec, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)

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

	ds := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: v1alpha1.DebugSessionSpec{
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
	podTemplate := &v1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dynamic-pod-template",
		},
		Spec: v1alpha1.DebugPodTemplateSpec{
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
	template := &v1alpha1.DebugSessionTemplate{
		Spec: v1alpha1.DebugSessionTemplateSpec{
			// No PodTemplateString - will use the referenced podTemplate's templateString
		},
	}

	spec, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)

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

	ds := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: v1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			TemplateRef: "invalid-template",
		},
	}

	// DebugPodTemplate with neither template nor templateString (invalid)
	podTemplate := &v1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-pod-template",
		},
		Spec: v1alpha1.DebugPodTemplateSpec{
			// Both Template and TemplateString are nil/empty
		},
	}

	template := &v1alpha1.DebugSessionTemplate{
		Spec: v1alpha1.DebugSessionTemplateSpec{},
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

	ds := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
		},
		Spec: v1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			TemplateRef:     "network-debug",
			TargetNamespace: "target-ns",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				"enableHostNetwork": {Raw: []byte(`false`)},
			},
		},
	}

	podTemplate := &v1alpha1.DebugPodTemplate{
		Spec: v1alpha1.DebugPodTemplateSpec{
			Template: &v1alpha1.DebugPodSpec{
				Spec: v1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox"},
					},
				},
			},
		},
	}

	template := &v1alpha1.DebugSessionTemplate{
		Spec: v1alpha1.DebugSessionTemplateSpec{
			PodOverridesTemplate: `
{{- if eq .vars.enableHostNetwork "true" }}
hostNetwork: true
{{- end }}
`,
		},
	}

	spec, err := controller.buildPodSpec(ds, template, podTemplate)
	require.NoError(t, err)

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
