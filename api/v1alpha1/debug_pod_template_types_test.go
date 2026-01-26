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

package v1alpha1

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDebugPodTemplate_BasicStructure(t *testing.T) {
	tests := []struct {
		name     string
		template DebugPodTemplate
		wantErr  bool
	}{
		{
			name: "valid basic template",
			template: DebugPodTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name: "basic-debug",
				},
				Spec: DebugPodTemplateSpec{
					DisplayName: "Basic Debug",
					Description: "A basic debug container",
					Template: DebugPodSpec{
						Spec: DebugPodSpecInner{
							Containers: []corev1.Container{
								{
									Name:  "debug",
									Image: "busybox:latest",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "template with host namespaces",
			template: DebugPodTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name: "privileged-debug",
				},
				Spec: DebugPodTemplateSpec{
					Template: DebugPodSpec{
						Spec: DebugPodSpecInner{
							HostNetwork: true,
							HostPID:     true,
							HostIPC:     true,
							Containers: []corev1.Container{
								{
									Name:  "debug",
									Image: "nicolaka/netshoot:latest",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the template can be created
			if tt.template.Name == "" && !tt.wantErr {
				t.Error("Expected template name to be set")
			}
		})
	}
}

func TestDebugPodTemplate_WithResources(t *testing.T) {
	template := DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "resource-limited-debug",
		},
		Spec: DebugPodTemplateSpec{
			DisplayName: "Resource Limited Debug",
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: "busybox:latest",
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
						},
					},
				},
			},
		},
	}

	if len(template.Spec.Template.Spec.Containers) != 1 {
		t.Errorf("Expected 1 container, got %d", len(template.Spec.Template.Spec.Containers))
	}

	container := template.Spec.Template.Spec.Containers[0]
	if container.Resources.Limits.Cpu().String() != "500m" {
		t.Errorf("Expected CPU limit 500m, got %s", container.Resources.Limits.Cpu().String())
	}
	if container.Resources.Limits.Memory().String() != "512Mi" {
		t.Errorf("Expected memory limit 512Mi, got %s", container.Resources.Limits.Memory().String())
	}
}

func TestDebugPodTemplate_WithVolumes(t *testing.T) {
	template := DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "volume-debug",
		},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: "busybox:latest",
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "host-root",
									MountPath: "/host",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "host-root",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/",
								},
							},
						},
					},
				},
			},
		},
	}

	if len(template.Spec.Template.Spec.Volumes) != 1 {
		t.Errorf("Expected 1 volume, got %d", len(template.Spec.Template.Spec.Volumes))
	}
	if template.Spec.Template.Spec.Volumes[0].Name != "host-root" {
		t.Errorf("Expected volume name 'host-root', got %s", template.Spec.Template.Spec.Volumes[0].Name)
	}
}

func TestDebugPodTemplate_WithSecurityContext(t *testing.T) {
	runAsUser := int64(1000)
	runAsNonRoot := true
	allowPrivEsc := false

	template := DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "secure-context-debug",
		},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: "busybox:latest",
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:                &runAsUser,
								RunAsNonRoot:             &runAsNonRoot,
								AllowPrivilegeEscalation: &allowPrivEsc,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
						},
					},
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &runAsNonRoot,
					},
				},
			},
		},
	}

	container := template.Spec.Template.Spec.Containers[0]
	if container.SecurityContext == nil {
		t.Fatal("Expected security context to be set")
	}
	if *container.SecurityContext.RunAsUser != 1000 {
		t.Errorf("Expected RunAsUser 1000, got %d", *container.SecurityContext.RunAsUser)
	}
	if !*container.SecurityContext.RunAsNonRoot {
		t.Error("Expected RunAsNonRoot to be true")
	}
	if *container.SecurityContext.AllowPrivilegeEscalation {
		t.Error("Expected AllowPrivilegeEscalation to be false")
	}
}

func TestDebugPodTemplate_WithTolerations(t *testing.T) {
	template := DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "toleration-debug",
		},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: "busybox:latest",
						},
					},
					Tolerations: []corev1.Toleration{
						{
							Operator: corev1.TolerationOpExists,
							Effect:   corev1.TaintEffectNoSchedule,
						},
						{
							Operator: corev1.TolerationOpExists,
							Effect:   corev1.TaintEffectNoExecute,
						},
					},
				},
			},
		},
	}

	if len(template.Spec.Template.Spec.Tolerations) != 2 {
		t.Errorf("Expected 2 tolerations, got %d", len(template.Spec.Template.Spec.Tolerations))
	}
}

func TestDebugPodTemplate_WithLabelsAndAnnotations(t *testing.T) {
	template := DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "labeled-debug",
		},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Metadata: &DebugPodMetadata{
					Labels: map[string]string{
						"app":     "debug",
						"version": "v1",
					},
					Annotations: map[string]string{
						"description": "debug pod",
					},
				},
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: "busybox:latest",
						},
					},
				},
			},
		},
	}

	if template.Spec.Template.Metadata == nil {
		t.Fatal("Expected metadata to be set")
	}
	if template.Spec.Template.Metadata.Labels["app"] != "debug" {
		t.Errorf("Expected label 'app=debug', got %s", template.Spec.Template.Metadata.Labels["app"])
	}
	if template.Spec.Template.Metadata.Annotations["description"] != "debug pod" {
		t.Errorf("Expected annotation 'description=debug pod'")
	}
}

func TestDebugPodTemplate_DeepCopy(t *testing.T) {
	original := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "original",
			Namespace: "default",
		},
		Spec: DebugPodTemplateSpec{
			DisplayName: "Original Template",
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: "busybox:latest",
						},
					},
				},
			},
		},
	}

	copied := original.DeepCopy()

	// Verify deep copy
	if copied.Name != original.Name {
		t.Errorf("Name mismatch: expected %s, got %s", original.Name, copied.Name)
	}
	if copied.Spec.DisplayName != original.Spec.DisplayName {
		t.Errorf("DisplayName mismatch")
	}

	// Modify copy and verify original unchanged
	copied.Spec.DisplayName = "Modified"
	if original.Spec.DisplayName == "Modified" {
		t.Error("DeepCopy modified original")
	}
}

func TestDebugPodTemplateList(t *testing.T) {
	list := &DebugPodTemplateList{
		Items: []DebugPodTemplate{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "template1"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "template2"},
			},
		},
	}

	if len(list.Items) != 2 {
		t.Errorf("Expected 2 items, got %d", len(list.Items))
	}
}

func TestDebugPodTemplate_InitContainers(t *testing.T) {
	template := DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "init-container-debug",
		},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					InitContainers: []corev1.Container{
						{
							Name:    "init",
							Image:   "busybox:latest",
							Command: []string{"echo", "initializing"},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: "busybox:latest",
						},
					},
				},
			},
		},
	}

	if len(template.Spec.Template.Spec.InitContainers) != 1 {
		t.Errorf("Expected 1 init container, got %d", len(template.Spec.Template.Spec.InitContainers))
	}
	if template.Spec.Template.Spec.InitContainers[0].Name != "init" {
		t.Errorf("Expected init container name 'init'")
	}
}

func TestDebugPodTemplate_DNSPolicy(t *testing.T) {
	template := DebugPodTemplate{
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					DNSPolicy: corev1.DNSClusterFirst,
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: "busybox:latest",
						},
					},
				},
			},
		},
	}

	if template.Spec.Template.Spec.DNSPolicy != corev1.DNSClusterFirst {
		t.Errorf("Expected DNSPolicy ClusterFirst")
	}
}

func TestDebugPodTemplate_ServiceAccount(t *testing.T) {
	automount := false
	template := DebugPodTemplate{
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					ServiceAccountName:           "debug-sa",
					AutomountServiceAccountToken: &automount,
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: "busybox:latest",
						},
					},
				},
			},
		},
	}

	if template.Spec.Template.Spec.ServiceAccountName != "debug-sa" {
		t.Error("Expected service account name 'debug-sa'")
	}
	if *template.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Error("Expected AutomountServiceAccountToken to be false")
	}
}

func TestDebugPodTemplate_HostNamespaces(t *testing.T) {
	tests := []struct {
		name        string
		hostNetwork bool
		hostPID     bool
		hostIPC     bool
	}{
		{"no host namespaces", false, false, false},
		{"host network only", true, false, false},
		{"host PID only", false, true, false},
		{"host IPC only", false, false, true},
		{"all host namespaces", true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := DebugPodTemplate{
				Spec: DebugPodTemplateSpec{
					Template: DebugPodSpec{
						Spec: DebugPodSpecInner{
							HostNetwork: tt.hostNetwork,
							HostPID:     tt.hostPID,
							HostIPC:     tt.hostIPC,
							Containers: []corev1.Container{
								{Name: "debug", Image: "busybox"},
							},
						},
					},
				},
			}

			if template.Spec.Template.Spec.HostNetwork != tt.hostNetwork {
				t.Errorf("HostNetwork mismatch: expected %v, got %v", tt.hostNetwork, template.Spec.Template.Spec.HostNetwork)
			}
			if template.Spec.Template.Spec.HostPID != tt.hostPID {
				t.Errorf("HostPID mismatch: expected %v, got %v", tt.hostPID, template.Spec.Template.Spec.HostPID)
			}
			if template.Spec.Template.Spec.HostIPC != tt.hostIPC {
				t.Errorf("HostIPC mismatch: expected %v, got %v", tt.hostIPC, template.Spec.Template.Spec.HostIPC)
			}
		})
	}
}

func TestDebugPodTemplate_NodeSelector(t *testing.T) {
	template := DebugPodTemplate{
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					NodeSelector: map[string]string{
						"node-type": "debug",
						"zone":      "us-east-1a",
					},
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox"},
					},
				},
			},
		},
	}

	if len(template.Spec.Template.Spec.NodeSelector) != 2 {
		t.Errorf("Expected 2 node selector entries, got %d", len(template.Spec.Template.Spec.NodeSelector))
	}
	if template.Spec.Template.Spec.NodeSelector["node-type"] != "debug" {
		t.Error("Expected node-type=debug selector")
	}
}

func TestDebugPodTemplate_Affinity(t *testing.T) {
	template := DebugPodTemplate{
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{
									{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      "kubernetes.io/os",
												Operator: corev1.NodeSelectorOpIn,
												Values:   []string{"linux"},
											},
										},
									},
								},
							},
						},
					},
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox"},
					},
				},
			},
		},
	}

	if template.Spec.Template.Spec.Affinity == nil {
		t.Fatal("Expected affinity to be set")
	}
	if template.Spec.Template.Spec.Affinity.NodeAffinity == nil {
		t.Fatal("Expected node affinity to be set")
	}
}

// Webhook validation tests

func TestDebugPodTemplate_ValidateCreate_Valid(t *testing.T) {
	ctx := context.Background()
	template := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "valid-template",
		},
		Spec: DebugPodTemplateSpec{
			DisplayName: "Valid Template",
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: "busybox:latest",
						},
					},
				},
			},
		},
	}

	warnings, err := template.ValidateCreate(ctx, template)
	if err != nil {
		t.Errorf("ValidateCreate() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() unexpected warnings: %v", warnings)
	}
}

func TestDebugPodTemplate_ValidateCreate_MissingContainers(t *testing.T) {
	ctx := context.Background()
	template := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-template",
		},
		Spec: DebugPodTemplateSpec{
			DisplayName: "Invalid Template",
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{}, // empty
				},
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing containers")
	}
}

func TestDebugPodTemplate_ValidateCreate_DuplicateContainerNames(t *testing.T) {
	ctx := context.Background()
	template := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "duplicate-containers",
		},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox"},
						{Name: "debug", Image: "alpine"}, // duplicate name
					},
				},
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("ValidateCreate() expected error for duplicate container names")
	}
}

func TestDebugPodTemplate_ValidateCreate_MissingContainerName(t *testing.T) {
	ctx := context.Background()
	template := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "missing-container-name",
		},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "", Image: "busybox"}, // empty name
					},
				},
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing container name")
	}
}

func TestDebugPodTemplate_ValidateUpdate(t *testing.T) {
	ctx := context.Background()
	oldTemplate := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "template",
		},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:1.0"},
					},
				},
			},
		},
	}
	newTemplate := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "template",
		},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:2.0"},
					},
				},
			},
		},
	}

	warnings, err := newTemplate.ValidateUpdate(ctx, oldTemplate, newTemplate)
	if err != nil {
		t.Errorf("ValidateUpdate() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateUpdate() unexpected warnings: %v", warnings)
	}
}

func TestDebugPodTemplate_ValidateDelete(t *testing.T) {
	ctx := context.Background()
	template := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "template",
		},
	}

	warnings, err := template.ValidateDelete(ctx, template)
	if err != nil {
		t.Errorf("ValidateDelete() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateDelete() unexpected warnings: %v", warnings)
	}
}

func TestDebugPodTemplate_ValidateCreate_InvalidSpec(t *testing.T) {
	ctx := context.Background()
	template := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "template"},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{},
				},
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("ValidateCreate() expected error for invalid spec")
	}
}

// SetCondition and GetCondition tests

func TestDebugPodTemplate_SetCondition(t *testing.T) {
	template := &DebugPodTemplate{}
	condition := metav1.Condition{
		Type:               string(DebugPodTemplateConditionReady),
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		Message:            "Template is ready",
		LastTransitionTime: metav1.Now(),
	}

	template.SetCondition(condition)

	if len(template.Status.Conditions) != 1 {
		t.Errorf("Expected 1 condition, got %d", len(template.Status.Conditions))
	}
	if template.Status.Conditions[0].Type != string(DebugPodTemplateConditionReady) {
		t.Errorf("Expected condition type %s, got %s", DebugPodTemplateConditionReady, template.Status.Conditions[0].Type)
	}
}

func TestDebugPodTemplate_SetCondition_Update(t *testing.T) {
	template := &DebugPodTemplate{}
	condition1 := metav1.Condition{
		Type:               string(DebugPodTemplateConditionReady),
		Status:             metav1.ConditionFalse,
		Reason:             "Pending",
		LastTransitionTime: metav1.Now(),
	}
	template.SetCondition(condition1)

	condition2 := metav1.Condition{
		Type:               string(DebugPodTemplateConditionReady),
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		LastTransitionTime: metav1.Now(),
	}
	template.SetCondition(condition2)

	if len(template.Status.Conditions) != 1 {
		t.Errorf("Expected 1 condition after update, got %d", len(template.Status.Conditions))
	}
	if template.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Error("Expected condition status to be updated to True")
	}
}

func TestDebugPodTemplate_GetCondition(t *testing.T) {
	template := &DebugPodTemplate{
		Status: DebugPodTemplateStatus{
			Conditions: []metav1.Condition{
				{
					Type:   string(DebugPodTemplateConditionReady),
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	condition := template.GetCondition(string(DebugPodTemplateConditionReady))
	if condition == nil {
		t.Fatal("Expected to find condition")
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("Expected status True, got %v", condition.Status)
	}
}

func TestDebugPodTemplate_GetCondition_NotFound(t *testing.T) {
	template := &DebugPodTemplate{}
	condition := template.GetCondition("non-existent")
	if condition != nil {
		t.Error("Expected nil for non-existent condition")
	}
}

func TestDebugPodTemplate_ValidateUpdate_Invalid(t *testing.T) {
	ctx := context.Background()
	template := &DebugPodTemplate{}

	oldTemplate := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox"},
					},
				},
			},
		},
	}

	newTemplate := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{}, // empty - invalid
				},
			},
		},
	}

	_, err := template.ValidateUpdate(ctx, oldTemplate, newTemplate)
	if err == nil {
		t.Error("ValidateUpdate() expected error for invalid spec")
	}
}

func TestDebugPodTemplate_ValidateCreate_MultipleContainers(t *testing.T) {
	ctx := context.Background()
	template := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "multi-container",
		},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "main", Image: "busybox"},
						{Name: "sidecar", Image: "alpine"},
					},
				},
			},
		},
	}

	warnings, err := template.ValidateCreate(ctx, template)
	if err != nil {
		t.Errorf("ValidateCreate() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() unexpected warnings: %v", warnings)
	}
}

func TestValidateDebugPodTemplateSpec_Nil(t *testing.T) {
	errs := validateDebugPodTemplateSpec(nil)
	if errs != nil {
		t.Errorf("validateDebugPodTemplateSpec(nil) expected nil, got %v", errs)
	}
}

func TestDebugPodTemplate_ValidateCreate_DuplicateContainerNamesTwo(t *testing.T) {
	ctx := context.Background()
	template := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "dup-containers"},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox"},
						{Name: "debug", Image: "alpine"}, // duplicate
					},
				},
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("expected error for duplicate container names")
	}
}

func TestDebugPodTemplate_ValidateCreate_EmptyContainerNameTwo(t *testing.T) {
	ctx := context.Background()
	template := &DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-name"},
		Spec: DebugPodTemplateSpec{
			Template: DebugPodSpec{
				Spec: DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "", Image: "busybox"}, // empty name
					},
				},
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("expected error for empty container name")
	}
}
