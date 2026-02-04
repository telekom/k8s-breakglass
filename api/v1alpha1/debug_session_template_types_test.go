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
	"k8s.io/apimachinery/pkg/runtime"
)

func TestDebugSessionTemplateMode(t *testing.T) {
	tests := []struct {
		name string
		mode DebugSessionTemplateMode
	}{
		{"workload mode", DebugSessionModeWorkload},
		{"kubectl-debug mode", DebugSessionModeKubectlDebug},
		{"hybrid mode", DebugSessionModeHybrid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := DebugSessionTemplate{
				Spec: DebugSessionTemplateSpec{
					Mode: tt.mode,
				},
			}
			if template.Spec.Mode != tt.mode {
				t.Errorf("Expected mode %s, got %s", tt.mode, template.Spec.Mode)
			}
		})
	}
}

func TestDebugWorkloadType(t *testing.T) {
	tests := []struct {
		name         string
		workloadType DebugWorkloadType
	}{
		{"DaemonSet workload", DebugWorkloadDaemonSet},
		{"Deployment workload", DebugWorkloadDeployment},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := DebugSessionTemplate{
				Spec: DebugSessionTemplateSpec{
					WorkloadType: tt.workloadType,
				},
			}
			if template.Spec.WorkloadType != tt.workloadType {
				t.Errorf("Expected workload type %s, got %s", tt.workloadType, template.Spec.WorkloadType)
			}
		})
	}
}

func TestDebugSessionTemplate_BasicWorkloadMode(t *testing.T) {
	replicas := int32(1)
	template := DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "standard-debug",
		},
		Spec: DebugSessionTemplateSpec{
			DisplayName: "Standard Debug",
			Description: "Standard debug session template",
			Mode:        DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-debug",
			},
			WorkloadType:    DebugWorkloadDaemonSet,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			FailMode:        "closed",
		},
	}

	if template.Spec.Mode != DebugSessionModeWorkload {
		t.Errorf("Expected workload mode")
	}
	if template.Spec.PodTemplateRef == nil {
		t.Fatal("Expected pod template reference")
	}
	if template.Spec.PodTemplateRef.Name != "basic-debug" {
		t.Errorf("Expected pod template ref 'basic-debug'")
	}
}

func TestDebugSessionTemplate_KubectlDebugMode(t *testing.T) {
	template := DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kubectl-debug-template",
		},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeKubectlDebug,
			KubectlDebug: &KubectlDebugConfig{
				EphemeralContainers: &EphemeralContainersConfig{
					Enabled:           true,
					AllowedNamespaces: &NamespaceFilter{Patterns: []string{"app-*", "service-*"}},
					DeniedNamespaces:  &NamespaceFilter{Patterns: []string{"kube-system", "kube-public"}},
					AllowedImages:     []string{"busybox:*", "nicolaka/netshoot:*"},
					RequireNonRoot:    true,
					AllowPrivileged:   false,
				},
				NodeDebug: &NodeDebugConfig{
					Enabled:       true,
					AllowedImages: []string{"busybox:*"},
					HostNamespaces: &HostNamespacesConfig{
						HostNetwork: true,
						HostPID:     true,
						HostIPC:     false,
					},
				},
			},
		},
	}

	if template.Spec.Mode != DebugSessionModeKubectlDebug {
		t.Errorf("Expected kubectl-debug mode")
	}
	if template.Spec.KubectlDebug == nil {
		t.Fatal("Expected kubectl debug config")
	}
	if !template.Spec.KubectlDebug.EphemeralContainers.Enabled {
		t.Error("Expected ephemeral containers enabled")
	}
	if !template.Spec.KubectlDebug.NodeDebug.Enabled {
		t.Error("Expected node debug enabled")
	}
}

func TestDebugSessionTemplate_HybridMode(t *testing.T) {
	template := DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "hybrid-debug-template",
		},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeHybrid,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-debug",
			},
			WorkloadType: DebugWorkloadDaemonSet,
			KubectlDebug: &KubectlDebugConfig{
				EphemeralContainers: &EphemeralContainersConfig{
					Enabled: true,
				},
			},
		},
	}

	if template.Spec.Mode != DebugSessionModeHybrid {
		t.Errorf("Expected hybrid mode")
	}
	if template.Spec.PodTemplateRef == nil {
		t.Fatal("Expected pod template reference for hybrid mode")
	}
	if template.Spec.KubectlDebug == nil {
		t.Fatal("Expected kubectl debug config for hybrid mode")
	}
}

func TestDebugSessionTemplate_EphemeralContainersConfig(t *testing.T) {
	tests := []struct {
		name   string
		config EphemeralContainersConfig
	}{
		{
			name: "basic config",
			config: EphemeralContainersConfig{
				Enabled: true,
			},
		},
		{
			name: "with namespace restrictions",
			config: EphemeralContainersConfig{
				Enabled:           true,
				AllowedNamespaces: &NamespaceFilter{Patterns: []string{"default", "app-*"}},
				DeniedNamespaces:  &NamespaceFilter{Patterns: []string{"kube-system"}},
			},
		},
		{
			name: "with image restrictions",
			config: EphemeralContainersConfig{
				Enabled:            true,
				AllowedImages:      []string{"busybox:*", "alpine:*"},
				RequireImageDigest: true,
			},
		},
		{
			name: "with security restrictions",
			config: EphemeralContainersConfig{
				Enabled:         true,
				RequireNonRoot:  true,
				AllowPrivileged: false,
				MaxCapabilities: []string{"NET_ADMIN", "SYS_TIME"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := DebugSessionTemplate{
				Spec: DebugSessionTemplateSpec{
					Mode: DebugSessionModeKubectlDebug,
					KubectlDebug: &KubectlDebugConfig{
						EphemeralContainers: &tt.config,
					},
				},
			}
			if template.Spec.KubectlDebug.EphemeralContainers.Enabled != tt.config.Enabled {
				t.Error("Enabled mismatch")
			}
		})
	}
}

func TestDebugSessionTemplate_NodeDebugConfig(t *testing.T) {
	config := NodeDebugConfig{
		Enabled:       true,
		AllowedImages: []string{"busybox:*", "alpine:*"},
		HostNamespaces: &HostNamespacesConfig{
			HostNetwork: true,
			HostPID:     true,
			HostIPC:     false,
		},
		NodeSelector: map[string]string{
			"node-role.kubernetes.io/worker": "",
		},
	}

	template := DebugSessionTemplate{
		Spec: DebugSessionTemplateSpec{
			KubectlDebug: &KubectlDebugConfig{
				NodeDebug: &config,
			},
		},
	}

	if !template.Spec.KubectlDebug.NodeDebug.Enabled {
		t.Error("Expected node debug enabled")
	}
	if len(template.Spec.KubectlDebug.NodeDebug.AllowedImages) != 2 {
		t.Error("Expected 2 allowed images")
	}
	if !template.Spec.KubectlDebug.NodeDebug.HostNamespaces.HostNetwork {
		t.Error("Expected host network enabled")
	}
	if template.Spec.KubectlDebug.NodeDebug.HostNamespaces.HostIPC {
		t.Error("Expected host IPC disabled")
	}
}

func TestDebugSessionTemplate_PodCopyConfig(t *testing.T) {
	config := PodCopyConfig{
		Enabled:         true,
		TargetNamespace: "debug-copies",
		Labels: map[string]string{
			"debug": "true",
		},
		TTL: "2h",
	}

	template := DebugSessionTemplate{
		Spec: DebugSessionTemplateSpec{
			KubectlDebug: &KubectlDebugConfig{
				PodCopy: &config,
			},
		},
	}

	if !template.Spec.KubectlDebug.PodCopy.Enabled {
		t.Error("Expected pod copy enabled")
	}
	if template.Spec.KubectlDebug.PodCopy.TargetNamespace != "debug-copies" {
		t.Error("Expected target namespace 'debug-copies'")
	}
	if template.Spec.KubectlDebug.PodCopy.TTL != "2h" {
		t.Error("Expected TTL '2h'")
	}
}

func TestDebugSessionTemplate_Allowed(t *testing.T) {
	tests := []struct {
		name    string
		allowed DebugSessionAllowed
	}{
		{
			name: "groups only",
			allowed: DebugSessionAllowed{
				Groups: []string{"admins", "sre-team"},
			},
		},
		{
			name: "users only",
			allowed: DebugSessionAllowed{
				Users: []string{"alice@example.com", "bob@example.com"},
			},
		},
		{
			name: "clusters only",
			allowed: DebugSessionAllowed{
				Clusters: []string{"production-*", "staging-*"},
			},
		},
		{
			name: "mixed",
			allowed: DebugSessionAllowed{
				Groups:   []string{"sre"},
				Users:    []string{"alice@example.com"},
				Clusters: []string{"*"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := DebugSessionTemplate{
				Spec: DebugSessionTemplateSpec{
					Allowed: &tt.allowed,
				},
			}
			if template.Spec.Allowed == nil {
				t.Fatal("Expected allowed config")
			}
		})
	}
}

func TestDebugSessionTemplate_Approvers(t *testing.T) {
	template := DebugSessionTemplate{
		Spec: DebugSessionTemplateSpec{
			Approvers: &DebugSessionApprovers{
				Groups: []string{"approvers", "team-leads"},
				Users:  []string{"manager@example.com"},
				AutoApproveFor: &AutoApproveConfig{
					Groups:   []string{"senior-sre"},
					Clusters: []string{"dev-*", "staging-*"},
				},
			},
		},
	}

	if template.Spec.Approvers == nil {
		t.Fatal("Expected approvers config")
	}
	if len(template.Spec.Approvers.Groups) != 2 {
		t.Error("Expected 2 approver groups")
	}
	if template.Spec.Approvers.AutoApproveFor == nil {
		t.Fatal("Expected auto-approve config")
	}
	if len(template.Spec.Approvers.AutoApproveFor.Groups) != 1 {
		t.Error("Expected 1 auto-approve group")
	}
}

func TestDebugSessionTemplate_Constraints(t *testing.T) {
	tests := []struct {
		name        string
		constraints DebugSessionConstraints
	}{
		{
			name: "default constraints",
			constraints: DebugSessionConstraints{
				MaxDuration:           "4h",
				DefaultDuration:       "1h",
				AllowRenewal:          ptr(true),
				MaxRenewals:           ptr(int32(3)),
				MaxConcurrentSessions: 2,
			},
		},
		{
			name: "strict constraints",
			constraints: DebugSessionConstraints{
				MaxDuration:           "30m",
				DefaultDuration:       "15m",
				AllowRenewal:          ptr(false),
				MaxConcurrentSessions: 1,
			},
		},
		{
			name: "relaxed constraints",
			constraints: DebugSessionConstraints{
				MaxDuration:           "24h",
				DefaultDuration:       "8h",
				AllowRenewal:          ptr(true),
				MaxRenewals:           ptr(int32(10)),
				MaxConcurrentSessions: 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := DebugSessionTemplate{
				Spec: DebugSessionTemplateSpec{
					Constraints: &tt.constraints,
				},
			}
			if template.Spec.Constraints == nil {
				t.Fatal("Expected constraints")
			}
			if template.Spec.Constraints.MaxDuration != tt.constraints.MaxDuration {
				t.Error("MaxDuration mismatch")
			}
			if !ptrEqual(template.Spec.Constraints.AllowRenewal, tt.constraints.AllowRenewal) {
				t.Error("AllowRenewal mismatch")
			}
		})
	}
}

func TestDebugSessionTemplate_TerminalSharing(t *testing.T) {
	tests := []struct {
		name            string
		terminalSharing TerminalSharingConfig
	}{
		{
			name: "tmux provider",
			terminalSharing: TerminalSharingConfig{
				Enabled:         true,
				Provider:        "tmux",
				MaxParticipants: 5,
			},
		},
		{
			name: "screen provider",
			terminalSharing: TerminalSharingConfig{
				Enabled:         true,
				Provider:        "screen",
				MaxParticipants: 3,
			},
		},
		{
			name: "disabled",
			terminalSharing: TerminalSharingConfig{
				Enabled: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := DebugSessionTemplate{
				Spec: DebugSessionTemplateSpec{
					TerminalSharing: &tt.terminalSharing,
				},
			}
			if template.Spec.TerminalSharing.Enabled != tt.terminalSharing.Enabled {
				t.Error("Enabled mismatch")
			}
		})
	}
}

func TestDebugSessionTemplate_PodOverrides(t *testing.T) {
	hostNetwork := true
	hostPID := true

	template := DebugSessionTemplate{
		Spec: DebugSessionTemplateSpec{
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-debug",
			},
			PodOverrides: &DebugPodOverrides{
				Spec: &DebugPodSpecOverrides{
					HostNetwork: &hostNetwork,
					HostPID:     &hostPID,
					Containers: []DebugContainerOverride{
						{
							Name: "debug",
							SecurityContext: &corev1.SecurityContext{
								Privileged: &hostNetwork,
							},
							Resources: &corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("1"),
									corev1.ResourceMemory: resource.MustParse("1Gi"),
								},
							},
							Env: []corev1.EnvVar{
								{Name: "DEBUG", Value: "true"},
							},
						},
					},
				},
			},
		},
	}

	if template.Spec.PodOverrides == nil {
		t.Fatal("Expected pod overrides")
	}
	if template.Spec.PodOverrides.Spec == nil {
		t.Fatal("Expected spec overrides")
	}
	if !*template.Spec.PodOverrides.Spec.HostNetwork {
		t.Error("Expected host network override to be true")
	}
	if len(template.Spec.PodOverrides.Spec.Containers) != 1 {
		t.Error("Expected 1 container override")
	}
}

func TestDebugSessionTemplate_AffinityOverrides(t *testing.T) {
	template := DebugSessionTemplate{
		Spec: DebugSessionTemplateSpec{
			AffinityOverrides: &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "node-role.kubernetes.io/worker",
										Operator: corev1.NodeSelectorOpExists,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if template.Spec.AffinityOverrides == nil {
		t.Fatal("Expected affinity overrides")
	}
	if template.Spec.AffinityOverrides.NodeAffinity == nil {
		t.Fatal("Expected node affinity")
	}
}

func TestDebugSessionTemplate_AdditionalTolerations(t *testing.T) {
	template := DebugSessionTemplate{
		Spec: DebugSessionTemplateSpec{
			AdditionalTolerations: []corev1.Toleration{
				{
					Key:      "node.kubernetes.io/not-ready",
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoExecute,
				},
				{
					Key:      "node.kubernetes.io/unreachable",
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoExecute,
				},
			},
		},
	}

	if len(template.Spec.AdditionalTolerations) != 2 {
		t.Errorf("Expected 2 additional tolerations, got %d", len(template.Spec.AdditionalTolerations))
	}
}

func TestDebugSessionTemplate_FailMode(t *testing.T) {
	tests := []struct {
		name     string
		failMode string
	}{
		{"closed mode", "closed"},
		{"open mode", "open"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := DebugSessionTemplate{
				Spec: DebugSessionTemplateSpec{
					FailMode: tt.failMode,
				},
			}
			if template.Spec.FailMode != tt.failMode {
				t.Errorf("Expected fail mode %s, got %s", tt.failMode, template.Spec.FailMode)
			}
		})
	}
}

func TestDebugSessionTemplate_DeepCopy(t *testing.T) {
	replicas := int32(1)
	original := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "original-template",
		},
		Spec: DebugSessionTemplateSpec{
			DisplayName: "Original",
			Mode:        DebugSessionModeWorkload,
			Replicas:    &replicas,
			Constraints: &DebugSessionConstraints{
				MaxDuration: "4h",
			},
		},
	}

	copied := original.DeepCopy()

	// Verify deep copy
	if copied.Name != original.Name {
		t.Error("Name mismatch")
	}
	if copied.Spec.Mode != original.Spec.Mode {
		t.Error("Mode mismatch")
	}

	// Modify copy and verify original unchanged
	*copied.Spec.Replicas = 5
	if *original.Spec.Replicas == 5 {
		t.Error("DeepCopy modified original replicas")
	}

	copied.Spec.Constraints.MaxDuration = "8h"
	if original.Spec.Constraints.MaxDuration == "8h" {
		t.Error("DeepCopy modified original constraints")
	}
}

func TestDebugSessionTemplateList(t *testing.T) {
	list := &DebugSessionTemplateList{
		Items: []DebugSessionTemplate{
			{ObjectMeta: metav1.ObjectMeta{Name: "template1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "template2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "template3"}},
		},
	}

	if len(list.Items) != 3 {
		t.Errorf("Expected 3 items, got %d", len(list.Items))
	}
}

func TestDebugSessionTemplate_CompleteProductionConfig(t *testing.T) {
	replicas := int32(1)
	template := DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "production-debug",
			Labels: map[string]string{
				"environment": "production",
			},
		},
		Spec: DebugSessionTemplateSpec{
			DisplayName: "Production Debug Session",
			Description: "Secure debug session for production clusters with full approval workflow",
			Mode:        DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "secure-debug",
			},
			WorkloadType:    DebugWorkloadDaemonSet,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			FailMode:        "closed",
			Allowed: &DebugSessionAllowed{
				Groups:   []string{"sre-team", "platform-team"},
				Clusters: []string{"production-*"},
			},
			Approvers: &DebugSessionApprovers{
				Groups: []string{"security-team", "team-leads"},
				AutoApproveFor: &AutoApproveConfig{
					Groups: []string{"senior-sre"},
				},
			},
			Constraints: &DebugSessionConstraints{
				MaxDuration:           "2h",
				DefaultDuration:       "30m",
				AllowRenewal:          ptr(true),
				MaxRenewals:           ptr(int32(2)),
				MaxConcurrentSessions: 1,
			},
			TerminalSharing: &TerminalSharingConfig{
				Enabled:         true,
				Provider:        "tmux",
				MaxParticipants: 3,
			},
		},
	}

	// Validate complete structure
	if template.Spec.Mode != DebugSessionModeWorkload {
		t.Error("Expected workload mode")
	}
	if template.Spec.PodTemplateRef == nil {
		t.Fatal("Expected pod template ref")
	}
	if template.Spec.Allowed == nil || len(template.Spec.Allowed.Groups) != 2 {
		t.Error("Expected 2 allowed groups")
	}
	if template.Spec.Approvers == nil || template.Spec.Approvers.AutoApproveFor == nil {
		t.Fatal("Expected approvers with auto-approve config")
	}
	if template.Spec.Constraints == nil {
		t.Fatal("Expected constraints")
	}
	if template.Spec.TerminalSharing == nil || !template.Spec.TerminalSharing.Enabled {
		t.Error("Expected terminal sharing enabled")
	}
}

func TestHostNamespacesConfig(t *testing.T) {
	tests := []struct {
		name   string
		config HostNamespacesConfig
	}{
		{
			name: "all enabled",
			config: HostNamespacesConfig{
				HostNetwork: true,
				HostPID:     true,
				HostIPC:     true,
			},
		},
		{
			name: "network only",
			config: HostNamespacesConfig{
				HostNetwork: true,
				HostPID:     false,
				HostIPC:     false,
			},
		},
		{
			name: "all disabled",
			config: HostNamespacesConfig{
				HostNetwork: false,
				HostPID:     false,
				HostIPC:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := DebugSessionTemplate{
				Spec: DebugSessionTemplateSpec{
					KubectlDebug: &KubectlDebugConfig{
						NodeDebug: &NodeDebugConfig{
							HostNamespaces: &tt.config,
						},
					},
				},
			}
			ns := template.Spec.KubectlDebug.NodeDebug.HostNamespaces
			if ns.HostNetwork != tt.config.HostNetwork {
				t.Error("HostNetwork mismatch")
			}
			if ns.HostPID != tt.config.HostPID {
				t.Error("HostPID mismatch")
			}
			if ns.HostIPC != tt.config.HostIPC {
				t.Error("HostIPC mismatch")
			}
		})
	}
}

func TestAutoApproveConfig(t *testing.T) {
	tests := []struct {
		name   string
		config AutoApproveConfig
	}{
		{
			name: "groups auto-approve",
			config: AutoApproveConfig{
				Groups: []string{"senior-engineers", "platform-leads"},
			},
		},
		{
			name: "clusters auto-approve",
			config: AutoApproveConfig{
				Clusters: []string{"dev-*", "test-*"},
			},
		},
		{
			name: "combined auto-approve",
			config: AutoApproveConfig{
				Groups:   []string{"sre"},
				Clusters: []string{"staging-*"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := DebugSessionTemplate{
				Spec: DebugSessionTemplateSpec{
					Approvers: &DebugSessionApprovers{
						AutoApproveFor: &tt.config,
					},
				},
			}
			if template.Spec.Approvers.AutoApproveFor == nil {
				t.Fatal("Expected auto-approve config")
			}
		})
	}
}

// Webhook validation tests

func TestDebugSessionTemplate_ValidateCreate_WorkloadMode(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "workload-template",
		},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
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

func TestDebugSessionTemplate_ValidateCreate_WorkloadMode_MissingPodTemplate(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-workload",
		},
		Spec: DebugSessionTemplateSpec{
			Mode:           DebugSessionModeWorkload,
			PodTemplateRef: nil, // missing for workload mode
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing podTemplateRef in workload mode")
	}
}

func TestDebugSessionTemplate_ValidateCreate_KubectlDebugMode(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kubectl-debug-template",
		},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeKubectlDebug,
			KubectlDebug: &KubectlDebugConfig{
				EphemeralContainers: &EphemeralContainersConfig{
					Enabled: true,
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

func TestDebugSessionTemplate_ValidateCreate_KubectlDebugMode_MissingConfig(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-kubectl-debug",
		},
		Spec: DebugSessionTemplateSpec{
			Mode:         DebugSessionModeKubectlDebug,
			KubectlDebug: nil, // missing for kubectl-debug mode
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing kubectlDebug config")
	}
}

func TestDebugSessionTemplate_ValidateCreate_HybridMode(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "hybrid-template",
		},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeHybrid,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			KubectlDebug: &KubectlDebugConfig{
				EphemeralContainers: &EphemeralContainersConfig{
					Enabled: true,
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

func TestDebugSessionTemplate_ValidateCreate_HybridMode_MissingPodTemplate(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-hybrid",
		},
		Spec: DebugSessionTemplateSpec{
			Mode:           DebugSessionModeHybrid,
			PodTemplateRef: nil, // missing for hybrid mode
			KubectlDebug: &KubectlDebugConfig{
				EphemeralContainers: &EphemeralContainersConfig{Enabled: true},
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing podTemplateRef in hybrid mode")
	}
}

func TestDebugSessionTemplate_ValidateCreate_HybridMode_MissingKubectlDebug(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-hybrid",
		},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeHybrid,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			KubectlDebug: nil, // missing for hybrid mode
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing kubectlDebug in hybrid mode")
	}
}

func TestDebugSessionTemplate_ValidateCreate_InvalidConstraintsDuration(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-constraints",
		},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			Constraints: &DebugSessionConstraints{
				MaxDuration: "invalid", // invalid duration
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("ValidateCreate() expected error for invalid maxDuration")
	}
}

func TestDebugSessionTemplate_ValidateCreate_InvalidDefaultDuration(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-default",
		},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			Constraints: &DebugSessionConstraints{
				DefaultDuration: "not-a-duration",
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("ValidateCreate() expected error for invalid defaultDuration")
	}
}

func TestDebugSessionTemplate_ValidateUpdate(t *testing.T) {
	ctx := context.Background()
	oldTemplate := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "template",
		},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "old-pod",
			},
		},
	}
	newTemplate := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "template",
		},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "new-pod",
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

func TestDebugSessionTemplate_ValidateDelete(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
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

func TestDebugSessionTemplate_ValidateCreate_InvalidSpec(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "template"},
		Spec:       DebugSessionTemplateSpec{},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing required fields")
	}
}

// SetCondition and GetCondition tests

func TestDebugSessionTemplate_SetCondition(t *testing.T) {
	template := &DebugSessionTemplate{}
	condition := metav1.Condition{
		Type:               string(DebugSessionTemplateConditionReady),
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		Message:            "Template is ready",
		LastTransitionTime: metav1.Now(),
	}

	template.SetCondition(condition)

	if len(template.Status.Conditions) != 1 {
		t.Errorf("Expected 1 condition, got %d", len(template.Status.Conditions))
	}
	if template.Status.Conditions[0].Type != string(DebugSessionTemplateConditionReady) {
		t.Errorf("Expected condition type %s", DebugSessionTemplateConditionReady)
	}
}

func TestDebugSessionTemplate_SetCondition_Update(t *testing.T) {
	template := &DebugSessionTemplate{}
	condition1 := metav1.Condition{
		Type:               string(DebugSessionTemplateConditionReady),
		Status:             metav1.ConditionFalse,
		Reason:             "Pending",
		LastTransitionTime: metav1.Now(),
	}
	template.SetCondition(condition1)

	condition2 := metav1.Condition{
		Type:               string(DebugSessionTemplateConditionReady),
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

func TestDebugSessionTemplate_GetCondition(t *testing.T) {
	template := &DebugSessionTemplate{
		Status: DebugSessionTemplateStatus{
			Conditions: []metav1.Condition{
				{
					Type:   string(DebugSessionTemplateConditionReady),
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	condition := template.GetCondition(string(DebugSessionTemplateConditionReady))
	if condition == nil {
		t.Fatal("Expected to find condition")
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("Expected status True, got %v", condition.Status)
	}
}

func TestDebugSessionTemplate_GetCondition_NotFound(t *testing.T) {
	template := &DebugSessionTemplate{}
	condition := template.GetCondition("non-existent")
	if condition != nil {
		t.Error("Expected nil for non-existent condition")
	}
}

func TestDebugSessionTemplate_ValidateUpdate_InvalidSpec(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{}

	oldTemplate := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "test-pod",
			},
		},
	}

	newTemplate := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       DebugSessionTemplateSpec{},
	}

	_, err := template.ValidateUpdate(ctx, oldTemplate, newTemplate)
	if err == nil {
		t.Error("ValidateUpdate() expected error for invalid new spec")
	}
}

func TestDebugSessionTemplate_ValidateUpdate_Invalid(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{}

	oldTemplate := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "test-pod",
			},
		},
	}

	newTemplate := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: DebugSessionTemplateSpec{
			Mode:           DebugSessionModeWorkload,
			PodTemplateRef: nil, // missing - invalid for workload mode
		},
	}

	_, err := template.ValidateUpdate(ctx, oldTemplate, newTemplate)
	if err == nil {
		t.Error("ValidateUpdate() expected error for invalid spec")
	}
}

func TestDebugSessionTemplate_ValidateCreate_DefaultMode(t *testing.T) {
	ctx := context.Background()
	// Test with empty mode (defaults to workload)
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-mode-template",
		},
		Spec: DebugSessionTemplateSpec{
			Mode: "", // empty defaults to workload
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
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

func TestValidateDebugSessionTemplateSpec_NilSpec(t *testing.T) {
	errs := validateDebugSessionTemplateSpec(nil)
	if errs != nil {
		t.Errorf("validateDebugSessionTemplateSpec(nil) expected nil errors, got %v", errs)
	}
}

func TestDebugSessionTemplate_ValidateCreate_HybridModeWithBothConfigs(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "hybrid-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeHybrid,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			KubectlDebug: &KubectlDebugConfig{
				EphemeralContainers: &EphemeralContainersConfig{
					Enabled: true,
				},
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err != nil {
		t.Errorf("expected success for complete hybrid mode, got %v", err)
	}
}

func TestDebugSessionTemplate_ValidateCreate_HybridModeNoPodTemplateRef(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "hybrid-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeHybrid,
			// PodTemplateRef is missing
			KubectlDebug: &KubectlDebugConfig{
				EphemeralContainers: &EphemeralContainersConfig{
					Enabled: true,
				},
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("expected error when hybrid mode is missing podTemplateRef")
	}
}

func TestDebugSessionTemplate_ValidateCreate_HybridModeNoKubectlDebug(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "hybrid-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeHybrid,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			// KubectlDebug is missing
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("expected error when hybrid mode is missing kubectlDebug")
	}
}

func TestDebugSessionTemplate_ValidateCreate_KubectlDebugModeNoConfig(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "kubectl-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeKubectlDebug,
			// KubectlDebug is missing
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("expected error when kubectl-debug mode is missing kubectlDebug")
	}
}

func TestDebugSessionTemplate_ValidateCreate_ConstraintsValid(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "constrained-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			Constraints: &DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err != nil {
		t.Errorf("expected success with valid constraints, got %v", err)
	}
}

func TestDebugSessionTemplate_ValidateCreate_MaxDurationInvalid(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "constrained-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			Constraints: &DebugSessionConstraints{
				MaxDuration: "invalid-duration",
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("expected error for invalid maxDuration")
	}
}

func TestDebugSessionTemplate_ValidateCreate_DefaultDurationInvalid(t *testing.T) {
	ctx := context.Background()
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "constrained-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			Constraints: &DebugSessionConstraints{
				DefaultDuration: "not-a-duration",
			},
		},
	}

	_, err := template.ValidateCreate(ctx, template)
	if err == nil {
		t.Error("expected error for invalid defaultDuration")
	}
}

// ptr is a generic helper to create a pointer to a value
func ptr[T any](v T) *T {
	return &v
}

// ptrEqual compares two pointers for equality
func ptrEqual[T comparable](a, b *T) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// TestValidateDebugSessionTemplateSpec_WorkloadModeValid verifies valid workload mode config
func TestValidateDebugSessionTemplateSpec_WorkloadModeValid(t *testing.T) {
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
		},
	}

	errs := validateDebugSessionTemplateSpec(template)
	if len(errs) > 0 {
		t.Errorf("expected no errors for valid workload mode, got %v", errs)
	}
}

// TestValidateDebugSessionTemplateSpec_KubectlDebugModeValid verifies valid kubectl-debug mode config
func TestValidateDebugSessionTemplateSpec_KubectlDebugModeValid(t *testing.T) {
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeKubectlDebug,
			KubectlDebug: &KubectlDebugConfig{
				EphemeralContainers: &EphemeralContainersConfig{
					Enabled: true,
				},
			},
		},
	}

	errs := validateDebugSessionTemplateSpec(template)
	if len(errs) > 0 {
		t.Errorf("expected no errors for valid kubectl-debug mode, got %v", errs)
	}
}

// TestValidateDebugSessionTemplateSpec_KubectlDebugModeMissingConfig
func TestValidateDebugSessionTemplateSpec_KubectlDebugModeMissingConfig(t *testing.T) {
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: DebugSessionTemplateSpec{
			Mode:         DebugSessionModeKubectlDebug,
			KubectlDebug: nil, // Missing required config
		},
	}

	errs := validateDebugSessionTemplateSpec(template)
	if len(errs) == 0 {
		t.Error("expected error for kubectl-debug mode without kubectlDebug config")
	}
}

// TestValidateDebugSessionTemplateSpec_DefaultMode tests default mode (workload)
func TestValidateDebugSessionTemplateSpec_DefaultMode(t *testing.T) {
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: "", // Default should be workload
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
		},
	}

	errs := validateDebugSessionTemplateSpec(template)
	if len(errs) > 0 {
		t.Errorf("expected no errors for default mode with podTemplateRef, got %v", errs)
	}
}

// TestValidateDebugSessionTemplateSpec_SchedulingOptions tests scheduling options validation
func TestValidateDebugSessionTemplateSpec_SchedulingOptions(t *testing.T) {
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			SchedulingOptions: &SchedulingOptions{
				Required: false,
				Options: []SchedulingOption{
					{
						Name:        "default-option",
						DisplayName: "Default Option",
						Default:     true,
					},
				},
			},
		},
	}

	errs := validateDebugSessionTemplateSpec(template)
	if len(errs) > 0 {
		t.Errorf("expected no errors for valid scheduling options, got %v", errs)
	}
}

// TestValidateDebugSessionTemplateSpec_Impersonation tests impersonation config validation
func TestValidateDebugSessionTemplateSpec_Impersonation(t *testing.T) {
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			Impersonation: &ImpersonationConfig{
				ServiceAccountRef: &ServiceAccountReference{
					Name:      "debug-sa",
					Namespace: "debug-system",
				},
			},
		},
	}

	errs := validateDebugSessionTemplateSpec(template)
	if len(errs) > 0 {
		t.Errorf("expected no errors for valid impersonation config, got %v", errs)
	}
}

// TestValidateDebugSessionTemplateSpec_NamespaceConstraints tests namespace constraints validation
func TestValidateDebugSessionTemplateSpec_NamespaceConstraints(t *testing.T) {
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			NamespaceConstraints: &NamespaceConstraints{
				DefaultNamespace:   "debug-ns",
				AllowUserNamespace: true,
				AllowedNamespaces: &NamespaceFilter{
					Patterns: []string{"dev-*", "test-*"},
				},
				DeniedNamespaces: &NamespaceFilter{
					Patterns: []string{"kube-system", "kube-public"},
				},
			},
		},
	}

	errs := validateDebugSessionTemplateSpec(template)
	if len(errs) > 0 {
		t.Errorf("expected no errors for valid namespace constraints, got %v", errs)
	}
}

// TestValidateDebugSessionTemplateSpec_AuxiliaryResources tests auxiliary resources validation
func TestValidateDebugSessionTemplateSpec_AuxiliaryResources(t *testing.T) {
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			AuxiliaryResources: []AuxiliaryResource{
				{
					Name:         "config-map",
					Description:  "Test config map",
					CreateBefore: true,
					DeleteAfter:  true,
					Template:     runtime.RawExtension{Raw: []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"test"}}`)},
				},
			},
		},
	}

	errs := validateDebugSessionTemplateSpec(template)
	if len(errs) > 0 {
		t.Errorf("expected no errors for valid auxiliary resources, got %v", errs)
	}
}

// TestValidateDebugSessionTemplateSpec_ConstraintsValidDurations tests valid constraint durations
func TestValidateDebugSessionTemplateSpec_ConstraintsValidDurations(t *testing.T) {
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			Constraints: &DebugSessionConstraints{
				MaxDuration:     "8h",
				DefaultDuration: "2h",
			},
		},
	}

	errs := validateDebugSessionTemplateSpec(template)
	if len(errs) > 0 {
		t.Errorf("expected no errors for valid constraint durations, got %v", errs)
	}
}

// TestValidateDebugSessionTemplateSpec_HybridModeBothMissing tests hybrid mode with both configs missing
func TestValidateDebugSessionTemplateSpec_HybridModeBothMissing(t *testing.T) {
	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: DebugSessionTemplateSpec{
			Mode:           DebugSessionModeHybrid,
			PodTemplateRef: nil,
			KubectlDebug:   nil,
		},
	}

	errs := validateDebugSessionTemplateSpec(template)
	if len(errs) != 2 {
		t.Errorf("expected 2 errors for hybrid mode with both configs missing, got %d: %v", len(errs), errs)
	}
}

// =============================================================================
// AllowedPodOperations Tests
// =============================================================================

func TestAllowedPodOperations_IsOperationAllowed_NilStruct(t *testing.T) {
	var ops *AllowedPodOperations

	// Nil struct should return backward-compatible defaults
	tests := []struct {
		operation string
		expected  bool
	}{
		{"exec", true},
		{"attach", true},
		{"portforward", true},
		{"log", false},
		{"logs", false},
		{"cp", false},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			result := ops.IsOperationAllowed(tt.operation)
			if result != tt.expected {
				t.Errorf("IsOperationAllowed(%q) on nil struct = %v, want %v", tt.operation, result, tt.expected)
			}
		})
	}
}

func TestAllowedPodOperations_IsOperationAllowed_EmptyStruct(t *testing.T) {
	ops := &AllowedPodOperations{}

	// Empty struct with nil fields should use defaults (exec, attach, portforward enabled)
	tests := []struct {
		operation string
		expected  bool
	}{
		{"exec", true},        // nil defaults to true
		{"attach", true},      // nil defaults to true
		{"portforward", true}, // nil defaults to true
		{"log", false},        // nil defaults to false
		{"logs", false},       // nil defaults to false
		{"cp", false},         // nil defaults to false
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			result := ops.IsOperationAllowed(tt.operation)
			if result != tt.expected {
				t.Errorf("IsOperationAllowed(%q) on empty struct = %v, want %v", tt.operation, result, tt.expected)
			}
		})
	}
}

func TestAllowedPodOperations_IsOperationAllowed_AllEnabled(t *testing.T) {
	boolTrue := true
	ops := &AllowedPodOperations{
		Exec:        &boolTrue,
		Attach:      &boolTrue,
		Logs:        &boolTrue,
		PortForward: &boolTrue,
		Cp:          &boolTrue,
	}

	tests := []struct {
		operation string
		expected  bool
	}{
		{"exec", true},
		{"attach", true},
		{"portforward", true},
		{"log", true},
		{"logs", true},
		{"cp", true},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			result := ops.IsOperationAllowed(tt.operation)
			if result != tt.expected {
				t.Errorf("IsOperationAllowed(%q) with all enabled = %v, want %v", tt.operation, result, tt.expected)
			}
		})
	}
}

func TestAllowedPodOperations_IsOperationAllowed_AllDisabled(t *testing.T) {
	boolFalse := false
	ops := &AllowedPodOperations{
		Exec:        &boolFalse,
		Attach:      &boolFalse,
		Logs:        &boolFalse,
		PortForward: &boolFalse,
		Cp:          &boolFalse,
	}

	tests := []struct {
		operation string
		expected  bool
	}{
		{"exec", false},
		{"attach", false},
		{"portforward", false},
		{"log", false},
		{"logs", false},
		{"cp", false},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			result := ops.IsOperationAllowed(tt.operation)
			if result != tt.expected {
				t.Errorf("IsOperationAllowed(%q) with all disabled = %v, want %v", tt.operation, result, tt.expected)
			}
		})
	}
}

func TestAllowedPodOperations_IsOperationAllowed_LogsOnlyProfile(t *testing.T) {
	// Use case: Read-only debugging - only logs allowed
	boolTrue := true
	boolFalse := false
	ops := &AllowedPodOperations{
		Exec:        &boolFalse,
		Attach:      &boolFalse,
		Logs:        &boolTrue,
		PortForward: &boolFalse,
		Cp:          &boolFalse,
	}

	tests := []struct {
		operation string
		expected  bool
	}{
		{"exec", false},
		{"attach", false},
		{"portforward", false},
		{"log", true},
		{"logs", true},
		{"cp", false},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			result := ops.IsOperationAllowed(tt.operation)
			if result != tt.expected {
				t.Errorf("IsOperationAllowed(%q) logs-only profile = %v, want %v", tt.operation, result, tt.expected)
			}
		})
	}
}

func TestAllowedPodOperations_IsOperationAllowed_CoredumpProfile(t *testing.T) {
	// Use case: Coredump extraction - cp and logs only, no exec
	boolTrue := true
	boolFalse := false
	ops := &AllowedPodOperations{
		Exec:        &boolFalse,
		Attach:      &boolFalse,
		Logs:        &boolTrue,
		PortForward: &boolFalse,
		Cp:          &boolTrue,
	}

	tests := []struct {
		operation string
		expected  bool
	}{
		{"exec", false},
		{"attach", false},
		{"portforward", false},
		{"log", true},
		{"logs", true},
		{"cp", true},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			result := ops.IsOperationAllowed(tt.operation)
			if result != tt.expected {
				t.Errorf("IsOperationAllowed(%q) coredump profile = %v, want %v", tt.operation, result, tt.expected)
			}
		})
	}
}

func TestAllowedPodOperations_IsOperationAllowed_FullDebugProfile(t *testing.T) {
	// Use case: Full debug access
	boolTrue := true
	ops := &AllowedPodOperations{
		Exec:        &boolTrue,
		Attach:      &boolTrue,
		Logs:        &boolTrue,
		PortForward: &boolTrue,
		Cp:          &boolTrue,
	}

	tests := []struct {
		operation string
		expected  bool
	}{
		{"exec", true},
		{"attach", true},
		{"portforward", true},
		{"log", true},
		{"logs", true},
		{"cp", true},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			result := ops.IsOperationAllowed(tt.operation)
			if result != tt.expected {
				t.Errorf("IsOperationAllowed(%q) full debug profile = %v, want %v", tt.operation, result, tt.expected)
			}
		})
	}
}

func TestAllowedPodOperations_InDebugSessionTemplateSpec(t *testing.T) {
	boolTrue := true
	boolFalse := false

	template := &DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: DebugSessionTemplateSpec{
			Mode: DebugSessionModeWorkload,
			PodTemplateRef: &DebugPodTemplateReference{
				Name: "basic-pod",
			},
			AllowedPodOperations: &AllowedPodOperations{
				Exec:        &boolFalse,
				Attach:      &boolFalse,
				Logs:        &boolTrue,
				PortForward: &boolFalse,
				Cp:          &boolTrue,
			},
		},
	}

	if template.Spec.AllowedPodOperations == nil {
		t.Fatal("AllowedPodOperations should be set")
	}

	if template.Spec.AllowedPodOperations.IsOperationAllowed("exec") {
		t.Error("exec should be disabled")
	}
	if !template.Spec.AllowedPodOperations.IsOperationAllowed("logs") {
		t.Error("logs should be enabled")
	}
	if !template.Spec.AllowedPodOperations.IsOperationAllowed("cp") {
		t.Error("cp should be enabled")
	}
}
