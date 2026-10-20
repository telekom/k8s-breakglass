// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestCRDSchema_EphemeralContainersSecurityContext checks that a template
// securityContext cannot contradict its own ephemeral-container policy.
func TestCRDSchema_EphemeralContainersSecurityContext(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()
	yes, no := true, false
	root := int64(0)

	tests := []struct {
		name    string
		config  EphemeralContainersConfig
		message string
	}{
		{name: "read-only rootfs", config: EphemeralContainersConfig{
			Enabled: true, SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &yes, RunAsNonRoot: &yes}}},
		{name: "privileged with allowPrivileged", config: EphemeralContainersConfig{
			Enabled: true, AllowPrivileged: true, SecurityContext: &corev1.SecurityContext{Privileged: &yes, AllowPrivilegeEscalation: &yes}}},
		{name: "privileged without allowPrivileged", config: EphemeralContainersConfig{
			Enabled: true, SecurityContext: &corev1.SecurityContext{Privileged: &yes}},
			message: "require allowPrivileged"},
		{name: "privilege escalation without allowPrivileged", config: EphemeralContainersConfig{
			Enabled: true, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &yes}},
			message: "require allowPrivileged"},
		{name: "root user under requireNonRoot", config: EphemeralContainersConfig{
			Enabled: true, SecurityContext: &corev1.SecurityContext{RunAsUser: &root}},
			message: "require requireNonRoot false"},
		{name: "runAsNonRoot false under requireNonRoot", config: EphemeralContainersConfig{
			Enabled: true, SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &no}},
			message: "require requireNonRoot false"},
		{name: "omitted requireNonRoot defaults to true", config: EphemeralContainersConfig{
			Enabled: true, RequireNonRoot: false, SecurityContext: &corev1.SecurityContext{RunAsUser: &root}}, message: "require requireNonRoot false"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := tc.config
			tmpl := &DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "ephemeral-sc-" + sanitizeName(tc.name), Namespace: "default"},
				Spec: DebugSessionTemplateSpec{
					DisplayName:  tc.name,
					Mode:         DebugSessionModeKubectlDebug,
					KubectlDebug: &KubectlDebugConfig{EphemeralContainers: &config},
				},
			}
			err := c.Create(ctx, tmpl)
			if tc.message == "" {
				if err != nil {
					t.Fatalf("valid template rejected: %v", err)
				}
				return
			}
			if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("expected Invalid containing %q, got %v", tc.message, err)
			}
		})
	}
}

func TestCRDSchema_PodCopySecurityContext(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()
	yes := true
	tests := []struct {
		name    string
		sc      *corev1.SecurityContext
		message string
	}{
		{name: "read-only rootfs", sc: &corev1.SecurityContext{ReadOnlyRootFilesystem: &yes}},
		{name: "privileged", sc: &corev1.SecurityContext{Privileged: &yes}, message: "must not be privileged"},
		{name: "windows host process", sc: &corev1.SecurityContext{WindowsOptions: &corev1.WindowsSecurityContextOptions{HostProcess: &yes}}, message: "must not be privileged"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := &DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "podcopy-sc-" + sanitizeName(tc.name), Namespace: "default"},
				Spec: DebugSessionTemplateSpec{
					DisplayName:  tc.name,
					Mode:         DebugSessionModeKubectlDebug,
					KubectlDebug: &KubectlDebugConfig{PodCopy: &PodCopyConfig{Enabled: true, SecurityContext: tc.sc}},
				},
			}
			err := c.Create(ctx, tmpl)
			if tc.message == "" {
				if err != nil {
					t.Fatalf("valid template rejected: %v", err)
				}
				return
			}
			if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("expected Invalid containing %q, got %v", tc.message, err)
			}
		})
	}
}
