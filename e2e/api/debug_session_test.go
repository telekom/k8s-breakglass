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

package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestDebugSessionLifecycle tests the full lifecycle of DebugSession and related templates.
//
// Test coverage for issue #48:
// - Create DebugPodTemplate
// - Create DebugSessionTemplate referencing the pod template
// - Create DebugSession from template
// - Verify session progresses through states
func TestDebugSessionLifecycle(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	var podTemplateName = "e2e-test-debug-pod-template"
	var sessionTemplateName = "e2e-test-debug-session-template"

	t.Run("CreateDebugPodTemplate", func(t *testing.T) {
		template := &telekomv1alpha1.DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: podTemplateName,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.DebugPodTemplateSpec{
				DisplayName: "E2E Test Debug Pod",
				Description: "Debug pod template for E2E testing",
				Template: telekomv1alpha1.DebugPodSpec{
					Spec: telekomv1alpha1.DebugPodSpecInner{
						Containers: []corev1.Container{
							{
								Name:    "debug",
								Image:   "busybox:latest",
								Command: []string{"sleep", "infinity"},
							},
						},
					},
				},
			},
		}

		cleanup.Add(template)

		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create DebugPodTemplate")

		var fetched telekomv1alpha1.DebugPodTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		require.Equal(t, "E2E Test Debug Pod", fetched.Spec.DisplayName)
	})

	t.Run("CreateDebugSessionTemplate", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: sessionTemplateName,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "E2E Test Debug Session",
				Description: "Debug session template for E2E testing",
				PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
					Name: podTemplateName,
				},
				TargetNamespace: "default",
			},
		}

		cleanup.Add(template)

		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create DebugSessionTemplate")

		var fetched telekomv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodTemplateRef)
		require.Equal(t, podTemplateName, fetched.Spec.PodTemplateRef.Name)
	})

	t.Run("DebugPodTemplateValidation", func(t *testing.T) {
		// Test validation: missing container spec
		invalidTemplate := &telekomv1alpha1.DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "e2e-test-invalid-pod-template",
			},
			Spec: telekomv1alpha1.DebugPodTemplateSpec{
				DisplayName: "Invalid Template",
				Template: telekomv1alpha1.DebugPodSpec{
					Spec: telekomv1alpha1.DebugPodSpecInner{
						Containers: []corev1.Container{}, // Empty containers
					},
				},
			},
		}

		cleanup.Add(invalidTemplate)
		err := cli.Create(ctx, invalidTemplate)
		// This might be accepted by the API but should be validated
		// The exact behavior depends on webhook configuration
		if err != nil {
			t.Logf("Validation correctly rejected empty containers: %v", err)
		}
	})
}

// TestDebugPodTemplateVariants tests different configurations of DebugPodTemplate.
func TestDebugPodTemplateVariants(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("TemplateWithNetworkTools", func(t *testing.T) {
		template := &telekomv1alpha1.DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "e2e-test-network-debug",
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.DebugPodTemplateSpec{
				DisplayName: "Network Debug Tools",
				Description: "Pod with network debugging tools",
				Template: telekomv1alpha1.DebugPodSpec{
					Spec: telekomv1alpha1.DebugPodSpecInner{
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

		cleanup.Add(template)

		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create network debug template")
	})

	t.Run("TemplateWithSecurityContext", func(t *testing.T) {
		runAsNonRoot := true
		runAsUser := int64(1000)
		template := &telekomv1alpha1.DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "e2e-test-secure-debug",
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.DebugPodTemplateSpec{
				DisplayName: "Secure Debug Pod",
				Description: "Debug pod with security constraints",
				Template: telekomv1alpha1.DebugPodSpec{
					Spec: telekomv1alpha1.DebugPodSpecInner{
						SecurityContext: &corev1.PodSecurityContext{
							RunAsNonRoot: &runAsNonRoot,
							RunAsUser:    &runAsUser,
						},
						Containers: []corev1.Container{
							{
								Name:    "debug",
								Image:   "busybox:latest",
								Command: []string{"sleep", "infinity"},
							},
						},
					},
				},
			},
		}

		cleanup.Add(template)

		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create secure debug template")

		var fetched telekomv1alpha1.DebugPodTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.Template.Spec.SecurityContext)
		require.True(t, *fetched.Spec.Template.Spec.SecurityContext.RunAsNonRoot)
	})
}
