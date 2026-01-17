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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestDebugPodTemplateAdvanced tests DebugPodTemplate CRD features.
func TestDebugPodTemplateAdvanced(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("TemplateWithSecurityContext", func(t *testing.T) {
		runAsNonRoot := true
		runAsUser := int64(1000)
		runAsGroup := int64(1000)

		template := &telekomv1alpha1.DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-pod-security"),
				Labels: helpers.E2ELabelsWithFeature("security-context"),
			},
			Spec: telekomv1alpha1.DebugPodTemplateSpec{
				DisplayName: "Security-Hardened Pod",
				Template: telekomv1alpha1.DebugPodSpec{
					Spec: telekomv1alpha1.DebugPodSpecInner{
						SecurityContext: &corev1.PodSecurityContext{
							RunAsNonRoot: &runAsNonRoot,
							RunAsUser:    &runAsUser,
							RunAsGroup:   &runAsGroup,
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
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create security-hardened pod template")

		var fetched telekomv1alpha1.DebugPodTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.Template.Spec.SecurityContext)
		assert.Equal(t, true, *fetched.Spec.Template.Spec.SecurityContext.RunAsNonRoot)

		t.Logf("Security-hardened pod template created: %s", fetched.Name)
	})

	t.Run("TemplateWithVolumes", func(t *testing.T) {
		template := &telekomv1alpha1.DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-pod-volumes"),
				Labels: helpers.E2ELabelsWithFeature("volumes"),
			},
			Spec: telekomv1alpha1.DebugPodTemplateSpec{
				DisplayName: "Pod with Volumes",
				Template: telekomv1alpha1.DebugPodSpec{
					Spec: telekomv1alpha1.DebugPodSpecInner{
						Volumes: []corev1.Volume{
							{
								Name: "config-volume",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
						},
						Containers: []corev1.Container{
							{
								Name:  "debug",
								Image: "busybox:latest",
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "config-volume",
										MountPath: "/config",
									},
								},
							},
						},
					},
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create pod template with volumes")

		var fetched telekomv1alpha1.DebugPodTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.Template.Spec.Volumes, 1)
		assert.Equal(t, "config-volume", fetched.Spec.Template.Spec.Volumes[0].Name)

		t.Logf("Pod template with volumes created: %s", fetched.Name)
	})
}

// TestDebugSessionTemplateAdvanced tests DebugSessionTemplate CRD features.
func TestDebugSessionTemplateAdvanced(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()

	// Create a pod template first
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   helpers.GenerateUniqueName("e2e-base-pod"),
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Base Pod Template",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: helpers.GetTmuxDebugImage(),
						},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err, "Failed to create base pod template")

	t.Run("TemplateWithConstraints", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-constrained"),
				Labels: helpers.E2ELabelsWithFeature("constraints"),
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName:    "Constrained Session",
				Description:    "Session template with strict constraints",
				PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplate.Name},
				Constraints: &telekomv1alpha1.DebugSessionConstraints{
					MaxDuration:           "2h",
					DefaultDuration:       "30m",
					AllowRenewal:          ptrBool(true),
					MaxRenewals:           ptrInt32(3),
					MaxConcurrentSessions: 2,
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create constrained session template")

		var fetched telekomv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.Constraints)
		assert.Equal(t, "2h", fetched.Spec.Constraints.MaxDuration)
		require.NotNil(t, fetched.Spec.Constraints.MaxRenewals)
		assert.Equal(t, int32(3), *fetched.Spec.Constraints.MaxRenewals)

		t.Logf("Session template with constraints created")
	})

	t.Run("TemplateWithApprovers", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-with-approvers"),
				Labels: helpers.E2ELabelsWithFeature("approvers"),
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName:    "Session with Approvers",
				Description:    "Session template requiring approval",
				PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplate.Name},
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{clusterName, "dev-cluster"},
					Groups:   []string{"developers"},
				},
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Users:  []string{helpers.TestUsers.DebugSessionApprover.Email},
					Groups: []string{"sre-team"},
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create session template with approvers")

		var fetched telekomv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.Approvers)
		assert.Contains(t, fetched.Spec.Approvers.Users, helpers.TestUsers.DebugSessionApprover.Email)

		t.Logf("Session template with approvers created")
	})

	t.Run("TemplateWithTerminalSharing", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-collab"),
				Labels: helpers.E2ELabelsWithFeature("collaboration"),
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName:    "Collaborative Session",
				Description:    "Session template with terminal sharing enabled",
				PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplate.Name},
				TerminalSharing: &telekomv1alpha1.TerminalSharingConfig{
					Enabled:         true,
					Provider:        "tmux",
					MaxParticipants: 5,
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create collaborative session template")

		var fetched telekomv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.TerminalSharing)
		assert.True(t, fetched.Spec.TerminalSharing.Enabled)
		assert.Equal(t, int32(5), fetched.Spec.TerminalSharing.MaxParticipants)

		t.Logf("Collaborative session template created with %d max participants",
			fetched.Spec.TerminalSharing.MaxParticipants)
	})
}

// TestDebugSessionCRUD tests DebugSession create/read/update/delete operations.
func TestDebugSessionCRUD(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create prerequisites: pod template and session template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   helpers.GenerateUniqueName("e2e-debug-pod"),
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "CRUD Test Pod",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
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
	cleanup.Add(podTemplate)
	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err)

	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   helpers.GenerateUniqueName("e2e-debug-session-tmpl"),
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:    "CRUD Test Template",
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplate.Name},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.DebugSessionRequester.Groups,
			},
		},
	}
	cleanup.Add(sessionTemplate)
	err = cli.Create(ctx, sessionTemplate)
	require.NoError(t, err)

	// Create test context for authenticated API client
	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.ClientForUser(helpers.TestUsers.DebugSessionRequester)

	t.Run("CreateDebugSession", func(t *testing.T) {
		session, err := requesterClient.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
			TemplateRef: sessionTemplate.Name,
			Cluster:     clusterName,
			Namespace:   namespace,
		})
		require.NoError(t, err, "Failed to create DebugSession via API")

		// Add to cleanup
		var sessionToCleanup telekomv1alpha1.DebugSession
		errGet := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &sessionToCleanup)
		require.NoError(t, errGet)
		cleanup.Add(&sessionToCleanup)

		var fetched telekomv1alpha1.DebugSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, sessionTemplate.Name, fetched.Spec.TemplateRef)

		t.Logf("DebugSession created via API: %s", fetched.Name)
	})
}

// ptrBool returns a pointer to a bool value
func ptrBool(b bool) *bool {
	return &b
}

// ptrInt32 returns a pointer to an int32 value
func ptrInt32(i int32) *int32 {
	return &i
}
