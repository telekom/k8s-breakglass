//go:build e2e

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

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

func TestKubectlDebuggingMode(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := helpers.NewTestContext(t, ctx)
	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()

	// 1. Create a DebugSessionTemplate for kubectl-debug mode
	templateName := "e2e-kubectl-debug-tmpl"

	tmpl := &v1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: templateName,
		},
		Spec: v1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Kubectl Debug",
			Mode:        v1alpha1.DebugSessionModeKubectlDebug,
			Rules: v1alpha1.DebugSessionRules{
				AutoApprove: true,
			},
			KubectlDebug: &v1alpha1.KubectlDebugConfig{
				EphemeralContainers: &v1alpha1.EphemeralContainerConfig{
					Enabled:        true,
					AllowedImages:  []string{"busybox", "alpine"},
					RequireNonRoot: false,
				},
				NodeDebug: &v1alpha1.NodeDebugConfig{
					Enabled: true,
				},
			},
		},
	}
	cleanup.Add(tmpl)
	err := cli.Create(ctx, tmpl)
	require.NoError(t, err, "Failed to create DebugSessionTemplate")

	// 2. Create a target pod to debug
	targetPodName := "debug-target-pod"
	targetNs := "default"
	targetPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetPodName,
			Namespace: targetNs,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Image: "nginx:alpine",
				},
			},
		},
	}
	cleanup.Add(targetPod)
	err = cli.Create(ctx, targetPod)
	if err != nil {
		t.Logf("Pod may already exist: %v", err)
	}

	// Wait for pod to be ready
	require.Eventually(t, func() bool {
		p := &corev1.Pod{}
		err := cli.Get(ctx, client.ObjectKey{Name: targetPodName, Namespace: targetNs}, p)
		return err == nil && p.Status.Phase == corev1.PodRunning
	}, helpers.WaitForConditionTimeout, 2*time.Second)

	// 3. Request a Debug Session (should auto-approve)
	requesterClient := tc.RequesterClient()
	session, err := requesterClient.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
		Cluster:     clusterName,
		TemplateRef: templateName,
		Reason:      "E2E Test Ephemeral",
	})
	require.NoError(t, err)
	cleanup.Add(&v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
	})

	helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		v1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)

	t.Log("Debug session activated for kubectl-debug mode")

	// 4. Verify session is active and has correct mode
	var activeSession v1alpha1.DebugSession
	err = cli.Get(ctx, client.ObjectKey{Name: session.Name, Namespace: session.Namespace}, &activeSession)
	require.NoError(t, err)
	require.Equal(t, v1alpha1.DebugSessionStateActive, activeSession.Status.State)

	t.Log("Kubectl debug mode test passed - session created and activated")
}

func TestTerminalSharingMode(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := helpers.NewTestContext(t, ctx)
	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()

	// Create template with terminal sharing enabled
	templateName := "e2e-terminal-sharing-tmpl"

	tmpl := &v1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: templateName,
		},
		Spec: v1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "E2E Terminal Sharing",
			Mode:            v1alpha1.DebugSessionModeWorkload,
			WorkloadType:    v1alpha1.DebugWorkloadDeployment,
			TargetNamespace: "default",
			Rules: v1alpha1.DebugSessionRules{
				AutoApprove: true,
			},
			PodTemplateRef: &v1alpha1.DebugPodTemplateRef{
				Name: "netshoot-base",
			},
			TerminalSharing: &v1alpha1.TerminalSharingConfig{
				Enabled:         true,
				Provider:        "tmux",
				MaxParticipants: 5,
			},
		},
	}
	cleanup.Add(tmpl)

	// Create base pod template
	podTmpl := &v1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "netshoot-base",
		},
		Spec: v1alpha1.DebugPodTemplateSpec{
			DisplayName: "Netshoot Base",
			Template: v1alpha1.DebugPodSpec{
				Spec: v1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:    "debug",
							Image:   helpers.GetTmuxDebugImage(),
							Command: []string{"sleep", "infinity"},
						},
					},
				},
			},
		},
	}
	cleanup.Add(podTmpl)
	err := cli.Create(ctx, podTmpl)
	require.NoError(t, err, "Failed to create DebugPodTemplate")

	err = cli.Create(ctx, tmpl)
	require.NoError(t, err, "Failed to create DebugSessionTemplate")

	// Request debug session
	requesterClient := tc.RequesterClient()
	session, err := requesterClient.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
		Cluster:     clusterName,
		TemplateRef: templateName,
		Reason:      "E2E Test Terminal Sharing",
	})
	require.NoError(t, err)
	cleanup.Add(&v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
	})

	helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		v1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

	// Verify terminal sharing is configured in status
	var activeSession v1alpha1.DebugSession
	err = cli.Get(ctx, client.ObjectKey{Name: session.Name, Namespace: session.Namespace}, &activeSession)
	require.NoError(t, err)
	require.NotNil(t, activeSession.Status.TerminalSharing, "Terminal sharing status should be set")
	require.Equal(t, "tmux", activeSession.Status.TerminalSharing.Provider)
	require.NotEmpty(t, activeSession.Status.TerminalSharing.AttachCommand)

	t.Logf("Terminal sharing configured with attach command: %s", activeSession.Status.TerminalSharing.AttachCommand)
}
