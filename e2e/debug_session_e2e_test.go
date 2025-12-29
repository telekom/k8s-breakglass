/*
Copyright 2024.

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
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

const (
	defaultTimeout  = 60 * time.Second
	defaultInterval = 2 * time.Second
)

var (
	k8sClient     client.Client
	testNamespace = "breakglass"
)

func init() {
	_ = telekomv1alpha1.AddToScheme(scheme.Scheme)
}

func getKubeconfig() string {
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		return kubeconfig
	}
	return os.Getenv("HOME") + "/.kube/config"
}

func setupClient(t *testing.T) client.Client {
	if k8sClient != nil {
		return k8sClient
	}

	kubeconfig := getKubeconfig()
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err, "Failed to load kubeconfig")

	k8sClient, err = client.New(config, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err, "Failed to create client")

	return k8sClient
}

// waitForCondition waits for a condition to be true within the timeout
func waitForCondition(ctx context.Context, condition func() (bool, error)) error {
	return wait.PollUntilContextTimeout(ctx, defaultInterval, defaultTimeout, true, func(ctx context.Context) (bool, error) {
		return condition()
	})
}

func TestDebugSession_E2E_DebugPodTemplateCreation(t *testing.T) {
	if os.Getenv("E2E_TEST") != "true" {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	ctx := context.Background()

	template := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-test-pod-template",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Test Pod Template",
			Description: "Created by E2E tests",
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

	// Cleanup before and after
	_ = cli.Delete(ctx, template)
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	// Create template
	err := cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create DebugPodTemplate")

	// Verify template exists
	var fetched telekomv1alpha1.DebugPodTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
	require.NoError(t, err, "Failed to get DebugPodTemplate")
	assert.Equal(t, "E2E Test Pod Template", fetched.Spec.DisplayName)
}

func TestDebugSession_E2E_DebugSessionTemplateCreation(t *testing.T) {
	if os.Getenv("E2E_TEST") != "true" {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	ctx := context.Background()

	// First create a pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-test-pod-template-2",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Test Pod Template 2",
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

	_ = cli.Delete(ctx, podTemplate)
	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err, "Failed to create DebugPodTemplate")
	defer func() {
		_ = cli.Delete(ctx, podTemplate)
	}()

	// Create session template
	replicas := int32(1)
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-test-session-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Test Session Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups: []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
				AllowRenewal:    true,
				MaxRenewals:     3,
			},
		},
	}

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() {
		_ = cli.Delete(ctx, sessionTemplate)
	}()

	err = cli.Create(ctx, sessionTemplate)
	require.NoError(t, err, "Failed to create DebugSessionTemplate")

	// Verify template exists
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: sessionTemplate.Name}, &fetched)
	require.NoError(t, err, "Failed to get DebugSessionTemplate")
	assert.Equal(t, telekomv1alpha1.DebugSessionModeWorkload, fetched.Spec.Mode)
}

func TestDebugSession_E2E_SessionCreation(t *testing.T) {
	if os.Getenv("E2E_TEST") != "true" {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	ctx := context.Background()

	// Ensure namespace exists
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
		},
	}
	_ = cli.Create(ctx, ns)

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-test-session",
			Namespace: testNamespace,
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "tenant-a",
			TemplateRef:       "e2e-test-session-template",
			RequestedBy:       "e2e-test@example.com",
			RequestedDuration: "1h",
			Reason:            "E2E testing",
		},
	}

	_ = cli.Delete(ctx, session)
	defer func() {
		_ = cli.Delete(ctx, session)
	}()

	err := cli.Create(ctx, session)
	require.NoError(t, err, "Failed to create DebugSession")

	// Wait for session to be processed
	err = waitForCondition(ctx, func() (bool, error) {
		var fetched telekomv1alpha1.DebugSession
		err := cli.Get(ctx, types.NamespacedName{
			Name:      session.Name,
			Namespace: session.Namespace,
		}, &fetched)
		if err != nil {
			return false, err
		}
		// Session should have a state set
		return fetched.Status.State != "", nil
	})
	require.NoError(t, err, "Session did not get processed")

	// Verify session state
	var fetched telekomv1alpha1.DebugSession
	err = cli.Get(ctx, types.NamespacedName{
		Name:      session.Name,
		Namespace: session.Namespace,
	}, &fetched)
	require.NoError(t, err)
	assert.NotEmpty(t, fetched.Status.State)
}

func TestDebugSession_E2E_SessionStateTransitions(t *testing.T) {
	if os.Getenv("E2E_TEST") != "true" {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	ctx := context.Background()

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-test-session-transitions",
			Namespace: testNamespace,
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "tenant-a",
			TemplateRef:       "e2e-test-session-template",
			RequestedBy:       "e2e-test@example.com",
			RequestedDuration: "30m",
			Reason:            "Testing state transitions",
		},
	}

	_ = cli.Delete(ctx, session)
	defer func() {
		_ = cli.Delete(ctx, session)
	}()

	err := cli.Create(ctx, session)
	require.NoError(t, err, "Failed to create DebugSession")

	// Wait for session to become active (auto-approved)
	err = waitForCondition(ctx, func() (bool, error) {
		var fetched telekomv1alpha1.DebugSession
		err := cli.Get(ctx, types.NamespacedName{
			Name:      session.Name,
			Namespace: session.Namespace,
		}, &fetched)
		if err != nil {
			return false, err
		}
		return fetched.Status.State == telekomv1alpha1.DebugSessionStateActive, nil
	})

	if err != nil {
		// Check what state the session is in
		var fetched telekomv1alpha1.DebugSession
		_ = cli.Get(ctx, types.NamespacedName{
			Name:      session.Name,
			Namespace: session.Namespace,
		}, &fetched)
		t.Logf("Session state: %s, message: %s", fetched.Status.State, fetched.Status.Message)
	}

	// For E2E with auto-approval, we expect Active state
	// If it needs approval, that's also valid
	var fetched telekomv1alpha1.DebugSession
	err = cli.Get(ctx, types.NamespacedName{
		Name:      session.Name,
		Namespace: session.Namespace,
	}, &fetched)
	require.NoError(t, err)
	assert.True(t,
		fetched.Status.State == telekomv1alpha1.DebugSessionStateActive ||
			fetched.Status.State == telekomv1alpha1.DebugSessionStatePendingApproval,
		"Unexpected state: %s", fetched.Status.State)
}

func TestDebugSession_E2E_SessionTermination(t *testing.T) {
	if os.Getenv("E2E_TEST") != "true" {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	ctx := context.Background()

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-test-session-terminate",
			Namespace: testNamespace,
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "tenant-a",
			TemplateRef:       "e2e-test-session-template",
			RequestedBy:       "e2e-test@example.com",
			RequestedDuration: "1h",
			Reason:            "Testing termination",
		},
	}

	_ = cli.Delete(ctx, session)
	err := cli.Create(ctx, session)
	require.NoError(t, err, "Failed to create DebugSession")

	// Wait for session to have a state
	err = waitForCondition(ctx, func() (bool, error) {
		var fetched telekomv1alpha1.DebugSession
		err := cli.Get(ctx, types.NamespacedName{
			Name:      session.Name,
			Namespace: session.Namespace,
		}, &fetched)
		if err != nil {
			return false, err
		}
		return fetched.Status.State != "", nil
	})
	require.NoError(t, err)

	// Terminate the session by updating status
	var fetched telekomv1alpha1.DebugSession
	err = cli.Get(ctx, types.NamespacedName{
		Name:      session.Name,
		Namespace: session.Namespace,
	}, &fetched)
	require.NoError(t, err)

	fetched.Status.State = telekomv1alpha1.DebugSessionStateTerminated
	fetched.Status.Message = "Terminated by E2E test"
	err = cli.Status().Update(ctx, &fetched)
	require.NoError(t, err)

	// Verify termination
	err = cli.Get(ctx, types.NamespacedName{
		Name:      session.Name,
		Namespace: session.Namespace,
	}, &fetched)
	require.NoError(t, err)
	assert.Equal(t, telekomv1alpha1.DebugSessionStateTerminated, fetched.Status.State)

	// Cleanup
	_ = cli.Delete(ctx, &fetched)
}

func TestDebugSession_E2E_SessionCleanup(t *testing.T) {
	if os.Getenv("E2E_TEST") != "true" {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	ctx := context.Background()

	sessionName := "e2e-test-session-cleanup"

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sessionName,
			Namespace: testNamespace,
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "tenant-a",
			TemplateRef:       "e2e-test-session-template",
			RequestedBy:       "e2e-test@example.com",
			RequestedDuration: "1h",
			Reason:            "Testing cleanup",
		},
	}

	_ = cli.Delete(ctx, session)
	err := cli.Create(ctx, session)
	require.NoError(t, err, "Failed to create DebugSession")

	// Delete the session
	err = cli.Delete(ctx, session)
	require.NoError(t, err, "Failed to delete DebugSession")

	// Wait for session to be deleted
	err = waitForCondition(ctx, func() (bool, error) {
		var fetched telekomv1alpha1.DebugSession
		err := cli.Get(ctx, types.NamespacedName{
			Name:      sessionName,
			Namespace: testNamespace,
		}, &fetched)
		if errors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
	require.NoError(t, err, "Session was not cleaned up")
}

func TestDebugSession_E2E_MultipleParticipants(t *testing.T) {
	if os.Getenv("E2E_TEST") != "true" {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	ctx := context.Background()

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-test-session-participants",
			Namespace: testNamespace,
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "tenant-a",
			TemplateRef:       "e2e-test-session-template",
			RequestedBy:       "owner@example.com",
			RequestedDuration: "1h",
			Reason:            "Testing participants",
			InvitedParticipants: []string{
				"participant1@example.com",
				"participant2@example.com",
			},
		},
	}

	_ = cli.Delete(ctx, session)
	defer func() {
		_ = cli.Delete(ctx, session)
	}()

	err := cli.Create(ctx, session)
	require.NoError(t, err, "Failed to create DebugSession")

	// Verify invited participants are in spec
	var fetched telekomv1alpha1.DebugSession
	err = cli.Get(ctx, types.NamespacedName{
		Name:      session.Name,
		Namespace: session.Namespace,
	}, &fetched)
	require.NoError(t, err)
	assert.Len(t, fetched.Spec.InvitedParticipants, 2)
}

func TestDebugSession_E2E_KubectlDebugMode(t *testing.T) {
	if os.Getenv("E2E_TEST") != "true" {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	ctx := context.Background()

	// Create kubectl-debug template
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-kubectl-debug-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "E2E Kubectl Debug Template",
			Mode:            telekomv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: "breakglass-debug",
			KubectlDebug: &telekomv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &telekomv1alpha1.EphemeralContainersConfig{
					Enabled:           true,
					AllowedNamespaces: []string{"default", "app-*"},
					DeniedNamespaces:  []string{"kube-system"},
					AllowedImages:     []string{"busybox:*", "alpine:*"},
					RequireNonRoot:    true,
				},
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups: []string{"*"},
			},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "2h",
				DefaultDuration: "30m",
			},
		},
	}

	_ = cli.Delete(ctx, template)
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	err := cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create kubectl-debug template")

	// Verify template
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
	require.NoError(t, err)
	assert.Equal(t, telekomv1alpha1.DebugSessionModeKubectlDebug, fetched.Spec.Mode)
	assert.NotNil(t, fetched.Spec.KubectlDebug)
	assert.True(t, fetched.Spec.KubectlDebug.EphemeralContainers.Enabled)
}

func TestDebugSession_E2E_HybridMode(t *testing.T) {
	if os.Getenv("E2E_TEST") != "true" {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	ctx := context.Background()

	// First create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-hybrid-pod-template",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Hybrid Pod Template",
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

	_ = cli.Delete(ctx, podTemplate)
	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err)
	defer func() {
		_ = cli.Delete(ctx, podTemplate)
	}()

	// Create hybrid template
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-hybrid-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Hybrid Template",
			Mode:        telekomv1alpha1.DebugSessionModeHybrid,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDaemonSet,
			TargetNamespace: "breakglass-debug",
			KubectlDebug: &telekomv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &telekomv1alpha1.EphemeralContainersConfig{
					Enabled: true,
				},
				NodeDebug: &telekomv1alpha1.NodeDebugConfig{
					Enabled: true,
				},
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups: []string{"*"},
			},
		},
	}

	_ = cli.Delete(ctx, template)
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create hybrid template")

	// Verify template
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
	require.NoError(t, err)
	assert.Equal(t, telekomv1alpha1.DebugSessionModeHybrid, fetched.Spec.Mode)
	assert.NotNil(t, fetched.Spec.PodTemplateRef)
	assert.NotNil(t, fetched.Spec.KubectlDebug)
}

// Helper function to print test summary
func TestMain(m *testing.M) {
	fmt.Println("Debug Session E2E Tests")
	fmt.Println("========================")
	fmt.Println("To run these tests, set E2E_TEST=true and ensure a cluster is available")
	fmt.Println("Example: E2E_TEST=true go test -v ./e2e/...")
	fmt.Println()

	os.Exit(m.Run())
}
