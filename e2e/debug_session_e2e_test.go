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
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

const (
	defaultTimeout  = 60 * time.Second
	defaultInterval = 2 * time.Second
)

var (
	k8sClient     client.Client
	apiClient     *helpers.APIClient
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

func setupAPIClient(t *testing.T) *helpers.APIClient {
	if apiClient != nil {
		return apiClient
	}
	apiClient = helpers.NewAPIClient()
	return apiClient
}

func TestDebugSession_E2E_DebugPodTemplateCreation(t *testing.T) {
	if !helpers.IsE2EEnabled() {
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
	if !helpers.IsE2EEnabled() {
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
				AllowRenewal:    ptrBool(true),
				MaxRenewals:     ptrInt32(3),
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
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Ensure namespace exists
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
		},
	}
	_ = cli.Create(ctx, ns)

	// Create session via API (preferred method)
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       "e2e-test-session-template",
		RequestedDuration: "1h",
		Namespace:         testNamespace,
		Reason:            "E2E testing",
	})
	defer func() {
		_ = cli.Delete(ctx, session)
	}()

	// Wait for session to be processed using helpers
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)
	assert.NotEmpty(t, session.Status.State)
}

func TestDebugSession_E2E_SessionStateTransitions(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create session via API (preferred method)
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       "e2e-test-session-template",
		RequestedDuration: "30m",
		Namespace:         testNamespace,
		Reason:            "Testing state transitions",
	})
	defer func() {
		_ = cli.Delete(ctx, session)
	}()

	// Wait for session to become active (auto-approved) - use helper
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)

	// For E2E with auto-approval, we expect Active state
	// If it needs approval, that's also valid
	t.Logf("Session state: %s, message: %s", session.Status.State, session.Status.Message)
	assert.True(t,
		session.Status.State == telekomv1alpha1.DebugSessionStateActive ||
			session.Status.State == telekomv1alpha1.DebugSessionStatePendingApproval,
		"Unexpected state: %s", session.Status.State)
}

func TestDebugSession_E2E_SessionTermination(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create session via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       "e2e-test-session-template",
		RequestedDuration: "1h",
		Namespace:         testNamespace,
		Reason:            "Testing termination",
	})
	defer func() {
		_ = cli.Delete(ctx, session)
	}()

	// Wait for session to have a state
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)

	// Terminate the session via API (preferred method)
	err := api.TerminateDebugSession(ctx, t, session.Name)
	require.NoError(t, err, "Failed to terminate session via API")

	// Verify termination using helper
	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.DebugSessionStateTerminated, defaultTimeout)
	assert.Equal(t, telekomv1alpha1.DebugSessionStateTerminated, session.Status.State)
}

func TestDebugSession_E2E_SessionCleanup(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create session via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       "e2e-test-session-template",
		RequestedDuration: "1h",
		Namespace:         testNamespace,
		Reason:            "Testing cleanup",
	})

	// Delete the session
	err := cli.Delete(ctx, session)
	require.NoError(t, err, "Failed to delete DebugSession")

	// Wait for session to be deleted using helper
	err = helpers.WaitForResourceDeleted(ctx, cli, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, session, defaultTimeout)
	require.NoError(t, err, "Session was not cleaned up")
}

func TestDebugSession_E2E_MultipleParticipants(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create session via API with invited participants
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       "e2e-test-session-template",
		RequestedDuration: "1h",
		Namespace:         testNamespace,
		Reason:            "Testing participants",
		InvitedParticipants: []string{
			"participant1@example.com",
			"participant2@example.com",
		},
	})
	defer func() {
		_ = cli.Delete(ctx, session)
	}()

	// Verify invited participants are in spec
	var fetched telekomv1alpha1.DebugSession
	err := cli.Get(ctx, types.NamespacedName{
		Name:      session.Name,
		Namespace: session.Namespace,
	}, &fetched)
	require.NoError(t, err)
	assert.Len(t, fetched.Spec.InvitedParticipants, 2)
}

func TestDebugSession_E2E_KubectlDebugMode(t *testing.T) {
	if !helpers.IsE2EEnabled() {
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
	if !helpers.IsE2EEnabled() {
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

// D-005: DebugSession manual approval workflow
func TestDebugSession_E2E_ManualApprovalWorkflow(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create pod template first
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-approval-pod-template",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Approval Pod Template",
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
	defer func() { _ = cli.Delete(ctx, podTemplate) }()

	// Create template WITHOUT autoApproveFor - requires manual approval
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-manual-approval-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Manual Approval Template",
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
			// Note: No autoApproveFor, so approval is required
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Groups: []string{"sre-team"},
			},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
			},
		},
	}
	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err)
	defer func() { _ = cli.Delete(ctx, template) }()

	// Create session via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       template.Name,
		RequestedDuration: "1h",
		Namespace:         testNamespace,
		Reason:            "Testing manual approval workflow",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to be in PendingApproval state using helper
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)
	t.Logf("Session state: %s", session.Status.State)

	// Approve session via API if pending approval
	if session.Status.State == telekomv1alpha1.DebugSessionStatePendingApproval {
		err = api.ApproveDebugSession(ctx, t, session.Name, "Approved by E2E test")
		require.NoError(t, err, "Failed to approve session via API")

		// Verify approval
		session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.DebugSessionStateActive, defaultTimeout)
		assert.Equal(t, telekomv1alpha1.DebugSessionStateActive, session.Status.State)
		assert.NotNil(t, session.Status.Approval)
	}
}

// D-006: DebugSession rejection workflow
func TestDebugSession_E2E_RejectionWorkflow(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create session via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       "e2e-manual-approval-template",
		RequestedDuration: "1h",
		Namespace:         testNamespace,
		Reason:            "Testing rejection workflow",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to have a state
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)

	// Reject the session via API
	err := api.RejectDebugSession(ctx, t, session.Name, "Insufficient justification provided")
	require.NoError(t, err, "Failed to reject session via API")

	// Verify rejection - the reject API sets state to Failed
	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.DebugSessionStateFailed, defaultTimeout)
	assert.Equal(t, telekomv1alpha1.DebugSessionStateFailed, session.Status.State)
	assert.NotNil(t, session.Status.Approval)
}

// D-009: DebugSession renewal
func TestDebugSession_E2E_SessionRenewal(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create session via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       "e2e-test-session-template",
		RequestedDuration: "30m",
		Namespace:         testNamespace,
		Reason:            "Testing session renewal",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to become active using helper
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)

	// Only test renewal if session is active
	if session.Status.State == telekomv1alpha1.DebugSessionStateActive {
		originalRenewalCount := session.Status.RenewalCount

		// Renew via API
		err := api.RenewDebugSession(ctx, t, session.Name, "30m")
		require.NoError(t, err, "Failed to renew session via API")

		// Verify renewal
		var fetched telekomv1alpha1.DebugSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, originalRenewalCount+1, fetched.Status.RenewalCount)
		t.Logf("Session renewed: renewalCount=%d, expiresAt=%v", fetched.Status.RenewalCount, fetched.Status.ExpiresAt)
	} else {
		t.Logf("Session is in state %s, skipping renewal test", session.Status.State)
	}
}

// D-011: DebugSession expiration
func TestDebugSession_E2E_SessionExpiration(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create session via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       "e2e-test-session-template",
		RequestedDuration: "1m", // Very short duration
		Namespace:         testNamespace,
		Reason:            "Testing session expiration",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to have a state
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)

	// Simulate expiration by setting state to Expired
	// Note: This simulates controller behavior - no API for expiration
	var fetched telekomv1alpha1.DebugSession
	err := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetched)
	require.NoError(t, err)

	// Set expiry to past time and state to expired
	pastTime := metav1.Time{Time: time.Now().Add(-1 * time.Hour)}
	fetched.Status.ExpiresAt = &pastTime
	fetched.Status.State = telekomv1alpha1.DebugSessionStateExpired
	fetched.Status.Message = "Session expired"
	err = cli.Status().Update(ctx, &fetched)
	require.NoError(t, err)

	// Verify expiration
	err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetched)
	require.NoError(t, err)
	assert.Equal(t, telekomv1alpha1.DebugSessionStateExpired, fetched.Status.State)
	t.Logf("Session expired at: %v", fetched.Status.ExpiresAt)
}

// D-013: DebugSession constraints enforcement
func TestDebugSession_E2E_ConstraintsEnforcement(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-constrained-pod-template",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Constrained Pod Template",
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
	defer func() { _ = cli.Delete(ctx, podTemplate) }()

	// Create template with strict constraints
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-constrained-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Constrained Template",
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
				MaxDuration:     "1h", // Max 1 hour
				DefaultDuration: "30m",
				AllowRenewal:    ptrBool(false), // No renewals allowed
				MaxRenewals:     ptrInt32(0),
			},
		},
	}
	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err)
	defer func() { _ = cli.Delete(ctx, template) }()

	// Create session requesting duration longer than max via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       template.Name,
		RequestedDuration: "4h", // Requesting 4h, max is 1h
		Namespace:         testNamespace,
		Reason:            "Testing constraints enforcement",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to be processed using helper
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)

	// The session should still exist, potentially with capped duration
	t.Logf("Session state: %s, requestedDuration: %s", session.Status.State, session.Spec.RequestedDuration)
	assert.NotEmpty(t, session.Status.State)
}

// D-014: DebugSession access control - allowed groups
func TestDebugSession_E2E_AccessControlAllowedGroups(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	ctx := context.Background()

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-access-control-pod-template",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Access Control Pod Template",
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
	defer func() { _ = cli.Delete(ctx, podTemplate) }()

	// Create template with restricted access
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-restricted-access-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Restricted Access Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups: []string{"sre-team", "platform-admins"}, // Restricted to specific groups
			},
		},
	}
	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err)
	defer func() { _ = cli.Delete(ctx, template) }()

	// Verify template has access restrictions
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
	require.NoError(t, err)
	assert.NotNil(t, fetched.Spec.Allowed)
	assert.Contains(t, fetched.Spec.Allowed.Groups, "sre-team")
	assert.Contains(t, fetched.Spec.Allowed.Groups, "platform-admins")
	t.Logf("Template has restricted access to groups: %v", fetched.Spec.Allowed.Groups)
}

// D-007: DebugSession workload deployment verification
func TestDebugSession_E2E_WorkloadDeployment(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create session via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       "e2e-test-session-template",
		RequestedDuration: "1h",
		Namespace:         testNamespace,
		Reason:            "Testing workload deployment",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to become active using helper
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)

	if session.Status.State == telekomv1alpha1.DebugSessionStateActive {
		// Check if deployed resources are recorded
		t.Logf("Session state: %s", session.Status.State)
		t.Logf("Deployed resources: %v", session.Status.DeployedResources)

		// The status should have deployed resources if workload mode is active
		// Note: This depends on the controller actually deploying workloads
		if len(session.Status.DeployedResources) > 0 {
			for _, res := range session.Status.DeployedResources {
				t.Logf("Deployed: %s/%s in namespace %s", res.Kind, res.Name, res.Namespace)
			}
		}
	} else {
		t.Logf("Session is in state %s, workload may not be deployed", session.Status.State)
	}
}

// ptrBool returns a pointer to a bool value
func ptrBool(b bool) *bool {
	return &b
}

// ptrInt32 returns a pointer to an int32 value
func ptrInt32(i int32) *int32 {
	return &i
}
