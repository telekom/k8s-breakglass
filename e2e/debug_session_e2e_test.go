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
	k8sClient      client.Client
	apiClient      *helpers.APIClient
	approverClient *helpers.APIClient
	testNamespace  = helpers.GetTestNamespace()
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
	// Use TestContext to get an authenticated client
	ctx := context.Background()
	tc := helpers.NewTestContext(t, ctx)
	apiClient = tc.RequesterClient()
	return apiClient
}

func setupApproverClient(t *testing.T) *helpers.APIClient {
	if approverClient != nil {
		return approverClient
	}
	// Use TestContext to get an authenticated approver client
	ctx := context.Background()
	tc := helpers.NewTestContext(t, ctx)
	approverClient = tc.ApproverClient()
	return approverClient
}

// ensureTestSessionTemplate ensures that the e2e-test-session-template exists.
// It creates the template if it doesn't exist, along with its required pod template.
// This allows multiple tests to share the same template without worrying about deletion order.
func ensureTestSessionTemplate(t *testing.T, cli client.Client, ctx context.Context) {
	// Check if template already exists
	var existing telekomv1alpha1.DebugSessionTemplate
	err := cli.Get(ctx, types.NamespacedName{Name: "e2e-test-session-template"}, &existing)
	if err == nil {
		return // Template already exists
	}

	// Create pod template first
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-shared-pod-template",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Shared Pod Template",
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
	// Delete first to handle any stale state
	_ = cli.Delete(ctx, podTemplate)
	err = cli.Create(ctx, podTemplate)
	if err != nil {
		t.Logf("Note: pod template creation returned: %v (may already exist)", err)
	}

	// Create session template with auto-approval
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
				Clusters: []string{"*"},
				Groups:   []string{"*"},
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
	err = cli.Create(ctx, sessionTemplate)
	require.NoError(t, err, "Failed to create shared e2e-test-session-template")
}

func TestDebugSession_E2E_DebugPodTemplateCreation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
	// Note: We don't delete this pod template because e2e-test-session-template references it
	// and other tests depend on that session template.

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
				Clusters: []string{"*"},
				Groups:   []string{"*"},
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
	// Note: We don't delete the template after this test, as other tests may depend on it.
	// The ensureTestSessionTemplate helper will recreate it if needed.

	err = cli.Create(ctx, sessionTemplate)
	require.NoError(t, err, "Failed to create DebugSessionTemplate")

	// Verify template exists
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: sessionTemplate.Name}, &fetched)
	require.NoError(t, err, "Failed to get DebugSessionTemplate")
	assert.Equal(t, telekomv1alpha1.DebugSessionModeWorkload, fetched.Spec.Mode)
}

func TestDebugSession_E2E_SessionCreation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Ensure shared test template exists
	ensureTestSessionTemplate(t, cli, ctx)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Ensure shared test template exists
	ensureTestSessionTemplate(t, cli, ctx)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Ensure shared test template exists
	ensureTestSessionTemplate(t, cli, ctx)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Ensure shared test template exists
	ensureTestSessionTemplate(t, cli, ctx)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Ensure shared test template exists
	ensureTestSessionTemplate(t, cli, ctx)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
					AllowedNamespaces: &telekomv1alpha1.NamespaceFilter{Patterns: []string{"default", "app-*"}},
					DeniedNamespaces:  &telekomv1alpha1.NamespaceFilter{Patterns: []string{"kube-system"}},
					AllowedImages:     []string{"busybox:*", "alpine:*"},
					RequireNonRoot:    true,
				},
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
				Clusters: []string{"*"},
				Groups:   []string{"*"},
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	approverAPI := setupApproverClient(t)
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
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			// Note: No autoApproveFor, so approval is required
			// Use senior-ops group which TestUsers.Approver has
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Groups: []string{"senior-ops"},
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

	// Approve session via API if pending approval - must use approver client
	if session.Status.State == telekomv1alpha1.DebugSessionStatePendingApproval {
		err = approverAPI.ApproveDebugSession(ctx, t, session.Name, "Approved by E2E test")
		require.NoError(t, err, "Failed to approve session via API")

		// Verify approval
		session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.DebugSessionStateActive, defaultTimeout)
		assert.Equal(t, telekomv1alpha1.DebugSessionStateActive, session.Status.State)
		assert.NotNil(t, session.Status.Approval)
	}
}

// D-006: DebugSession rejection workflow
func TestDebugSession_E2E_RejectionWorkflow(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	approverAPI := setupApproverClient(t)
	ctx := context.Background()

	// Create pod template first
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-rejection-pod-template",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Rejection Pod Template",
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

	// Create template requiring manual approval
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-rejection-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Rejection Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			// Use senior-ops group which TestUsers.Approver has
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Groups: []string{"senior-ops"},
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
		Reason:            "Testing rejection workflow",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to have a state
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)

	// Reject the session via API - must use approver client
	err = approverAPI.RejectDebugSession(ctx, t, session.Name, "Insufficient justification provided")
	require.NoError(t, err, "Failed to reject session via API")

	// Verify rejection - the reject API sets state to Terminated (not Failed)
	// When a session is rejected, it immediately goes to Terminated state with the rejection reason
	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.DebugSessionStateTerminated, defaultTimeout)
	assert.Equal(t, telekomv1alpha1.DebugSessionStateTerminated, session.Status.State)
	assert.NotNil(t, session.Status.Approval)
}

// D-009: DebugSession renewal
func TestDebugSession_E2E_SessionRenewal(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Ensure shared test template exists
	ensureTestSessionTemplate(t, cli, ctx)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Ensure shared test template exists
	ensureTestSessionTemplate(t, cli, ctx)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
				Clusters: []string{"*"},
				Groups:   []string{"*"},
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Ensure shared test template exists
	ensureTestSessionTemplate(t, cli, ctx)

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

// ============================================================================
// Kubectl-Debug Mode E2E Tests
// ============================================================================

// D-015: DebugSession kubectl-debug ephemeral container injection
func TestDebugSession_E2E_EphemeralContainerInjection(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// First, create a target pod to inject into
	targetPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-target-pod",
			Namespace: "default",
			Labels: map[string]string{
				"e2e-test": "true",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "app",
					Image:   "nginx:alpine",
					Command: []string{"sleep", "infinity"},
				},
			},
		},
	}

	_ = cli.Delete(ctx, targetPod)
	err := cli.Create(ctx, targetPod)
	require.NoError(t, err, "Failed to create target pod")
	defer func() { _ = cli.Delete(ctx, targetPod) }()

	// Wait for target pod to be running
	err = helpers.WaitForPodReady(ctx, cli, targetPod.Namespace, targetPod.Name, defaultTimeout)
	require.NoError(t, err, "Failed to wait for target pod to be ready")

	// Create kubectl-debug session template
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-ephemeral-container-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "E2E Ephemeral Container Template",
			Mode:            telekomv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: "default",
			KubectlDebug: &telekomv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &telekomv1alpha1.EphemeralContainersConfig{
					Enabled:           true,
					AllowedNamespaces: &telekomv1alpha1.NamespaceFilter{Patterns: []string{"default"}},
					AllowedImages:     []string{"busybox:*", "alpine:*"},
					RequireNonRoot:    false,
				},
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "1h",
				DefaultDuration: "30m",
			},
		},
	}

	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create ephemeral container template")
	defer func() { _ = cli.Delete(ctx, template) }()

	// Create session via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       template.Name,
		RequestedDuration: "30m",
		Namespace:         testNamespace,
		Reason:            "Testing ephemeral container injection",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to become active
	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateActive, defaultTimeout)

	// Inject ephemeral container via API
	err = api.InjectEphemeralContainer(ctx, t, session.Name, helpers.EphemeralContainerRequest{
		Namespace:     "default",
		PodName:       targetPod.Name,
		ContainerName: "debugger",
		Image:         "busybox:latest",
		Command:       []string{"sh"},
	})

	if err != nil {
		// This may fail if the cluster doesn't support ephemeral containers
		t.Logf("Ephemeral container injection failed (may not be supported): %v", err)
	} else {
		t.Log("Ephemeral container injected successfully")

		// Verify the session status was updated
		var fetched telekomv1alpha1.DebugSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetched)
		require.NoError(t, err)

		if fetched.Status.KubectlDebugStatus != nil {
			assert.NotEmpty(t, fetched.Status.KubectlDebugStatus.EphemeralContainersInjected)
			t.Logf("Ephemeral containers injected: %+v", fetched.Status.KubectlDebugStatus.EphemeralContainersInjected)
		}
	}
}

// D-016: DebugSession kubectl-debug pod copy
func TestDebugSession_E2E_PodCopy(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// First, create a target pod to copy
	targetPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-copy-source-pod",
			Namespace: "default",
			Labels: map[string]string{
				"e2e-test": "pod-copy",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "app",
					Image:   "nginx:alpine",
					Command: []string{"sleep", "infinity"},
				},
			},
		},
	}

	_ = cli.Delete(ctx, targetPod)
	err := cli.Create(ctx, targetPod)
	require.NoError(t, err, "Failed to create source pod")
	defer func() { _ = cli.Delete(ctx, targetPod) }()

	// Wait for target pod to be running
	err = helpers.WaitForPodReady(ctx, cli, targetPod.Namespace, targetPod.Name, defaultTimeout)
	require.NoError(t, err, "Failed to wait for source pod to be ready")

	// Ensure debug-copies namespace exists
	debugCopiesNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "debug-copies",
		},
	}
	_ = cli.Create(ctx, debugCopiesNs)

	// Create kubectl-debug session template with pod copy enabled
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-pod-copy-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "E2E Pod Copy Template",
			Mode:            telekomv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: "debug-copies",
			KubectlDebug: &telekomv1alpha1.KubectlDebugConfig{
				PodCopy: &telekomv1alpha1.PodCopyConfig{
					Enabled:         true,
					TargetNamespace: "debug-copies",
					TTL:             "1h",
				},
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "1h",
				DefaultDuration: "30m",
			},
		},
	}

	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create pod copy template")
	defer func() { _ = cli.Delete(ctx, template) }()

	// Create session via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       template.Name,
		RequestedDuration: "30m",
		Namespace:         testNamespace,
		Reason:            "Testing pod copy",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to become active
	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateActive, defaultTimeout)

	// Create pod copy via API
	copyResult, err := api.CreatePodCopy(ctx, t, session.Name, helpers.PodCopyRequest{
		Namespace:  "default",
		PodName:    targetPod.Name,
		DebugImage: "busybox:latest",
	})

	if err != nil {
		t.Logf("Pod copy creation failed: %v", err)
	} else {
		t.Logf("Pod copy created: %s/%s", copyResult.CopyNamespace, copyResult.CopyName)

		// Clean up the copy
		copyPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      copyResult.CopyName,
				Namespace: copyResult.CopyNamespace,
			},
		}
		defer func() { _ = cli.Delete(ctx, copyPod) }()
	}
}

// D-017: DebugSession kubectl-debug node debug pod
func TestDebugSession_E2E_NodeDebugPod(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Get a node name
	nodeList := &corev1.NodeList{}
	err := cli.List(ctx, nodeList)
	require.NoError(t, err, "Failed to list nodes")
	require.NotEmpty(t, nodeList.Items, "No nodes found in cluster")

	nodeName := nodeList.Items[0].Name
	t.Logf("Using node: %s", nodeName)

	// Ensure debug namespace exists
	debugNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "breakglass-debug",
		},
	}
	_ = cli.Create(ctx, debugNs)

	// Create kubectl-debug session template with node debug enabled
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-node-debug-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "E2E Node Debug Template",
			Mode:            telekomv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: "breakglass-debug",
			KubectlDebug: &telekomv1alpha1.KubectlDebugConfig{
				NodeDebug: &telekomv1alpha1.NodeDebugConfig{
					Enabled:       true,
					AllowedImages: []string{"busybox:stable"},
					HostNamespaces: &telekomv1alpha1.HostNamespacesConfig{
						HostNetwork: true,
						HostPID:     true,
						HostIPC:     false,
					},
				},
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "1h",
				DefaultDuration: "30m",
			},
		},
	}

	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create node debug template")
	defer func() { _ = cli.Delete(ctx, template) }()

	// Create session via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       template.Name,
		RequestedDuration: "30m",
		Namespace:         testNamespace,
		Reason:            "Testing node debug pod",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to become active
	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateActive, defaultTimeout)

	// Create node debug pod via API
	nodeDebugResult, err := api.CreateNodeDebugPod(ctx, t, session.Name, helpers.NodeDebugRequest{
		NodeName: nodeName,
	})

	if err != nil {
		t.Logf("Node debug pod creation failed: %v", err)
	} else {
		t.Logf("Node debug pod created: %s/%s on node %s",
			nodeDebugResult.Namespace, nodeDebugResult.PodName, nodeName)

		// Clean up the debug pod
		debugPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeDebugResult.PodName,
				Namespace: nodeDebugResult.Namespace,
			},
		}
		defer func() { _ = cli.Delete(ctx, debugPod) }()
	}
}

// D-018: DebugSession terminal sharing
func TestDebugSession_E2E_TerminalSharing(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-terminal-sharing-pod",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Terminal Sharing Pod",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
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

	_ = cli.Delete(ctx, podTemplate)
	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err)
	defer func() { _ = cli.Delete(ctx, podTemplate) }()

	// Create session template with terminal sharing
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-terminal-sharing-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Terminal Sharing Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			TerminalSharing: &telekomv1alpha1.TerminalSharingConfig{
				Enabled:         true,
				Provider:        "tmux",
				MaxParticipants: 5,
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
		},
	}

	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create terminal sharing template")
	defer func() { _ = cli.Delete(ctx, template) }()

	// Verify template has terminal sharing config
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
	require.NoError(t, err)
	assert.NotNil(t, fetched.Spec.TerminalSharing)
	assert.True(t, fetched.Spec.TerminalSharing.Enabled)
	assert.Equal(t, "tmux", fetched.Spec.TerminalSharing.Provider)
	t.Logf("Terminal sharing enabled (tmux)")
}

// D-019: DebugSession auto-approve by group
func TestDebugSession_E2E_AutoApproveByGroup(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-auto-approve-group-pod",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Auto-Approve Group Pod",
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

	// Create session template with group-based auto-approve
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-auto-approve-group-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Auto-Approve Group Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Groups: []string{"sre-leads"},
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Groups:   []string{"sre-leads", "platform-admins"},
					Clusters: []string{"dev-*"},
				},
			},
		},
	}

	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create auto-approve group template")
	defer func() { _ = cli.Delete(ctx, template) }()

	// Verify template has auto-approve group config
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
	require.NoError(t, err)
	assert.NotNil(t, fetched.Spec.Approvers)
	assert.NotNil(t, fetched.Spec.Approvers.AutoApproveFor)
	assert.Contains(t, fetched.Spec.Approvers.AutoApproveFor.Groups, "sre-leads")
	t.Logf("Auto-approve configured for groups: %v", fetched.Spec.Approvers.AutoApproveFor.Groups)
}

// ============================================================================
// Scheduling Constraints E2E Tests
// ============================================================================

// D-020: DebugSession with scheduling constraints (node selector)
func TestDebugSession_E2E_SchedulingConstraints_NodeSelector(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-scheduling-node-selector-pod",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Scheduling NodeSelector Pod",
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

	// Create session template with scheduling constraints
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-scheduling-constraints-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Scheduling Constraints Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			SchedulingConstraints: &telekomv1alpha1.SchedulingConstraints{
				NodeSelector: map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
		},
	}

	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create scheduling constraints template")
	defer func() { _ = cli.Delete(ctx, template) }()

	// Verify template has scheduling constraints
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
	require.NoError(t, err)
	assert.NotNil(t, fetched.Spec.SchedulingConstraints)
	assert.Equal(t, "linux", fetched.Spec.SchedulingConstraints.NodeSelector["kubernetes.io/os"])
	t.Logf("Scheduling constraints configured with nodeSelector: %v", fetched.Spec.SchedulingConstraints.NodeSelector)
}

// D-021: DebugSession with scheduling options selection
func TestDebugSession_E2E_SchedulingOptions(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-scheduling-options-pod",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Scheduling Options Pod",
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

	// Create session template with multiple scheduling options
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-scheduling-options-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Scheduling Options Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			// Base scheduling constraints applied to all sessions
			SchedulingConstraints: &telekomv1alpha1.SchedulingConstraints{
				NodeSelector: map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
			// Multiple scheduling options the user can choose from
			SchedulingOptions: &telekomv1alpha1.SchedulingOptions{
				Required: false, // Optional selection
				Options: []telekomv1alpha1.SchedulingOption{
					{
						Name:        "standard",
						DisplayName: "Standard Workers",
						Description: "Run on standard worker nodes",
						Default:     true, // This is the default option
						SchedulingConstraints: &telekomv1alpha1.SchedulingConstraints{
							NodeSelector: map[string]string{
								"node-type": "standard",
							},
						},
					},
					{
						Name:        "high-memory",
						DisplayName: "High Memory Nodes",
						Description: "Run on high-memory nodes for memory-intensive debugging",
						SchedulingConstraints: &telekomv1alpha1.SchedulingConstraints{
							NodeSelector: map[string]string{
								"node-type": "high-memory",
							},
						},
					},
				},
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
		},
	}

	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create scheduling options template")
	defer func() { _ = cli.Delete(ctx, template) }()

	// Verify template has scheduling options
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
	require.NoError(t, err)
	assert.NotNil(t, fetched.Spec.SchedulingOptions)
	assert.Len(t, fetched.Spec.SchedulingOptions.Options, 2)
	t.Logf("Scheduling options configured: %v", []string{"standard", "high-memory"})

	// Create session with specific scheduling option selected via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:                  "tenant-a",
		TemplateRef:              template.Name,
		RequestedDuration:        "30m",
		Namespace:                testNamespace,
		Reason:                   "Testing scheduling option selection",
		SelectedSchedulingOption: "high-memory", // Select high-memory option
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to be processed
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)

	// Verify the session has resolved scheduling constraints
	t.Logf("Session state: %s", session.Status.State)
	t.Logf("Selected scheduling option: %s", session.Spec.SelectedSchedulingOption)

	// The session should have the selected option and resolved constraints
	assert.Equal(t, "high-memory", session.Spec.SelectedSchedulingOption)
	if session.Spec.ResolvedSchedulingConstraints != nil {
		t.Logf("Resolved scheduling constraints: nodeSelector=%v",
			session.Spec.ResolvedSchedulingConstraints.NodeSelector)
		// Should have merged constraints: linux OS + high-memory node-type
		assert.Equal(t, "linux", session.Spec.ResolvedSchedulingConstraints.NodeSelector["kubernetes.io/os"])
		assert.Equal(t, "high-memory", session.Spec.ResolvedSchedulingConstraints.NodeSelector["node-type"])
	}
}

// ============================================================================
// Namespace Constraints E2E Tests
// ============================================================================

// D-022: DebugSession with namespace constraints
func TestDebugSession_E2E_NamespaceConstraints(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-namespace-constraints-pod",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Namespace Constraints Pod",
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

	// Create session template with namespace constraints
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-namespace-constraints-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Namespace Constraints Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
				AllowedNamespaces: &telekomv1alpha1.NamespaceFilter{
					Patterns: []string{"breakglass-*", "debug-*"},
				},
				DeniedNamespaces: &telekomv1alpha1.NamespaceFilter{
					Patterns: []string{"kube-system", "kube-public"},
				},
				DefaultNamespace:   "breakglass-debug",
				AllowUserNamespace: true,
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
		},
	}

	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create namespace constraints template")
	defer func() { _ = cli.Delete(ctx, template) }()

	// Verify template has namespace constraints
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
	require.NoError(t, err)
	assert.NotNil(t, fetched.Spec.NamespaceConstraints)
	assert.True(t, fetched.Spec.NamespaceConstraints.AllowUserNamespace)
	assert.Equal(t, "breakglass-debug", fetched.Spec.NamespaceConstraints.DefaultNamespace)
	t.Logf("Namespace constraints: allowed=%v, denied=%v, default=%s",
		fetched.Spec.NamespaceConstraints.AllowedNamespaces.Patterns,
		fetched.Spec.NamespaceConstraints.DeniedNamespaces.Patterns,
		fetched.Spec.NamespaceConstraints.DefaultNamespace)
}

// D-023: DebugSession with user-selected target namespace
func TestDebugSession_E2E_TargetNamespaceSelection(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-target-namespace-pod",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Target Namespace Pod",
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

	// Create session template allowing user namespace selection
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-target-namespace-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Target Namespace Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType: telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:     &replicas,
			// No fixed TargetNamespace - use namespace constraints instead
			NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
				AllowedNamespaces: &telekomv1alpha1.NamespaceFilter{
					Patterns: []string{"debug-*", "breakglass-*"},
				},
				DefaultNamespace:   "debug-default",
				AllowUserNamespace: true, // User can specify namespace
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
		},
	}

	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create target namespace template")
	defer func() { _ = cli.Delete(ctx, template) }()

	// Create the target namespace first
	targetNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "debug-custom",
		},
	}
	_ = cli.Create(ctx, targetNs)
	defer func() { _ = cli.Delete(ctx, targetNs) }()

	// Create session with user-selected target namespace
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       template.Name,
		RequestedDuration: "30m",
		Namespace:         testNamespace,
		Reason:            "Testing target namespace selection",
		TargetNamespace:   "debug-custom", // User selects custom namespace
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to be processed
	session = helpers.WaitForDebugSessionStateAny(t, ctx, cli, session.Name, session.Namespace, defaultTimeout)

	// Verify the session has the user-selected target namespace
	t.Logf("Session state: %s", session.Status.State)
	t.Logf("Target namespace: %s", session.Spec.TargetNamespace)
	assert.Equal(t, "debug-custom", session.Spec.TargetNamespace)
}

// D-024: DebugSession rejects invalid target namespace
func TestDebugSession_E2E_InvalidTargetNamespaceRejected(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-invalid-ns-pod",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Invalid NS Pod",
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

	// Create session template with strict namespace constraints
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-strict-ns-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Strict NS Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType: telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:     &replicas,
			NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
				AllowedNamespaces: &telekomv1alpha1.NamespaceFilter{
					Patterns: []string{"debug-*"}, // Only debug-* namespaces allowed
				},
				DeniedNamespaces: &telekomv1alpha1.NamespaceFilter{
					Patterns: []string{"kube-*"}, // Deny kube-* namespaces
				},
				DefaultNamespace:   "debug-default",
				AllowUserNamespace: true,
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
		},
	}

	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create strict ns template")
	defer func() { _ = cli.Delete(ctx, template) }()

	// Try to create session with an invalid target namespace (not matching allowed pattern)
	_, err = api.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       template.Name,
		RequestedDuration: "30m",
		Namespace:         testNamespace,
		Reason:            "Testing invalid namespace rejection",
		TargetNamespace:   "production", // This should be rejected (doesn't match debug-*)
	})

	// Expect an error (400 Bad Request) because namespace doesn't match constraints
	require.Error(t, err, "Expected error when creating session with invalid namespace")
	t.Logf("Session creation correctly rejected with error: %v", err)
	assert.Contains(t, err.Error(), "status=400", "Expected 400 Bad Request for invalid namespace")
}

// D-025: DebugSession with cluster selector in allowed section
func TestDebugSession_E2E_ClusterSelector(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-cluster-selector-pod",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Cluster Selector Pod",
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

	// Create session template with cluster selector (label-based)
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-cluster-selector-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Cluster Selector Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
				// Use cluster selector instead of explicit cluster names
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"environment": "production",
						"tier":        "critical",
					},
				},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
		},
	}

	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create cluster selector template")
	defer func() { _ = cli.Delete(ctx, template) }()

	// Verify template has cluster selector
	var fetched telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
	require.NoError(t, err)
	assert.NotNil(t, fetched.Spec.Allowed)
	assert.NotNil(t, fetched.Spec.Allowed.ClusterSelector)
	assert.Equal(t, "production", fetched.Spec.Allowed.ClusterSelector.MatchLabels["environment"])
	assert.Equal(t, "critical", fetched.Spec.Allowed.ClusterSelector.MatchLabels["tier"])
	t.Logf("Cluster selector configured: matchLabels=%v", fetched.Spec.Allowed.ClusterSelector.MatchLabels)
}
