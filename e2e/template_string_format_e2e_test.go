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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// ============================================================================
// E2E Tests: templateString format detection and workload creation
// These tests verify that kind: Pod, kind: Deployment, kind: DaemonSet, and
// bare PodSpec formats are correctly handled end-to-end.
// ============================================================================

// TestTemplateStringFormat_E2E_KindPodDaemonSet verifies that a kind: Pod
// templateString is correctly parsed and wrapped into a DaemonSet workload.
func TestTemplateStringFormat_E2E_KindPodDaemonSet(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create DebugPodTemplate with kind: Pod templateString
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-kind-pod-daemonset",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Kind Pod DaemonSet",
			TemplateString: `apiVersion: v1
kind: Pod
metadata:
  labels:
    e2e-test: kind-pod-format
spec:
  automountServiceAccountToken: false
  containers:
    - name: debug
      image: busybox:latest
      command: ["sleep", "infinity"]
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
        requests:
          cpu: "50m"
          memory: "32Mi"
`,
		},
	}

	_ = cli.Delete(ctx, podTemplate)
	defer func() { _ = cli.Delete(ctx, podTemplate) }()
	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err, "Failed to create DebugPodTemplate with kind:Pod templateString")

	// Create DebugSessionTemplate referencing the pod template
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-kind-pod-ds-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Kind Pod → DaemonSet",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDaemonSet,
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
				MaxDuration:     "1h",
				DefaultDuration: "30m",
			},
		},
	}

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() { _ = cli.Delete(ctx, sessionTemplate) }()
	err = cli.Create(ctx, sessionTemplate)
	require.NoError(t, err, "Failed to create DebugSessionTemplate")

	// Create a debug session via API
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		TemplateRef:       sessionTemplate.Name,
		Cluster:           helpers.GetTestClusterName(),
		RequestedDuration: "30m",
		Reason:            "E2E test: kind:Pod format",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	// Wait for session to become active
	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateActive, defaultTimeout)

	// Verify the workload was created as a DaemonSet
	var ds appsv1.DaemonSet
	// ds.Name already starts with "debug-" (e.g., "debug-user-cluster-123"),
	// so we use it directly without adding another "debug-" prefix.
	err = cli.Get(ctx, types.NamespacedName{
		Name:      session.Name,
		Namespace: "breakglass-debug",
	}, &ds)
	require.NoError(t, err, "Expected DaemonSet to be created from kind:Pod templateString")

	// Verify the container was correctly extracted from the Pod manifest
	require.Len(t, ds.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "debug", ds.Spec.Template.Spec.Containers[0].Name)
	assert.Equal(t, "busybox:latest", ds.Spec.Template.Spec.Containers[0].Image)

	// Verify pod-level labels from Pod manifest were merged
	assert.Equal(t, "kind-pod-format", ds.Labels["e2e-test"])
}

// TestTemplateStringFormat_E2E_FullDeploymentManifest verifies that a kind: Deployment
// templateString is used directly as the workload.
func TestTemplateStringFormat_E2E_FullDeploymentManifest(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create DebugSessionTemplate with inline Deployment templateString
	replicas := int32(1)
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-full-deployment",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:  "E2E Full Deployment",
			Mode:         telekomv1alpha1.DebugSessionModeWorkload,
			WorkloadType: telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:     &replicas,
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: will-be-overridden
spec:
  replicas: 5
  selector:
    matchLabels:
      will: be-overridden
  template:
    metadata:
      labels:
        from-template: "true"
    spec:
      automountServiceAccountToken: false
      containers:
        - name: debug-app
          image: busybox:latest
          command: ["sleep", "infinity"]
          resources:
            limits:
              cpu: "100m"
              memory: "64Mi"
`,
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
				MaxDuration:     "1h",
				DefaultDuration: "30m",
			},
		},
	}

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() { _ = cli.Delete(ctx, sessionTemplate) }()
	err := cli.Create(ctx, sessionTemplate)
	require.NoError(t, err, "Failed to create DebugSessionTemplate with Deployment templateString")

	// Create session
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		TemplateRef:       sessionTemplate.Name,
		Cluster:           helpers.GetTestClusterName(),
		RequestedDuration: "30m",
		Reason:            "E2E test: full Deployment manifest",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateActive, defaultTimeout)

	// Verify Deployment was created
	var deploy appsv1.Deployment
	// session.Name already starts with "debug-" prefix, so use it directly.
	err = cli.Get(ctx, types.NamespacedName{
		Name:      session.Name,
		Namespace: "breakglass-debug",
	}, &deploy)
	require.NoError(t, err, "Expected Deployment to be created from kind:Deployment templateString")

	// Name should be overridden by breakglass (not "will-be-overridden")
	assert.Equal(t, session.Name, deploy.Name)

	// Replicas should come from session template override (1), not manifest (5)
	require.NotNil(t, deploy.Spec.Replicas)
	assert.Equal(t, int32(1), *deploy.Spec.Replicas)

	// Container should be from the manifest
	require.Len(t, deploy.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "debug-app", deploy.Spec.Template.Spec.Containers[0].Name)

	// Breakglass labels should be present
	assert.NotEmpty(t, deploy.Labels["breakglass.telekom.com/debug-session"])
}

// TestTemplateStringFormat_E2E_WebhookRejectsUnsupportedKind verifies that the
// admission webhook rejects a templateString with an unsupported kind.
func TestTemplateStringFormat_E2E_WebhookRejectsUnsupportedKind(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-unsupported-kind",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Unsupported Kind",
			TemplateString: `apiVersion: batch/v1
kind: Job
metadata:
  name: test-job
spec:
  template:
    spec:
      containers:
        - name: test
          image: busybox:latest
`,
		},
	}

	_ = cli.Delete(ctx, podTemplate)
	defer func() { _ = cli.Delete(ctx, podTemplate) }()

	err := cli.Create(ctx, podTemplate)
	require.Error(t, err, "Expected webhook to reject unsupported kind Job")
	assert.Contains(t, err.Error(), "unsupported kind")
}

// TestTemplateStringFormat_E2E_WebhookRejectsWrongAPIVersion verifies that the
// admission webhook rejects a templateString with a wrong apiVersion for Pod.
func TestTemplateStringFormat_E2E_WebhookRejectsWrongAPIVersion(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	ctx := context.Background()

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-wrong-api-version",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Wrong API Version",
			TemplateString: `apiVersion: apps/v1
kind: Pod
spec:
  containers:
    - name: test
      image: busybox:latest
`,
		},
	}

	_ = cli.Delete(ctx, podTemplate)
	defer func() { _ = cli.Delete(ctx, podTemplate) }()

	err := cli.Create(ctx, podTemplate)
	require.Error(t, err, "Expected webhook to reject wrong apiVersion for Pod")
	assert.Contains(t, err.Error(), "apiVersion")
}

// TestTemplateStringFormat_E2E_WorkloadTypeMismatchRejected verifies that at runtime,
// a DaemonSet templateString with a Deployment workloadType is rejected.
func TestTemplateStringFormat_E2E_WorkloadTypeMismatchRejected(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create a template where the templateString produces a DaemonSet but workloadType is Deployment
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-workload-mismatch",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:  "E2E Workload Mismatch",
			Mode:         telekomv1alpha1.DebugSessionModeWorkload,
			WorkloadType: telekomv1alpha1.DebugWorkloadDeployment, // Mismatch!
			PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ds
spec:
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: busybox:latest
          command: ["sleep", "infinity"]
`,
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
				MaxDuration:     "1h",
				DefaultDuration: "30m",
			},
		},
	}

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() { _ = cli.Delete(ctx, sessionTemplate) }()
	err := cli.Create(ctx, sessionTemplate)
	require.NoError(t, err, "Template should be created (mismatch is a warning, not error)")

	// Create a session - the mismatch should cause the reconciler to fail
	session, err := api.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
		TemplateRef:       sessionTemplate.Name,
		Cluster:           helpers.GetTestClusterName(),
		RequestedDuration: "30m",
		Reason:            "E2E test: workload type mismatch",
	})
	if err != nil {
		// If API rejects it, that's also acceptable
		return
	}
	defer func() { _ = cli.Delete(ctx, session) }()

	// If created, the session should fail during reconciliation
	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateFailed, defaultTimeout)
	assert.Contains(t, session.Status.Message, "must match",
		"Expected failure message about workload type mismatch")
}

// TestTemplateStringFormat_E2E_BareSpecBackwardCompatible verifies that the
// original bare PodSpec format still works correctly end-to-end.
func TestTemplateStringFormat_E2E_BareSpecBackwardCompatible(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create template with bare PodSpec (original format)
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-bare-spec",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:  "E2E Bare Spec",
			Mode:         telekomv1alpha1.DebugSessionModeWorkload,
			WorkloadType: telekomv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
    command: ["sleep", "infinity"]
    resources:
      limits:
        cpu: "100m"
        memory: "64Mi"
`,
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
				MaxDuration:     "1h",
				DefaultDuration: "30m",
			},
		},
	}

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() { _ = cli.Delete(ctx, sessionTemplate) }()
	err := cli.Create(ctx, sessionTemplate)
	require.NoError(t, err, "Failed to create DebugSessionTemplate with bare PodSpec")

	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		TemplateRef:       sessionTemplate.Name,
		Cluster:           helpers.GetTestClusterName(),
		RequestedDuration: "30m",
		Reason:            "E2E test: bare PodSpec backward compat",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateActive, defaultTimeout)

	// Verify DaemonSet was created
	var ds appsv1.DaemonSet
	// session.Name already starts with "debug-" prefix, so use it directly.
	err = cli.Get(ctx, types.NamespacedName{
		Name:      session.Name,
		Namespace: "breakglass-debug",
	}, &ds)
	require.NoError(t, err, "Expected DaemonSet to be created from bare PodSpec")
	require.Len(t, ds.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "debug", ds.Spec.Template.Spec.Containers[0].Name)
}

// TestTemplateStringFormat_E2E_FullDaemonSetManifest verifies that a kind: DaemonSet
// templateString is used as the workload and overrides are applied.
func TestTemplateStringFormat_E2E_FullDaemonSetManifest(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create DebugSessionTemplate with inline DaemonSet templateString
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-full-daemonset",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:  "E2E Full DaemonSet",
			Mode:         telekomv1alpha1.DebugSessionModeWorkload,
			WorkloadType: telekomv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: template-ds
  labels:
    from-template: "true"
spec:
  selector:
    matchLabels:
      will: be-overridden
  template:
    metadata:
      labels:
        from-template: "true"
    spec:
      automountServiceAccountToken: false
      containers:
        - name: debug-ds
          image: busybox:latest
          command: ["sleep", "infinity"]
          resources:
            limits:
              cpu: "100m"
              memory: "64Mi"
            requests:
              cpu: "50m"
              memory: "32Mi"
`,
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
				MaxDuration:     "1h",
				DefaultDuration: "30m",
			},
		},
	}

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() { _ = cli.Delete(ctx, sessionTemplate) }()
	err := cli.Create(ctx, sessionTemplate)
	require.NoError(t, err, "Failed to create DebugSessionTemplate with DaemonSet templateString")

	// Create session
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		TemplateRef:       sessionTemplate.Name,
		Cluster:           helpers.GetTestClusterName(),
		RequestedDuration: "30m",
		Reason:            "E2E test: full DaemonSet manifest",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateActive, defaultTimeout)

	// Verify DaemonSet was created
	var ds appsv1.DaemonSet
	// session.Name already starts with "debug-" prefix, so use it directly.
	err = cli.Get(ctx, types.NamespacedName{
		Name:      session.Name,
		Namespace: "breakglass-debug",
	}, &ds)
	require.NoError(t, err, "Expected DaemonSet to be created from kind:DaemonSet templateString")

	// Name should be overridden by breakglass
	assert.Equal(t, session.Name, ds.Name)

	// Container should be from the manifest
	require.Len(t, ds.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "debug-ds", ds.Spec.Template.Spec.Containers[0].Name)
	assert.Equal(t, "busybox:latest", ds.Spec.Template.Spec.Containers[0].Image)

	// Breakglass labels should be present (merged with template labels)
	assert.NotEmpty(t, ds.Labels["breakglass.telekom.com/debug-session"])
}

// TestTemplateStringFormat_E2E_KindPodWithOverrides verifies that a kind: Pod
// templateString correctly applies scheduling and toleration overrides from
// the DebugSessionTemplate.
func TestTemplateStringFormat_E2E_KindPodWithOverrides(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()

	// Create DebugPodTemplate with kind: Pod
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-pod-overrides",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Pod With Overrides",
			TemplateString: `apiVersion: v1
kind: Pod
spec:
  automountServiceAccountToken: false
  containers:
    - name: debug
      image: busybox:latest
      command: ["sleep", "infinity"]
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
        requests:
          cpu: "50m"
          memory: "32Mi"
`,
		},
	}

	_ = cli.Delete(ctx, podTemplate)
	defer func() { _ = cli.Delete(ctx, podTemplate) }()
	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err, "Failed to create DebugPodTemplate")

	// Create DebugSessionTemplate with toleration overrides
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-pod-overrides-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Pod Overrides",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDaemonSet,
			TargetNamespace: "breakglass-debug",
			AdditionalTolerations: []corev1.Toleration{
				{
					Key:      "e2e-test",
					Operator: corev1.TolerationOpEqual,
					Value:    "pod-overrides",
					Effect:   corev1.TaintEffectNoSchedule,
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

	_ = cli.Delete(ctx, sessionTemplate)
	defer func() { _ = cli.Delete(ctx, sessionTemplate) }()
	err = cli.Create(ctx, sessionTemplate)
	require.NoError(t, err, "Failed to create DebugSessionTemplate with overrides")

	// Create session
	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		TemplateRef:       sessionTemplate.Name,
		Cluster:           helpers.GetTestClusterName(),
		RequestedDuration: "30m",
		Reason:            "E2E test: kind:Pod with overrides",
	})
	defer func() { _ = cli.Delete(ctx, session) }()

	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateActive, defaultTimeout)

	// Verify the DaemonSet was created
	var ds appsv1.DaemonSet
	// session.Name already starts with "debug-" prefix, so use it directly.
	err = cli.Get(ctx, types.NamespacedName{
		Name:      session.Name,
		Namespace: "breakglass-debug",
	}, &ds)
	require.NoError(t, err, "Expected DaemonSet to be created")

	// Verify the container is from the Pod template
	require.Len(t, ds.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "debug", ds.Spec.Template.Spec.Containers[0].Name)

	// Verify the toleration override was applied
	found := false
	for _, tol := range ds.Spec.Template.Spec.Tolerations {
		if tol.Key == "e2e-test" && tol.Value == "pod-overrides" {
			found = true
			break
		}
	}
	assert.True(t, found,
		"Expected toleration from DebugSessionTemplate.AdditionalTolerations to be applied")
}
