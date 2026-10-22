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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

const roRootfsNamespace = "e2e-ro-rootfs"

// requireReadOnlyRootfsExpression mirrors common "require read-only root
// filesystem" admission policies. It also covers the ephemeralcontainers
// subresource, so it is stricter than policies that only match pods.
const requireReadOnlyRootfsExpression = `(object.spec.containers + object.spec.?initContainers.orValue([]) + ` +
	`object.spec.?ephemeralContainers.orValue([])).all(c, has(c.securityContext) && ` +
	`has(c.securityContext.readOnlyRootFilesystem) && c.securityContext.readOnlyRootFilesystem == true)`

// Template securityContext lets ephemeral and pod-copy debug containers pass
// a read-only root filesystem admission policy without a policy exception.
func TestDebugSession_E2E_KubectlDebugReadOnlyRootFilesystemAdmission(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	cli := setupClient(t)
	api := setupAPIClient(t)
	ctx := context.Background()
	readOnly := true
	writable := false

	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   roRootfsNamespace,
		Labels: map[string]string{"e2e-require-ro-rootfs": "true"},
	}}
	_ = cli.Delete(ctx, namespace)
	require.NoError(t, helpers.WaitForResourceDeleted(ctx, cli, client.ObjectKeyFromObject(namespace), &corev1.Namespace{}, defaultTimeout))
	require.NoError(t, cli.Create(ctx, namespace))
	defer func() { _ = cli.Delete(ctx, namespace) }()

	failurePolicy := admissionregistrationv1.Fail
	policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-require-ro-rootfs"},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &failurePolicy,
			MatchConstraints: &admissionregistrationv1.MatchResources{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: namespace.Labels},
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionregistrationv1.RuleWithOperations{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods", "pods/ephemeralcontainers"},
						},
					},
				}},
			},
			Validations: []admissionregistrationv1.Validation{{
				Expression: requireReadOnlyRootfsExpression,
				Message:    "Root filesystem must be read-only.",
			}},
		},
	}
	binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: policy.Name},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        policy.Name,
			ValidationActions: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny},
		},
	}
	_ = cli.Delete(ctx, binding)
	_ = cli.Delete(ctx, policy)
	require.NoError(t, cli.Create(ctx, policy))
	defer func() { _ = cli.Delete(ctx, policy) }()
	require.NoError(t, cli.Create(ctx, binding))
	defer func() { _ = cli.Delete(ctx, binding) }()

	// Negative control: the policy must actually deny a writable root
	// filesystem before the positive cases mean anything.
	require.Eventually(t, func() bool {
		probe := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "e2e-ro-rootfs-probe", Namespace: roRootfsNamespace},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "busybox:latest"}}},
		}
		err := cli.Create(ctx, probe, client.DryRunAll)
		return err != nil && strings.Contains(err.Error(), "Root filesystem must be read-only")
	}, defaultTimeout, defaultInterval, "admission policy must deny a writable root filesystem")

	sourcePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-ro-rootfs-source", Namespace: roRootfsNamespace},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:            "app",
			Image:           "busybox:latest",
			Command:         []string{"sleep", "infinity"},
			SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &readOnly},
		}}},
	}
	require.NoError(t, cli.Create(ctx, sourcePod))
	require.NoError(t, helpers.WaitForPodReady(ctx, cli, sourcePod.Namespace, sourcePod.Name, defaultTimeout))

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-ro-rootfs-kubectl-debug"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "E2E Read-Only Rootfs kubectl debug",
			Mode:            breakglassv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: roRootfsNamespace,
			KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
					Enabled:           true,
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{roRootfsNamespace}},
					AllowedImages:     []string{"busybox:*"},
					SecurityContext:   &corev1.SecurityContext{ReadOnlyRootFilesystem: &readOnly},
				},
				PodCopy: &breakglassv1alpha1.PodCopyConfig{
					Enabled:         true,
					TargetNamespace: roRootfsNamespace,
					TTL:             "1h",
					SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &readOnly},
				},
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &breakglassv1alpha1.AutoApproveConfig{Clusters: []string{"*"}},
			},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "1h", DefaultDuration: "30m"},
		},
	}
	_ = cli.Delete(ctx, template)
	require.NoError(t, cli.Create(ctx, template))
	defer func() { _ = cli.Delete(ctx, template) }()

	session := api.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		Cluster:           "tenant-a",
		TemplateRef:       template.Name,
		RequestedDuration: "30m",
		Reason:            "Testing read-only root filesystem admission",
	})
	defer func() { _ = cli.Delete(ctx, session) }()
	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateActive, defaultTimeout)

	// Copy before injection: kubelet updates to ephemeral-container status change
	// the source resourceVersion, which the pod-copy authorization fence rejects.
	copyResult, err := api.CreatePodCopy(ctx, t, session.Name, helpers.PodCopyRequest{
		Namespace:  roRootfsNamespace,
		PodName:    sourcePod.Name,
		DebugImage: "busybox:latest",
	})
	require.NoError(t, err, "admission must accept the pod copy with the template security context")
	copyPod := &corev1.Pod{}
	require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: copyResult.CopyNamespace, Name: copyResult.CopyName}, copyPod))
	defer func() { _ = cli.Delete(ctx, copyPod) }()
	require.Len(t, copyPod.Spec.Containers, 2)
	for _, container := range copyPod.Spec.Containers {
		require.NotNil(t, container.SecurityContext, container.Name)
		require.True(t, *container.SecurityContext.ReadOnlyRootFilesystem, container.Name)
	}
	require.NoError(t, helpers.WaitForPodReady(ctx, cli, copyPod.Namespace, copyPod.Name, defaultTimeout))

	// The client asks for a writable root filesystem; the template wins.
	// requireNonRoot defaults to true, so the request runs as nobody.
	nobody, nonRoot := int64(65534), true
	require.NoError(t, api.InjectEphemeralContainer(ctx, t, session.Name, helpers.EphemeralContainerRequest{
		Namespace:     roRootfsNamespace,
		PodName:       sourcePod.Name,
		ContainerName: "debugger",
		Image:         "busybox:latest",
		Command:       []string{"sh"},
		SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem: &writable,
			RunAsNonRoot:           &nonRoot,
			RunAsUser:              &nobody,
		},
	}), "admission must accept the ephemeral container with the template security context")
	require.NoError(t, cli.Get(ctx, client.ObjectKeyFromObject(sourcePod), sourcePod))
	require.Len(t, sourcePod.Spec.EphemeralContainers, 1)
	require.NotNil(t, sourcePod.Spec.EphemeralContainers[0].SecurityContext)
	require.True(t, *sourcePod.Spec.EphemeralContainers[0].SecurityContext.ReadOnlyRootFilesystem)

	require.NoError(t, api.TerminateDebugSession(ctx, t, session.Name))
}
