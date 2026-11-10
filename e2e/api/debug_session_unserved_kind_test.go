// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const unservedKindOptOutEnv = "BREAKGLASS_DISABLE_DEBUG_SESSION_UNSERVED_KIND_HANDLING"

// TestDebugSessionUnservedAuxiliaryKind covers #1663: a template that needs a
// Kyverno PolicyException targets a cluster without the Kyverno CRDs. The
// session must fail cleanly, cleanup must complete, and the controller must
// not keep retrying (and auditing) cleanup afterwards.
func TestDebugSessionUnservedAuxiliaryKind(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	_, err := s.Client.RESTMapper().RESTMapping(schema.GroupKind{Group: "policies.kyverno.io", Kind: "PolicyException"})
	require.True(t, meta.IsNoMatchError(err), "the e2e target must not serve PolicyException; got %v", err)

	requester := helpers.TestUsers.PlatformIdentityRequester
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("unserved-kind")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Unserved PolicyException",
			Mode:            breakglassv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: "breakglass-debug",
			KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, AllowedImages: []string{"busybox:*"}, RequireNonRoot: true},
			},
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: ptr.To(true)},
			Allowed:              &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{s.Cluster}, Groups: requester.Groups},
			Approvers:            &breakglassv1alpha1.DebugSessionApprovers{AutoApproveFor: &breakglassv1alpha1.AutoApproveConfig{Clusters: []string{s.Cluster}}},
			Constraints:          &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "20m", DefaultDuration: "10m"},
			AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{
				Name: "policy-exception", Category: "policy-exceptions", CreateBefore: ptr.To(true), DeleteAfter: ptr.To(true),
				TemplateString: `apiVersion: policies.kyverno.io/v1
kind: PolicyException
metadata:
  name: {{ .session.name }}
spec:
  exceptions: []
  match:
    any: []
`,
			}},
			RequiredAuxiliaryResourceCategories: []string{"policy-exceptions"},
		},
	}
	require.NoError(t, s.CreateResource(template))

	run := func(t *testing.T, wantMessage string) {
		t.Helper()
		api := s.TC.ClientForUser(requester)
		var session *breakglassv1alpha1.DebugSession
		require.Eventually(t, func() bool {
			created, err := api.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
				TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m", Reason: "unserved auxiliary kind regression",
			})
			if err != nil {
				t.Logf("create debug session: %v", err)
				return false
			}
			session = created
			return true
		}, helpers.WaitForStateTimeout, 2*time.Second)
		s.Cleanup.Add(session)

		failed := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStateFailed, helpers.WaitForStateTimeout)
		assert.Contains(t, failed.Status.Message, wantMessage)

		// Cleanup must complete: no residual inventory and no failed condition.
		key := client.ObjectKeyFromObject(failed)
		require.Eventually(t, func() bool {
			current := &breakglassv1alpha1.DebugSession{}
			if s.Client.Get(ctx, key, current) != nil {
				return false
			}
			for _, status := range current.Status.AuxiliaryResourceStatuses {
				if !status.Deleted {
					return false
				}
			}
			condition := current.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
			return condition == nil || condition.Status != metav1.ConditionTrue
		}, helpers.WaitForStateTimeout, time.Second, "cleanup must complete")

		// No retry loop: the terminal session stays untouched. Each retry used
		// to patch status and emit debug_session.cleanup_failed every ~5s.
		settled := &breakglassv1alpha1.DebugSession{}
		require.NoError(t, s.Client.Get(ctx, key, settled))
		time.Sleep(15 * time.Second)
		after := &breakglassv1alpha1.DebugSession{}
		require.NoError(t, s.Client.Get(ctx, key, after))
		assert.Equal(t, settled.ResourceVersion, after.ResourceVersion, "a cleanly failed session must not be reconciled again")
		assert.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, after.Status.State)
	}

	t.Run("default fails in preflight", func(t *testing.T) {
		run(t, `requires policies.kyverno.io/v1 PolicyException, which target cluster`)
	})

	t.Run("opt-out fails at create without residuals", func(t *testing.T) {
		restore := setControllerEnv(t, s, unservedKindOptOutEnv, "true")
		t.Cleanup(restore)
		run(t, `no matches for kind "PolicyException"`)
	})
}

// setControllerEnv sets an environment variable on the breakglass controller
// deployment, waits for the rollout and the API, and returns a restore func.
func setControllerEnv(t *testing.T, s *helpers.TestSetup, name, value string) func() {
	t.Helper()
	ctx := s.Ctx
	var list appsv1.DeploymentList
	require.NoError(t, s.Client.List(ctx, &list, client.InNamespace(s.Namespace), client.MatchingLabels{"app": "breakglass"}))
	require.Len(t, list.Items, 1, "expected exactly one breakglass controller deployment")
	key := client.ObjectKeyFromObject(&list.Items[0])
	original := list.Items[0].Spec.Template.Spec.Containers[0].Env

	apply := func(ctx context.Context, env []corev1.EnvVar) {
		require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var current appsv1.Deployment
			if err := s.Client.Get(ctx, key, &current); err != nil {
				return err
			}
			current.Spec.Template.Spec.Containers[0].Env = env
			return s.Client.Update(ctx, &current)
		}))
		require.NoError(t, helpers.WaitForDeploymentReady(ctx, s.Client, key.Namespace, key.Name, 3*time.Minute))
		require.NoError(t, helpers.NewAPIClient().WaitForAPIReady(ctx, 2*time.Minute))
	}

	env := make([]corev1.EnvVar, 0, len(original)+1)
	for _, e := range original {
		if e.Name != name {
			env = append(env, e)
		}
	}
	apply(ctx, append(env, corev1.EnvVar{Name: name, Value: value}))
	return func() {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		apply(restoreCtx, original)
	}
}
