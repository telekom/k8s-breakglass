// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"
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

	run := func(t *testing.T, wantMessage string) client.ObjectKey {
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
			// A definitively rejected create leaves an error-only status
			// without identity; only creation evidence is a residual.
			for _, status := range current.Status.AuxiliaryResourceStatuses {
				if !status.Deleted && (status.UID != "" || status.CreateOperationID != "") {
					return false
				}
			}
			condition := current.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
			complete := current.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupComplete))
			return (condition == nil || condition.Status != metav1.ConditionTrue) && complete != nil && complete.Status == metav1.ConditionTrue
		}, helpers.WaitForStateTimeout, time.Second, "cleanup must complete and be marked CleanupComplete")

		// No retry loop: the terminal session stays untouched. Each retry used
		// to patch status and emit debug_session.cleanup_failed every ~5s.
		settled := &breakglassv1alpha1.DebugSession{}
		require.NoError(t, s.Client.Get(ctx, key, settled))
		time.Sleep(15 * time.Second)
		after := &breakglassv1alpha1.DebugSession{}
		require.NoError(t, s.Client.Get(ctx, key, after))
		assert.Equal(t, settled.ResourceVersion, after.ResourceVersion, "a cleanly failed session must not be reconciled again")
		assert.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, after.Status.State)
		return key
	}

	var failedKey client.ObjectKey
	t.Run("default fails in preflight", func(t *testing.T) {
		failedKey = run(t, `requires policies.kyverno.io/v1 PolicyException, which target cluster`)
	})

	t.Run("cleanup acknowledgement needs the dedicated verb", func(t *testing.T) {
		require.NotEmpty(t, failedKey.Name)
		testCleanupAcknowledgementAuthorization(t, s, failedKey)
	})

	t.Run("opt-out fails at create without residuals", func(t *testing.T) {
		setControllerEnv(t, s, unservedKindOptOutEnv, "true")
		run(t, `no matches for kind "PolicyException"`)
	})
}

// setControllerEnv sets an environment variable on the breakglass controller
// deployment and waits for the rollout and the API.
func setControllerEnv(t *testing.T, s *helpers.TestSetup, name, value string) {
	t.Helper()
	updateController(t, s, func(d *appsv1.Deployment) {
		c := &d.Spec.Template.Spec.Containers[0]
		env := make([]corev1.EnvVar, 0, len(c.Env)+1)
		for _, e := range c.Env {
			if e.Name != name {
				env = append(env, e)
			}
		}
		c.Env = append(env, corev1.EnvVar{Name: name, Value: value})
	})
}

// updateController changes the breakglass controller deployment and waits for
// the rollout and the API. Restoration of the original replicas and container
// is registered before the mutation, so a failed wait cannot leak
// the change into later tests.
func updateController(t *testing.T, s *helpers.TestSetup, mutate func(*appsv1.Deployment)) {
	t.Helper()
	ctx := s.Ctx
	// The controller runs in its own namespace, independent of the test
	// namespace (E2E_NAMESPACE may be "default").
	var list appsv1.DeploymentList
	require.NoError(t, s.Client.List(ctx, &list, client.MatchingLabels{"app": "breakglass"}))
	require.Len(t, list.Items, 1, "expected exactly one breakglass controller deployment in the cluster")
	key := client.ObjectKeyFromObject(&list.Items[0])
	originalContainer := *list.Items[0].Spec.Template.Spec.Containers[0].DeepCopy()
	originalReplicas := list.Items[0].Spec.Replicas

	apply := func(ctx context.Context, change func(*appsv1.Deployment)) {
		require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var current appsv1.Deployment
			if err := s.Client.Get(ctx, key, &current); err != nil {
				return err
			}
			change(&current)
			return s.Client.Update(ctx, &current)
		}))
		require.NoError(t, helpers.WaitForDeploymentReady(ctx, s.Client, key.Namespace, key.Name, 3*time.Minute))
		// A Ready rollout can still have terminating old pods, and the shared
		// API port-forward may stay attached to one of them; the next test
		// then reads EOF. Wait until only updated pods remain and the API
		// answers several times in a row through the (re)connected forward.
		require.Eventually(t, func() bool {
			var deployment appsv1.Deployment
			if s.Client.Get(ctx, key, &deployment) != nil {
				return false
			}
			var pods corev1.PodList
			if s.Client.List(ctx, &pods, client.InNamespace(key.Namespace), client.MatchingLabels(deployment.Spec.Selector.MatchLabels)) != nil {
				return false
			}
			replicas := ptr.Deref(deployment.Spec.Replicas, 1)
			return int32(len(pods.Items)) == replicas && deployment.Status.Replicas == replicas && deployment.Status.ReadyReplicas == replicas
		}, 3*time.Minute, time.Second, "old controller pods must terminate")
		api := helpers.NewAPIClient()
		healthy := 0
		require.Eventually(t, func() bool {
			if api.HealthCheck(ctx) != nil {
				healthy = 0
				return false
			}
			healthy++
			return healthy >= 5
		}, 2*time.Minute, time.Second, "API must answer consistently after the controller restart")
	}

	t.Cleanup(func() {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		apply(restoreCtx, func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0] = originalContainer
			d.Spec.Replicas = originalReplicas
		})
	})
	apply(ctx, mutate)
}

// testCleanupAcknowledgementAuthorization proves through the real API server
// and admission webhook that a user who may update DebugSessions cannot
// acknowledge cleanup without create on DebugSessionCleanupAcknowledgements,
// and that acknowledgedBy must name the creating user.
func testCleanupAcknowledgementAuthorization(t *testing.T, s *helpers.TestSetup, key client.ObjectKey) {
	ctx := s.Ctx
	suffix := helpers.GenerateUniqueName("ack")
	requester, operator := "e2e-requester-"+suffix, "e2e-operator-"+suffix
	update := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: suffix + "-update"}, Rules: []rbacv1.PolicyRule{{
		APIGroups: []string{breakglassv1alpha1.GroupVersion.Group}, Resources: []string{"debugsessions"}, Verbs: []string{"get", "update", "patch"},
	}}}
	acknowledge := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: suffix + "-ack"}, Rules: []rbacv1.PolicyRule{{
		APIGroups: []string{breakglassv1alpha1.GroupVersion.Group}, Resources: []string{"debugsessioncleanupacknowledgements"}, Verbs: []string{"create"},
	}}}
	bind := func(name, role string, users ...string) *rbacv1.ClusterRoleBinding {
		binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role}}
		for _, user := range users {
			binding.Subjects = append(binding.Subjects, rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: user})
		}
		return binding
	}
	for _, obj := range []client.Object{update, acknowledge, bind(suffix+"-update", update.Name, requester, operator), bind(suffix+"-ack", acknowledge.Name, operator)} {
		require.NoError(t, s.CreateResource(obj))
	}
	as := func(user string) client.Client {
		cfg, err := clientcmd.BuildConfigFromFlags("", helpers.GetKubeconfig())
		require.NoError(t, err)
		cfg.Impersonate.UserName = user
		cfg.Impersonate.Groups = []string{"system:authenticated"}
		c, err := client.New(cfg, client.Options{Scheme: s.Client.Scheme()})
		require.NoError(t, err)
		return c
	}
	session := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, s.Client.Get(ctx, key, session))
	// The session's requester, by their recorded username, may create
	// acknowledgements too: four-eyes must reject them.
	sessionRequester := session.Spec.RequestedBy
	require.NotEmpty(t, sessionRequester)
	require.NoError(t, s.CreateResource(bind(suffix+"-ack-requester", acknowledge.Name, sessionRequester)))
	ack := func(name, by string) *breakglassv1alpha1.DebugSessionCleanupAcknowledgement {
		return &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{
			ObjectMeta: metav1.ObjectMeta{Name: suffix + "-" + name, Namespace: key.Namespace},
			Spec: breakglassv1alpha1.DebugSessionCleanupAcknowledgementSpec{
				SessionName: key.Name, SessionUID: string(session.UID), AcknowledgedBy: by,
				Identities: []breakglassv1alpha1.CleanupAcknowledgedIdentity{{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "breakglass-debug", Name: "none", UID: "none"}},
			},
		}
	}
	// RBAC propagation is eventually consistent; wait until the operator passes.
	require.Eventually(t, func() bool {
		obj := ack("operator", operator)
		if err := as(operator).Create(ctx, obj); err != nil {
			t.Logf("operator create: %v", err)
			return false
		}
		s.Cleanup.Add(obj)
		return true
	}, time.Minute, 2*time.Second, "an operator with create on the resource may acknowledge")

	err := as(requester).Create(ctx, ack("requester", requester))
	require.Error(t, err, "update on debugsessions alone must not allow acknowledgement")
	assert.True(t, apierrors.IsForbidden(err), "RBAC must deny the requester, got %v", err)

	err = as(operator).Create(ctx, ack("forged", requester))
	require.Error(t, err, "acknowledgedBy must name the creating user")
	assert.True(t, apierrors.IsInvalid(err), "the admission policy rejects a forged actor as Invalid, got %v", err)

	// Four-eyes runs before any cleanup check: the requester's own
	// acknowledgement is rejected although the API server admitted it.
	require.Eventually(t, func() bool {
		obj := ack("by-requester", sessionRequester)
		if err := as(sessionRequester).Create(ctx, obj); err != nil {
			t.Logf("requester create: %v", err)
			return false
		}
		s.Cleanup.Add(obj)
		return true
	}, time.Minute, 2*time.Second, "the requester holds create on the resource")
	require.Eventually(t, func() bool {
		processed := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
		if s.Client.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: suffix + "-by-requester"}, processed) != nil {
			return false
		}
		return processed.Status.Phase == breakglassv1alpha1.CleanupAcknowledgementRejected &&
			strings.Contains(processed.Status.Message, "four-eyes") && strings.Contains(processed.Status.Message, sessionRequester)
	}, helpers.WaitForStateTimeout, time.Second, "the requester's own acknowledgement must be rejected by four-eyes")

	// The controller records the outcome on the acknowledgement. The session
	// is not CleanupFailed, so the acknowledgement is rejected and retires
	// nothing.
	require.Eventually(t, func() bool {
		processed := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
		if s.Client.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: suffix + "-operator"}, processed) != nil {
			return false
		}
		return processed.Status.Phase == breakglassv1alpha1.CleanupAcknowledgementRejected &&
			strings.Contains(processed.Status.Message, "not failing")
	}, helpers.WaitForStateTimeout, time.Second, "the acknowledgement must be processed")
}
