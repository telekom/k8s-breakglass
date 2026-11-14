// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const debugSessionLabel = "breakglass.telekom.com/debug-session"

// TestDebugSessionRuntimeLabelReservation applies the optional
// config/components/runtime-label-reservation policy and proves that a normal
// user can no longer forge or strip the debug-session label, while the
// controller still creates a working debug Deployment (whose Pods the
// kube-controller-manager creates from the reserved template). Before the
// component is applied and after it is removed, the forged label is accepted.
func TestDebugSessionRuntimeLabelReservation(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	if helpers.GetSpokeAKubeconfig() != "" {
		t.Skip("needs the single-cluster setup, where the ClusterConfig credentials are the kubeconfig this test uses")
	}
	ctx := s.Ctx
	const ns = "breakglass-debug"
	cfg := helpers.GetConfig(t)
	kube := kubernetes.NewForConfigOrDie(cfg)

	// The single-cluster ClusterConfig uses this test's kubeconfig, so this is
	// the user the controller creates debug workloads as.
	review, err := kube.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	require.NoError(t, err)
	controllerUser := review.Status.UserInfo.Username
	require.NotEmpty(t, controllerUser)

	const forgerName = "e2e-label-forger@example.com"
	require.NoError(t, s.CreateResource(&rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("label-forger"), Namespace: ns},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "edit"},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: forgerName}},
	}))
	forgerCfg := rest.CopyConfig(cfg)
	forgerCfg.Impersonate = rest.ImpersonationConfig{UserName: forgerName, Groups: []string{"system:authenticated"}}
	forger, err := client.New(forgerCfg, client.Options{Scheme: s.Client.Scheme()})
	require.NoError(t, err)

	forgedPod := func() *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("forged"), Namespace: ns, Labels: map[string]string{debugSessionLabel: "forged"}},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox:latest", Command: []string{"sleep", "60"},
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To[int64](65532), AllowPrivilegeEscalation: ptr.To(false),
					Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}}}},
		}
	}
	isReserved := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "reserved for the breakglass controller")
	}
	// RBAC for the new RoleBinding can take a moment to apply.
	require.Eventually(t, func() bool { return forger.Create(ctx, forgedPod(), client.DryRunAll) == nil }, time.Minute, time.Second,
		"without the component a pod creator can set the debug-session label")

	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "components", "runtime-label-reservation", "policy.yaml"))
	require.NoError(t, err)
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	var applied []*unstructured.Unstructured
	for {
		obj := &unstructured.Unstructured{}
		err := decoder.Decode(&obj.Object)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if obj.GetKind() == "ValidatingAdmissionPolicy" {
			// What an operator does with the documented kustomize patch.
			variables, _, err := unstructured.NestedSlice(obj.Object, "spec", "variables")
			require.NoError(t, err)
			variables[0].(map[string]any)["expression"] = "[" + strconv.Quote("system:serviceaccount:breakglass-system:breakglass-manager") + ", " + strconv.Quote(controllerUser) + "]"
			require.NoError(t, unstructured.SetNestedSlice(obj.Object, variables, "spec", "variables"))
		}
		require.NoError(t, s.Client.Create(ctx, obj))
		// Registered per object and unconditionally (not via s.Cleanup, which
		// CI skips on failure): a leftover Deny policy would break later tests.
		t.Cleanup(func() { _ = s.Client.Delete(context.Background(), obj) })
		applied = append(applied, obj)
	}
	removed := false
	removeComponent := func() {
		if removed {
			return
		}
		removed = true
		for _, obj := range applied {
			_ = s.Client.Delete(context.Background(), obj)
		}
	}

	require.Eventually(t, func() bool { return isReserved(forger.Create(ctx, forgedPod(), client.DryRunAll)) }, time.Minute, time.Second,
		"with the component a forged debug-session label must be denied")
	plain := forgedPod()
	plain.Labels = map[string]string{"app": "plain"}
	require.NoError(t, forger.Create(ctx, plain, client.DryRunAll), "pods without reserved keys are unaffected")

	// A real debug session: the controller creates the Deployment, the
	// kube-controller-manager creates its Pods.
	requester := helpers.TestUsers.PlatformIdentityRequester
	approver := helpers.TestUsers.DebugSessionApprover
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("label-reservation")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:          "Label reservation",
			Mode:                 breakglassv1alpha1.DebugSessionModeWorkload,
			WorkloadType:         breakglassv1alpha1.DebugWorkloadDeployment,
			TargetNamespace:      ns,
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{DefaultNamespace: ns},
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: label-reservation
spec:
  selector:
    matchLabels:
      label-reservation: {{ .session.name | yamlQuote }}
  template:
    metadata:
      labels:
        label-reservation: {{ .session.name | yamlQuote }}
    spec:
      containers:
      - name: busybox
        image: busybox:latest
        imagePullPolicy: IfNotPresent
        command: ["sleep", "3600"]
        securityContext:
          runAsNonRoot: true
          runAsUser: 65532
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          seccompProfile:
            type: RuntimeDefault
        resources:
          requests:
            memory: 16Mi
`,
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "20m", DefaultDuration: "10m", RetainFor: "10s"},
		},
	}
	require.NoError(t, s.CreateResource(template))
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("label-reservation"), Namespace: s.Namespace},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
			Clusters:    []string{s.Cluster},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Groups: requester.Groups},
			Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Users: []string{approver.Email}},
		},
	}
	require.NoError(t, s.CreateResource(binding))

	var session *breakglassv1alpha1.DebugSession
	require.Eventually(t, func() bool {
		created, err := s.TC.ClientForUser(requester).CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
			TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m", Reason: "label reservation e2e",
		})
		if err != nil {
			return false
		}
		session = created
		return true
	}, helpers.WaitForStateTimeout, time.Second, "binding must become usable")
	s.Cleanup.Add(session)
	t.Cleanup(func() { _ = s.TC.ClientForUser(requester).TerminateDebugSession(context.Background(), t, session.Name) })
	helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForStateTimeout)
	status, err := NewDebugSessionAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, ctx, approver)).ApproveDebugSession(ctx, t, session.Name, "label reservation e2e")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	active := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
	require.Eventually(t, func() bool {
		if s.Client.Get(ctx, client.ObjectKeyFromObject(active), active) != nil {
			return false
		}
		return len(active.Status.AllowedPods) > 0 && active.Status.AllowedPods[0].Ready
	}, helpers.WaitForStateTimeout, time.Second, "the controller-created debug pod must become Ready under the policy")
	debugPod := &corev1.Pod{}
	require.NoError(t, s.Client.Get(ctx, types.NamespacedName{Namespace: active.Status.AllowedPods[0].Namespace, Name: active.Status.AllowedPods[0].Name}, debugPod))
	require.Equal(t, session.Name, debugPod.Labels[debugSessionLabel])

	// Nor may the forger strip the label from the real debug pod to hide it.
	strip := client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"labels":{"`+debugSessionLabel+`":null}}}`))
	require.True(t, isReserved(forger.Patch(ctx, debugPod.DeepCopy(), strip, client.DryRunAll)), "removing the label must be denied")

	// Cleanup under the Deny policy, with a foreign finalizer holding the
	// debug Deployment: the controller switches its delete to Foreground and
	// the garbage collector must still remove the ReplicaSets and Pods.
	rs := &appsv1.ReplicaSet{}
	require.NoError(t, s.Client.Get(ctx, types.NamespacedName{Namespace: debugPod.Namespace, Name: metav1.GetControllerOf(debugPod).Name}, rs))
	deployment := &appsv1.Deployment{}
	require.NoError(t, s.Client.Get(ctx, types.NamespacedName{Namespace: rs.Namespace, Name: metav1.GetControllerOf(rs).Name}, deployment))
	const hold = "e2e.breakglass.telekom.com/hold"
	release := func() error {
		return client.IgnoreNotFound(s.Client.Patch(context.Background(), deployment.DeepCopy(), client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"finalizers":null}}`))))
	}
	t.Cleanup(func() { _ = release() })
	require.NoError(t, s.Client.Patch(ctx, deployment.DeepCopy(), client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"finalizers":["`+hold+`"]}}`))))
	sessionPods := &corev1.PodList{}
	require.NoError(t, s.Client.List(ctx, sessionPods, client.InNamespace(ns), client.MatchingLabels{debugSessionLabel: session.Name}))
	require.NotEmpty(t, sessionPods.Items)
	require.NoError(t, s.TC.ClientForUser(requester).TerminateDebugSession(ctx, t, session.Name))
	require.Eventually(t, func() bool {
		for _, p := range sessionPods.Items {
			live := &corev1.Pod{}
			err := s.Client.Get(ctx, client.ObjectKeyFromObject(&p), live)
			if !apierrors.IsNotFound(err) && (err != nil || live.UID == p.UID) {
				return false
			}
		}
		live := &appsv1.ReplicaSet{}
		err := s.Client.Get(ctx, client.ObjectKeyFromObject(rs), live)
		return apierrors.IsNotFound(err) || (err == nil && live.UID != rs.UID)
	}, helpers.WaitForStateTimeout, time.Second, "the held Deployment's ReplicaSets and Pods must be removed under the policy")
	held := &appsv1.Deployment{}
	require.NoError(t, s.Client.Get(ctx, client.ObjectKeyFromObject(deployment), held))
	require.Equal(t, deployment.UID, held.UID)
	require.NotNil(t, held.DeletionTimestamp, "cleanup deleted the Deployment; the foreign finalizer holds it")
	require.NoError(t, release())
	require.Eventually(t, func() bool {
		live := &appsv1.Deployment{}
		err := s.Client.Get(ctx, client.ObjectKeyFromObject(deployment), live)
		return apierrors.IsNotFound(err) || (err == nil && live.UID != deployment.UID)
	}, helpers.WaitForStateTimeout, time.Second, "the Deployment must be gone once released")

	removeComponent()
	require.Eventually(t, func() bool { return forger.Create(ctx, forgedPod(), client.DryRunAll) == nil }, time.Minute, time.Second,
		"after the component is removed nothing is reserved any more")
}
