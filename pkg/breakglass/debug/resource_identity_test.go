// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestDeleteTrackedResourceIdentityAndLegacyRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, recorded, live, recovery string
		wantError, deleted             bool
	}{
		{"original", "original", "original", "", false, true},
		{"replacement", "original", "replacement", "", false, false},
		{"legacy missing", "", "", "", false, true},
		{"legacy existing requires operator", "", "original", "", true, false},
		{"legacy approved", "", "original", `{"v1/Pod/ns/pod":"original"}`, false, true},
		{"legacy replaced after inspection", "", "replacement", `{"v1/Pod/ns/pod":"original"}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: types.UID(tc.live)}}
			builder := fake.NewClientBuilder().WithScheme(testScheme())
			if tc.live != "" {
				builder.WithObjects(pod)
			}
			target := builder.Build()
			ref := pod.DeepCopy()
			ref.UID = types.UID(tc.recorded)
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{LegacyCleanupUIDsAnnotation: tc.recovery}}}
			err := deleteTrackedResource(ctx, target, session, ref)
			if tc.wantError {
				require.ErrorContains(t, err, "operator")
			} else {
				require.NoError(t, err)
			}
			err = target.Get(ctx, client.ObjectKeyFromObject(pod), &corev1.Pod{})
			require.Equal(t, tc.deleted, apierrors.IsNotFound(err))
		})
	}
}

func TestDeleteTrackedResourceUsesUIDPrecondition(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "original"}}
	target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(pod).WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			options := &client.DeleteOptions{}
			for _, opt := range opts {
				opt.ApplyToDelete(options)
			}
			require.NotNil(t, options.Preconditions)
			require.Equal(t, types.UID("original"), *options.Preconditions.UID)
			// Simulate replacement between the read and deletion: the API's UID
			// precondition must fail, not delete the new instance.
			return apierrors.NewConflict(corev1.Resource("pods"), obj.GetName(), nil)
		},
	}).Build()
	require.Error(t, deleteTrackedResource(context.Background(), target, nil, pod))
	require.NoError(t, target.Get(context.Background(), client.ObjectKeyFromObject(pod), &corev1.Pod{}))
}

func TestLifecycleCleanupPathsPreserveReplacement(t *testing.T) {
	for _, kind := range []string{"deployed", "pod-template", "auxiliary", "copied"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "replacement"}}
			target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(pod).Build()
			ds := newTestDebugSession("session", "template", "cluster", "user@example.com")
			ds.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "v1", Kind: "Pod", Namespace: "ns", Name: "pod", UID: "original", Source: "debug-pod"}}
			ctrl := &DebugSessionController{log: zap.NewNop().Sugar()}
			switch kind {
			case "deployed":
				require.NoError(t, ctrl.cleanupDeployedResources(ctx, ds, target, false, false))
				require.Empty(t, ds.Status.DeployedResources)
			case "pod-template":
				ds.Status.PodTemplateResourceStatuses = []breakglassv1alpha1.PodTemplateResourceStatus{{APIVersion: "v1", Kind: "Pod", Namespace: "ns", ResourceName: "pod", UID: "original", Created: true}}
				require.Error(t, ctrl.cleanupPodTemplateResources(ctx, ds, target))
			case "auxiliary":
				m := NewAuxiliaryResourceManager(zap.NewNop().Sugar(), target)
				require.NoError(t, m.deleteResource(ctx, target, breakglassv1alpha1.AuxiliaryResourceStatus{APIVersion: "v1", Kind: "Pod", Namespace: "ns", ResourceName: "pod", UID: "original"}, ds))
			case "copied":
				ds.Status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{CopiedPods: []breakglassv1alpha1.CopiedPodRef{{CopyName: "pod", CopyNamespace: "ns", CopyUID: "original"}}}
				hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(ds).WithStatusSubresource(ds).Build()
				h := NewKubectlDebugHandler(hub, &mockClientProvider{clients: map[string]client.Client{"cluster": target}})
				require.NoError(t, h.CleanupKubectlDebugResources(ctx, ds))
			}
			live := &corev1.Pod{}
			require.NoError(t, target.Get(ctx, client.ObjectKeyFromObject(pod), live))
			require.Equal(t, types.UID("replacement"), live.UID)
		})
	}
}

func TestTrackedWorkloadPodMembership(t *testing.T) {
	controller := true
	template := corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "debug", Image: "debug:v1"}}}}
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "deployment", Namespace: "ns", UID: "deployment-uid"}, Spec: appsv1.DeploymentSpec{Template: template}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "ns", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: deployment.Name, UID: deployment.UID, Controller: &controller}}}, Spec: appsv1.ReplicaSetSpec{Template: template}}
	daemon := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "daemon", Namespace: "ns", UID: "daemon-uid"}, Spec: appsv1.DaemonSetSpec{Template: template}}
	target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(deployment, rs, daemon).Build()
	for _, tc := range []struct {
		name, kind, refName, refUID, ownerKind, ownerName, ownerUID string
		controller, modified, want                                  bool
	}{
		{"direct", "Pod", "pod", "pod-uid", "", "", "", false, false, true},
		{"daemon", "DaemonSet", "daemon", "daemon-uid", "DaemonSet", "daemon", "daemon-uid", true, false, true},
		{"deployment", "Deployment", "deployment", "deployment-uid", "ReplicaSet", "rs", "rs-uid", true, false, true},
		{"label only", "DaemonSet", "daemon", "daemon-uid", "", "", "", false, false, false},
		{"noncontroller forgery", "DaemonSet", "daemon", "daemon-uid", "DaemonSet", "daemon", "daemon-uid", false, false, false},
		{"controller forgery unrelated spec", "DaemonSet", "daemon", "daemon-uid", "DaemonSet", "daemon", "daemon-uid", true, true, false},
		{"replaced controller", "DaemonSet", "daemon", "old-uid", "DaemonSet", "daemon", "old-uid", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid"}, Spec: *template.Spec.DeepCopy()}
			if tc.ownerKind != "" {
				pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: tc.ownerKind, Name: tc.ownerName, UID: types.UID(tc.ownerUID), Controller: ptr.To(tc.controller)}}
			}
			if tc.modified {
				pod.Spec.Containers[0].Image = "database:production"
			}
			ds := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "apps/v1", Kind: tc.kind, Name: tc.refName, Namespace: "ns", UID: tc.refUID, Source: "debug-pod"}}}}
			require.Equal(t, tc.want, (&DebugSessionController{}).podBelongsToTrackedWorkload(context.Background(), target, ds, pod))
		})
	}

	t.Run("job controller and UID are required", func(t *testing.T) {
		jobTemplate := corev1.PodTemplateSpec{Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "debug", Image: "debug:v1"}}}}
		job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "ns", UID: "job-uid"}, Spec: batchv1.JobSpec{Template: jobTemplate}}
		target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job).Build()
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "job-pod", Namespace: "ns", UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: ptr.To(true)}}}, Spec: *jobTemplate.Spec.DeepCopy()}
		session := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, Namespace: job.Namespace, UID: string(job.UID), Source: "debug-pod"}}}}
		require.True(t, (&DebugSessionController{}).podBelongsToTrackedWorkload(context.Background(), target, session, pod))
		pod.OwnerReferences[0].UID = "replacement-uid"
		require.False(t, (&DebugSessionController{}).podBelongsToTrackedWorkload(context.Background(), target, session, pod))
	})
}

func TestPodTemplateIdentityComesFromApplyResponse(t *testing.T) {
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid"}}
	gets := 0
	target := fake.NewClientBuilder().WithScheme(testScheme()).WithInterceptorFuncs(interceptor.Funcs{
		Apply: func(_ context.Context, _ client.WithWatch, cfg runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
			return json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"config","namespace":"ns","uid":"applied-uid"}}`), cfg)
		},
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
			gets++
			obj.SetUID("existing-uid")
			obj.SetLabels(map[string]string{"breakglass.t-caas.telekom.com/session": ds.Name, DebugSessionUIDLabelKey: string(ds.UID)})
			obj.SetAnnotations(map[string]string{"breakglass.t-caas.telekom.com/source-session": ds.Namespace + "/" + ds.Name, DebugSessionUIDAnnotationKey: string(ds.UID)})
			return nil
		},
	}).Build()
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion("v1")
	obj.SetKind("ConfigMap")
	obj.SetName("config")
	require.NoError(t, (&DebugSessionController{log: zap.NewNop().Sugar()}).deployPodTemplateResource(context.Background(), target, ds, obj, "ns"))
	require.Equal(t, 1, gets, "apply response must supply identity without a second lookup")
	require.Equal(t, "applied-uid", ds.Status.PodTemplateResourceStatuses[0].UID)
	require.Equal(t, "applied-uid", ds.Status.DeployedResources[0].UID)
}

func TestAuxiliaryReadinessUsesOneUIDCheckedSnapshot(t *testing.T) {
	gets := 0
	target := fake.NewClientBuilder().WithScheme(testScheme()).WithInterceptorFuncs(interceptor.Funcs{Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
		gets++
		obj.SetUID("original")
		return nil
	}}).Build()
	m := NewAuxiliaryResourceManager(zap.NewNop().Sugar(), target)
	result := m.checkSingleResourceReadiness(context.Background(), zap.NewNop().Sugar(), target, "v1", "ConfigMap", "config", "ns", "original")
	require.Equal(t, 1, gets)
	require.True(t, result.ready)
	gets = 0
	result = m.checkSingleResourceReadiness(context.Background(), zap.NewNop().Sugar(), target, "v1", "ConfigMap", "config", "ns", "other")
	require.Equal(t, 1, gets)
	require.True(t, result.failed)
	gets = 0
	result = m.checkSingleResourceReadiness(context.Background(), zap.NewNop().Sugar(), target, "v1", "ConfigMap", "config", "ns", "")
	require.Zero(t, gets)
	require.True(t, result.failed)
	require.Contains(t, result.message, "terminate this legacy debug session and request a new session")
}

func TestCleanupResourcesRetainsInventoryWhenClusterConfigMissing(t *testing.T) {
	ds := newTestDebugSession("session", "template", "missing-cluster", "user@example.com")
	ds.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "v1", Kind: "Pod", Name: "pod", Namespace: "ns", UID: "original", Source: "debug-pod"}}
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(ds).WithStatusSubresource(ds).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar()))
	require.Error(t, controller.cleanupResources(context.Background(), ds))
	require.Len(t, ds.Status.DeployedResources, 1)
	require.Equal(t, "original", ds.Status.DeployedResources[0].UID)
	saved := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(ds), saved))
	require.Equal(t, ds.Status.DeployedResources, saved.Status.DeployedResources)
}

func TestTrackedApplyRetainsResponseIdentity(t *testing.T) {
	for _, obj := range []client.Object{
		&corev1.Pod{},
		&corev1.ResourceQuota{},
		&policyv1.PodDisruptionBudget{},
		&appsv1.Deployment{},
		&appsv1.DaemonSet{},
		&unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
		}},
	} {
		t.Run(fmt.Sprintf("%T", obj), func(t *testing.T) {
			obj.SetName("tracked")
			obj.SetNamespace("ns")
			target := fake.NewClientBuilder().WithScheme(testScheme()).WithInterceptorFuncs(interceptor.Funcs{
				Apply: func(_ context.Context, _ client.WithWatch, cfg runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
					options := (&client.ApplyOptions{}).ApplyOptions(opts)
					require.Equal(t, "breakglass-controller", options.FieldManager)
					require.NotNil(t, options.Force)
					require.True(t, *options.Force)
					response := obj.DeepCopyObject().(client.Object)
					response.SetUID(types.UID("applied-original"))
					body, err := json.Marshal(response)
					require.NoError(t, err)
					return json.Unmarshal(body, cfg)
				},
				Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
					t.Fatal("must use apply response, not a replacement lookup")
					return nil
				},
			}).Build()
			require.NoError(t, applyTrackedResource(context.Background(), target, obj))
			require.Equal(t, types.UID("applied-original"), obj.GetUID())
		})
	}
}

func TestWorkloadTemplateAllowsConfiguredDefaultTolerations(t *testing.T) {
	template := &corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "debug", Image: "debug:v1"}}}}
	for _, tc := range []struct {
		name          string
		toleration    corev1.Toleration
		modifiedImage bool
		want          bool
	}{
		{name: "not-ready 60 seconds", toleration: corev1.Toleration{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: ptr.To[int64](60)}, want: true},
		{name: "unreachable 600 seconds", toleration: corev1.Toleration{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: ptr.To[int64](600)}, want: true},
		{name: "unbounded known condition", toleration: corev1.Toleration{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute}, want: true},
		{name: "unrelated key", toleration: corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: ptr.To[int64](60)}},
		{name: "different effect", toleration: corev1.Toleration{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}},
		{name: "different operator", toleration: corev1.Toleration{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoExecute}},
		{name: "modified executable", toleration: corev1.Toleration{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: ptr.To[int64](60)}, modifiedImage: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{Spec: *template.Spec.DeepCopy()}
			pod.Spec.Tolerations = []corev1.Toleration{tc.toleration}
			if tc.modifiedImage {
				pod.Spec.Containers[0].Image = "unrelated:v1"
			}
			before := pod.DeepCopy()
			require.Equal(t, tc.want, podMatchesWorkloadTemplate(pod, template, false))
			require.Equal(t, before, pod, "normalization must not mutate the live pod")
			require.Empty(t, template.Spec.Tolerations)
		})
	}
}

func TestWorkloadTemplateAllowsKubernetesDefaultSchedulingFields(t *testing.T) {
	for _, daemonSet := range []bool{false, true} {
		t.Run(fmt.Sprintf("canonical defaults daemonSet=%t", daemonSet), func(t *testing.T) {
			template := &corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "debug", Image: "debug:v1"}},
			}}
			pod := &corev1.Pod{Spec: *template.Spec.DeepCopy()}
			pod.Spec.Priority = ptr.To[int32](0)
			pod.Spec.PreemptionPolicy = ptr.To(corev1.PreemptLowerPriority)
			templateBefore, podBefore := template.DeepCopy(), pod.DeepCopy()

			target := fake.NewClientBuilder().WithScheme(testScheme()).Build()
			require.False(t, podMatchesWorkloadTemplate(pod, template, daemonSet), "the original strict comparison rejects API-added defaults")
			require.True(t, podMatchesAdmittedWorkloadTemplate(context.Background(), target, pod, template, daemonSet), "canonical API defaults must not invalidate the workload identity")
			require.Equal(t, templateBefore, template, "normalization must not mutate the template")
			require.Equal(t, podBefore, pod, "normalization must not mutate the live pod")
		})
	}

	t.Run("configured scheduling intent remains significant", func(t *testing.T) {
		template := &corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers:       []corev1.Container{{Name: "debug", Image: "debug:v1"}},
			Priority:         ptr.To[int32](100),
			PreemptionPolicy: ptr.To(corev1.PreemptNever),
		}}
		pod := &corev1.Pod{Spec: *template.Spec.DeepCopy()}
		priorityClass := &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "debug-priority"}, Value: 100, PreemptionPolicy: ptr.To(corev1.PreemptNever)}
		target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(priorityClass).Build()
		require.True(t, podMatchesAdmittedWorkloadTemplate(context.Background(), target, pod, template, true))

		tampered := pod.DeepCopy()
		tampered.Spec.Priority = ptr.To[int32](0)
		require.False(t, podMatchesAdmittedWorkloadTemplate(context.Background(), target, tampered, template, true))
		tampered = pod.DeepCopy()
		tampered.Spec.PreemptionPolicy = ptr.To(corev1.PreemptLowerPriority)
		require.False(t, podMatchesAdmittedWorkloadTemplate(context.Background(), target, tampered, template, true))
	})
}

func TestAdmittedPriorityClassDiscriminator(t *testing.T) {
	template := &corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "debug", Image: "debug:v1"}}}}
	makePod := func(class string, priority int32, policy corev1.PreemptionPolicy) *corev1.Pod {
		return &corev1.Pod{Spec: corev1.PodSpec{
			Containers:        []corev1.Container{{Name: "debug", Image: "debug:v1"}},
			PriorityClassName: class,
			Priority:          ptr.To(priority),
			PreemptionPolicy:  ptr.To(policy),
		}}
	}

	t.Run("omitted class accepts verified global default", func(t *testing.T) {
		class := &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "global-debug"}, Value: 100, GlobalDefault: true, PreemptionPolicy: ptr.To(corev1.PreemptNever)}
		target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(class).Build()
		pod := makePod(class.Name, class.Value, corev1.PreemptNever)
		require.True(t, podMatchesAdmittedWorkloadTemplate(context.Background(), target, pod, template, false))
	})

	for _, tc := range []struct {
		name     string
		class    *schedulingv1.PriorityClass
		podClass string
		priority int32
		policy   corev1.PreemptionPolicy
	}{
		{name: "missing class", podClass: "missing", priority: 100, policy: corev1.PreemptNever},
		{name: "non-global class", class: &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "ordinary"}, Value: 100, PreemptionPolicy: ptr.To(corev1.PreemptNever)}, podClass: "ordinary", priority: 100, policy: corev1.PreemptNever},
		{name: "wrong numeric value", class: &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "global"}, Value: 100, GlobalDefault: true}, podClass: "global", priority: 200, policy: corev1.PreemptLowerPriority},
		{name: "wrong effective policy", class: &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "global"}, Value: 100, GlobalDefault: true, PreemptionPolicy: ptr.To(corev1.PreemptNever)}, podClass: "global", priority: 100, policy: corev1.PreemptLowerPriority},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := fake.NewClientBuilder().WithScheme(testScheme()).Build()
			if tc.class != nil {
				target = fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(tc.class).Build()
			}
			require.False(t, podMatchesAdmittedWorkloadTemplate(context.Background(), target, makePod(tc.podClass, tc.priority, tc.policy), template, false))
		})
	}

	t.Run("explicit class mismatch is rejected", func(t *testing.T) {
		expected := template.DeepCopy()
		expected.Spec.PriorityClassName = "configured"
		class := &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "configured"}, Value: 100, PreemptionPolicy: ptr.To(corev1.PreemptNever)}
		other := class.DeepCopy()
		other.Name = "other"
		target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(class, other).Build()
		require.True(t, podMatchesAdmittedWorkloadTemplate(context.Background(), target, makePod(class.Name, 100, corev1.PreemptNever), expected, false))
		pod := makePod("other", 100, corev1.PreemptNever)
		require.False(t, podMatchesAdmittedWorkloadTemplate(context.Background(), target, pod, expected, false))
	})

	t.Run("class lookup denied", func(t *testing.T) {
		target := fake.NewClientBuilder().WithScheme(testScheme()).WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, key client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return apierrors.NewForbidden(schedulingv1.Resource("priorityclasses"), key.Name, fmt.Errorf("test denial"))
			},
		}).Build()
		require.False(t, podMatchesAdmittedWorkloadTemplate(context.Background(), target, makePod("global", 100, corev1.PreemptNever), template, false))
	})

	for _, field := range []string{"priority", "policy"} {
		t.Run("missing admitted "+field, func(t *testing.T) {
			class := &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "global"}, Value: 0, GlobalDefault: true}
			target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(class).Build()
			pod := makePod(class.Name, 0, corev1.PreemptLowerPriority)
			if field == "priority" {
				pod.Spec.Priority = nil
			} else {
				pod.Spec.PreemptionPolicy = nil
			}
			require.False(t, podMatchesAdmittedWorkloadTemplate(context.Background(), target, pod, template, false))
		})
	}

	t.Run("synthetic replica set template stays strict", func(t *testing.T) {
		pod := makePod("global-debug", 100, corev1.PreemptNever)
		require.False(t, podMatchesWorkloadTemplate(pod, template, false))
	})
}

func TestTrackedWorkloadAdmittedPodMembership(t *testing.T) {
	for _, kind := range []string{"DaemonSet", "Deployment"} {
		for _, global := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/global=%t", kind, global), func(t *testing.T) {
				ctx := context.Background()
				class := &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "debug-priority"}, Value: 100, GlobalDefault: global, PreemptionPolicy: ptr.To(corev1.PreemptNever)}
				template := corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "debug", Image: "debug:v1"}}}}
				if !global {
					template.Spec.PriorityClassName = class.Name
				}
				meta := metav1.ObjectMeta{Name: "workload", Namespace: "ns", UID: "workload-uid"}
				owner := metav1.OwnerReference{APIVersion: "apps/v1", Kind: kind, Name: meta.Name, UID: meta.UID, Controller: ptr.To(true)}
				deployment := &appsv1.Deployment{ObjectMeta: meta, Spec: appsv1.DeploymentSpec{Template: template}}
				rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "ns", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{owner}}, Spec: appsv1.ReplicaSetSpec{Template: template}}
				objects := []client.Object{class}
				if kind == "DaemonSet" {
					objects = append(objects, &appsv1.DaemonSet{ObjectMeta: meta, Spec: appsv1.DaemonSetSpec{Template: template}})
				} else {
					objects = append(objects, deployment, rs)
					owner = metav1.OwnerReference{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: ptr.To(true)}
				}
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{owner}}, Spec: *template.Spec.DeepCopy()}
				pod.Spec.PriorityClassName = class.Name
				pod.Spec.Priority = ptr.To(class.Value)
				pod.Spec.PreemptionPolicy = ptr.To(corev1.PreemptNever)
				podBefore, templateBefore := pod.DeepCopy(), template.DeepCopy()
				session := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "apps/v1", Kind: kind, Name: meta.Name, Namespace: meta.Namespace, UID: string(meta.UID), Source: "debug-pod"}}}}
				target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(objects...).Build()
				controller := &DebugSessionController{}
				require.False(t, podMatchesWorkloadTemplate(pod, &template, kind == "DaemonSet"), "the old comparison rejects this admitted Pod")
				require.True(t, controller.podBelongsToTrackedWorkload(ctx, target, session, pod))
				require.Equal(t, podBefore, pod)
				require.Equal(t, templateBefore, &template)
				tampered := pod.DeepCopy()
				tampered.Spec.Containers[0].Image = "unrelated:v1"
				require.False(t, controller.podBelongsToTrackedWorkload(ctx, target, session, tampered))
				if kind == "Deployment" && global {
					rs.Spec.Template.Spec.PriorityClassName = class.Name
					target = fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(class, deployment, rs).Build()
					require.False(t, controller.podBelongsToTrackedWorkload(ctx, target, session, pod), "admission defaults must not excuse ReplicaSet template changes")
				}
			})
		}
	}
}
