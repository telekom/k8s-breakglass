// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// runtimeIdentityCase is one of the three configurations every pod kind is
// tested with: the default, the global opt-out and the template opt-out.
type runtimeIdentityCase struct {
	name           string
	globalDisabled bool
	templateValue  *bool
	wantIdentity   bool
}

var runtimeIdentityCases = []runtimeIdentityCase{
	{name: "default", wantIdentity: true},
	{name: "template true", templateValue: ptr.To(true), wantIdentity: true},
	{name: "global opt-out", globalDisabled: true},
	{name: "template opt-out", templateValue: ptr.To(false)},
}

func withRuntimeIdentityTemplate(template *breakglassv1alpha1.DebugSessionTemplateSpec, value *bool) {
	if value != nil {
		template.Audit = &breakglassv1alpha1.DebugSessionAuditConfig{RuntimeIdentityMetadata: value}
	}
}

func identitySession(ds *breakglassv1alpha1.DebugSession) *breakglassv1alpha1.DebugSession {
	ds.Spec.TemplateRef = "net-debug"
	ds.Spec.RequestedBy = "requester@example.com"
	ds.Spec.TicketSystemID = "INC-4711 / urgent"
	ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{ApprovedBy: "approver@example.com"}
	return ds
}

// assertRuntimeIdentity checks the metadata of one pod. Without runtime
// identity, the controller adds none of the new annotations and keeps the
// session label.
func assertRuntimeIdentity(t *testing.T, meta metav1.ObjectMeta, ds *breakglassv1alpha1.DebugSession, want bool) {
	t.Helper()
	assert.Equal(t, ds.Name, meta.Labels[DebugSessionLabelKey], "the existing session label is always kept")
	if !want {
		assert.NotEqual(t, ds.Spec.RequestedBy, meta.Annotations[RuntimeIdentityRequestedByAnnotation])
		assert.NotEqual(t, ds.Status.Approval.ApprovedBy, meta.Annotations[RuntimeIdentityApprovedByAnnotation])
		assert.NotContains(t, meta.Annotations, RuntimeIdentityTicketAnnotation)
		return
	}
	assert.Equal(t, string(ds.UID), meta.Labels[DebugSessionUIDLabelKey])
	assert.Equal(t, ds.Spec.TemplateRef, meta.Labels[DebugTemplateLabelKey])
	assert.Equal(t, ds.Spec.RequestedBy, meta.Annotations[RuntimeIdentityRequestedByAnnotation])
	assert.Equal(t, ds.Status.Approval.ApprovedBy, meta.Annotations[RuntimeIdentityApprovedByAnnotation])
	assert.Equal(t, ds.Spec.TicketSystemID, meta.Annotations[RuntimeIdentityTicketAnnotation])
}

func TestApplyRuntimeIdentityMetadataOverridesOtherSources(t *testing.T) {
	ds := identitySession(&breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "debug-a", UID: "0f1e2d3c-aaaa-bbbb-cccc-000000000001"}})
	ds.Status.Approval = nil
	ds.Spec.TicketSystemID = ""
	meta := metav1.ObjectMeta{
		Labels: map[string]string{DebugSessionUIDLabelKey: "spoofed", "keep": "me"},
		Annotations: map[string]string{
			RuntimeIdentityRequestedByAnnotation: "spoofed",
			RuntimeIdentityApprovedByAnnotation:  "spoofed",
			RuntimeIdentityTicketAnnotation:      "spoofed",
		},
	}
	ApplyRuntimeIdentityMetadata(&meta, ds, nil, false)
	assert.Equal(t, string(ds.UID), meta.Labels[DebugSessionUIDLabelKey])
	assert.Equal(t, "me", meta.Labels["keep"])
	assert.Equal(t, "requester@example.com", meta.Annotations[RuntimeIdentityRequestedByAnnotation])
	assert.NotContains(t, meta.Annotations, RuntimeIdentityApprovedByAnnotation, "no approver: no other source may fill the key in")
	assert.NotContains(t, meta.Annotations, RuntimeIdentityTicketAnnotation)
}

func TestApplyRuntimeIdentityMetadataOptOuts(t *testing.T) {
	for _, tc := range runtimeIdentityCases {
		t.Run(tc.name, func(t *testing.T) {
			ds := identitySession(&breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "debug-a", UID: "uid-1"}})
			template := &breakglassv1alpha1.DebugSessionTemplateSpec{}
			withRuntimeIdentityTemplate(template, tc.templateValue)
			meta := metav1.ObjectMeta{Labels: map[string]string{DebugSessionLabelKey: ds.Name}}
			ApplyRuntimeIdentityMetadata(&meta, ds, template, tc.globalDisabled)
			assertRuntimeIdentity(t, meta, ds, tc.wantIdentity)
			if !tc.wantIdentity {
				assert.Equal(t, map[string]string{DebugSessionLabelKey: ds.Name}, meta.Labels, "opt-outs leave labels untouched")
			}
		})
	}
}

func TestRuntimeIdentityLabelValue(t *testing.T) {
	assert.Equal(t, "debug-a", runtimeIdentityLabelValue("debug-a"))
	assert.Equal(t, "", runtimeIdentityLabelValue(""))
	long := strings.Repeat("a", 80)
	for _, value := range []string{long, long + "b", "user@example.com", "-starts-with-dash", "ü"} {
		got := runtimeIdentityLabelValue(value)
		assert.Empty(t, validation.IsValidLabelValue(got), "%q -> %q must be a valid label value", value, got)
	}
	assert.NotEqual(t, runtimeIdentityLabelValue(long), runtimeIdentityLabelValue(long+"b"), "truncated values stay distinct")
}

func TestAssignEphemeralContainerName(t *testing.T) {
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "s", UID: "1A2B3C4D-0000-0000-0000-000000000000"}}
	assert.Equal(t, "bg-1a2b3c4d-", ephemeralContainerNamePrefix(ds))
	assert.Equal(t, "bg-1a2b3c4d-1", assignEphemeralContainerName(ds, "pod-uid", nil, "debug"))
	assert.Equal(t, "bg-1a2b3c4d-3", assignEphemeralContainerName(ds, "pod-uid", []string{"other", "bg-1a2b3c4d-2", "bg-ffffffff-9"}, "debug"),
		"n follows the highest n of this session in the pod")

	operation := func(podUID, name, requested string) breakglassv1alpha1.KubectlDebugOperation {
		return breakglassv1alpha1.KubectlDebugOperation{
			Kind:               kubectlDebugOperationKindEphemeralContainer,
			TargetPod:          breakglassv1alpha1.KubectlDebugOperationTargetPod{UID: "pod-uid"},
			EphemeralContainer: breakglassv1alpha1.KubectlDebugEphemeralContainerIntent{Name: name, RequestedName: requested},
		}
	}
	ds.Status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{Operations: []breakglassv1alpha1.KubectlDebugOperation{
		operation("pod-uid", "bg-1a2b3c4d-4", "debug"),
		operation("pod-uid", "legacy", ""),
	}}
	assert.Equal(t, "bg-1a2b3c4d-4", assignEphemeralContainerName(ds, "pod-uid", nil, "debug"), "a retry reuses the recorded name")
	assert.Equal(t, "legacy", assignEphemeralContainerName(ds, "pod-uid", nil, "legacy"), "an operation from before the upgrade keeps its name")
	assert.Equal(t, "bg-1a2b3c4d-5", assignEphemeralContainerName(ds, "pod-uid", nil, "second"))
	assert.Equal(t, "bg-1a2b3c4d-1", assignEphemeralContainerName(ds, "other-pod", nil, "debug"), "names are counted per pod")

	short := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "x"}}
	assert.Empty(t, validation.IsDNS1123Label(assignEphemeralContainerName(short, "p", nil, "debug")), "sessions without a UID still get a valid name")
}

func TestEphemeralContainerAnnotationKey(t *testing.T) {
	key, err := ephemeralContainerAnnotationKey("bg-1a2b3c4d-999999999")
	require.NoError(t, err)
	assert.Equal(t, "breakglass.telekom.com/ephemeral.bg-1a2b3c4d-999999999", key)
	_, err = ephemeralContainerAnnotationKey(strings.Repeat("a", 54))
	assert.Error(t, err, "the name part of an annotation key is limited to 63 characters")
}

func TestRuntimeIdentityWorkloadPods(t *testing.T) {
	for _, tc := range runtimeIdentityCases {
		t.Run(tc.name, func(t *testing.T) {
			controller, session, template, _ := newDeploymentFenceFixture(t)
			identitySession(session)
			session.Spec.TemplateRef = template.Name
			template.Spec.Labels = map[string]string{DebugSessionUIDLabelKey: "spoofed"}
			template.Spec.Annotations = map[string]string{RuntimeIdentityApprovedByAnnotation: "spoofed"}
			withRuntimeIdentityTemplate(&template.Spec, tc.templateValue)
			controller.WithRuntimeIdentityMetadataDisabled(tc.globalDisabled)
			workload, _, err := controller.buildWorkload(session, template, nil, nil, "target")
			require.NoError(t, err)
			deployment, ok := workload.(*appsv1.Deployment)
			require.True(t, ok)
			assertRuntimeIdentity(t, deployment.Spec.Template.ObjectMeta, session, tc.wantIdentity)
			assert.Equal(t, template.Name, deployment.Spec.Template.Labels[DebugTemplateLabelKey], "the existing template label is always kept")
			if !tc.wantIdentity {
				assert.Equal(t, "spoofed", deployment.Spec.Template.Annotations[RuntimeIdentityApprovedByAnnotation], "opt-outs keep the previous metadata")
			}
		})
	}
}

func TestRuntimeIdentityPodCopyAndNodeDebugPods(t *testing.T) {
	for _, tc := range runtimeIdentityCases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newKubectlTestScheme()
			session := identitySession(motdKubectlSession("identity-session", &breakglassv1alpha1.KubectlDebugConfig{
				PodCopy:   &breakglassv1alpha1.PodCopyConfig{Enabled: true, TargetNamespace: "debug-copies", TTL: "1h"},
				NodeDebug: &breakglassv1alpha1.NodeDebugConfig{Enabled: true},
			}, nil))
			withRuntimeIdentityTemplate(session.Status.ResolvedTemplate, tc.templateValue)
			hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
			targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "production", UID: "pod-app-uid"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "myapp:v1"}}}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "debug-copies", UID: "debug-copies-uid"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-debug", UID: "namespace-uid"}},
				&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1", UID: "node-uid"}},
			).Build()
			handler := newTestKubectlDebugHandler(hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}}).
				WithRuntimeIdentityMetadataDisabled(tc.globalDisabled)

			copyPod, err := handler.CreatePodCopy(context.Background(), session, "production", "app-pod", "busybox:latest", session.Spec.RequestedBy)
			require.NoError(t, err)
			assertRuntimeIdentity(t, copyPod.ObjectMeta, session, tc.wantIdentity)
			assert.Equal(t, "true", copyPod.Labels["breakglass.telekom.com/debug-copy"])

			nodePod, err := handler.CreateNodeDebugPod(context.Background(), session, "worker-1", session.Spec.RequestedBy)
			require.NoError(t, err)
			assertRuntimeIdentity(t, nodePod.ObjectMeta, session, tc.wantIdentity)
			assert.Equal(t, "requester_example.com", nodePod.Labels["breakglass.telekom.com/requested-by"], "the existing operator label is kept")
		})
	}
}

func TestRuntimeIdentityEphemeralContainers(t *testing.T) {
	for _, tc := range runtimeIdentityCases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newKubectlTestScheme()
			session := newEphemeralOperationTestSession()
			session.UID = "0f1e2d3c-aaaa-bbbb-cccc-000000000001"
			withRuntimeIdentityTemplate(session.Status.ResolvedTemplate, tc.templateValue)
			updates := 0
			target := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default", UID: "target-uid", Annotations: map[string]string{"app": "keep"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:v1"}}},
			}).WithInterceptorFuncs(interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, cl ctrlclient.Client, name string, obj ctrlclient.Object, opts ...ctrlclient.SubResourceUpdateOption) error {
				if name == "ephemeralcontainers" {
					updates++
					// The pod was annotated before the container is added.
					live := &corev1.Pod{}
					require.NoError(t, cl.Get(ctx, ctrlclient.ObjectKeyFromObject(obj), live))
					containers := obj.(*corev1.Pod).Spec.EphemeralContainers
					_, annotated := live.Annotations[EphemeralContainerAnnotationPrefix+containers[len(containers)-1].Name]
					assert.Equal(t, tc.wantIdentity, annotated, "the annotation precedes the injection")
					return cl.Update(ctx, obj)
				}
				return cl.SubResource(name).Update(ctx, obj, opts...)
			}}).Build()
			hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(session).Build()
			handler := newTestKubectlDebugHandler(hub, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": target}}).
				WithRuntimeIdentityMetadataDisabled(tc.globalDisabled)

			name, err := handler.InjectEphemeralContainerNamed(context.Background(), session, "default", "target", "debugger", "busybox:latest", []string{"sh"}, nil, "test-user@example.com")
			require.NoError(t, err)
			pod := &corev1.Pod{}
			require.NoError(t, target.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "default", Name: "target"}, pod))
			require.Len(t, pod.Spec.EphemeralContainers, 1)
			assert.Equal(t, name, pod.Spec.EphemeralContainers[0].Name)
			assert.Equal(t, "keep", pod.Annotations["app"])
			if !tc.wantIdentity {
				assert.Equal(t, "debugger", name, "opt-outs keep the requested name")
				assert.Len(t, pod.Annotations, 1, "opt-outs add no annotation")
				return
			}
			assert.Equal(t, "bg-0f1e2d3c-1", name)
			assert.Equal(t, string(session.UID), pod.Annotations["breakglass.telekom.com/ephemeral.bg-0f1e2d3c-1"])

			// Retrying the same request is idempotent; a new request gets n+1.
			stored := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), stored))
			assert.Equal(t, "debugger", stored.Status.KubectlDebugStatus.Operations[0].EphemeralContainer.RequestedName)
			retried, err := handler.InjectEphemeralContainerNamed(context.Background(), stored, "default", "target", "debugger", "busybox:latest", []string{"sh"}, nil, "test-user@example.com")
			require.NoError(t, err)
			assert.Equal(t, name, retried)
			assert.Equal(t, 1, updates, "a retry must not inject again")
			require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), stored))
			second, err := handler.InjectEphemeralContainerNamed(context.Background(), stored, "default", "target", "second", "busybox:latest", []string{"sh"}, nil, "test-user@example.com")
			require.NoError(t, err)
			assert.Equal(t, "bg-0f1e2d3c-2", second)
		})
	}
}
