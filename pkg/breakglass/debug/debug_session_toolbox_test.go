// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const testToolboxImage = "registry.example/breakglass-toolbox@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func toolboxVolume(name string) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{Image: &corev1.ImageVolumeSource{
		Reference: testToolboxImage, PullPolicy: corev1.PullIfNotPresent,
	}}}
}

func assertToolboxMounted(t *testing.T, c corev1.Container, volume, path string) {
	t.Helper()
	assert.Contains(t, c.VolumeMounts, corev1.VolumeMount{Name: volume, MountPath: path, ReadOnly: true}, c.Name)
	assert.Contains(t, c.Env, corev1.EnvVar{Name: toolboxEnvName, Value: path}, c.Name)
}

func TestInjectToolboxMountsEveryRegularContainer(t *testing.T) {
	spec := corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init"}},
		Containers:     []corev1.Container{{Name: "a"}, {Name: "b", Env: []corev1.EnvVar{{Name: toolboxEnvName, Value: "/forged"}}}},
	}
	injectToolbox(&spec, &breakglassv1alpha1.DebugSessionToolbox{Image: testToolboxImage})
	for _, c := range spec.Containers {
		assertToolboxMounted(t, c, toolboxVolumeName, breakglassv1alpha1.DefaultDebugSessionToolboxMountPath)
	}
	assert.Equal(t, []corev1.EnvVar{{Name: toolboxEnvName, Value: breakglassv1alpha1.DefaultDebugSessionToolboxMountPath}}, spec.Containers[1].Env, "the controller value replaces a template value")
	assert.Empty(t, spec.InitContainers[0].VolumeMounts, "init containers are not interactive")
	assert.Equal(t, []corev1.Volume{toolboxVolume(toolboxVolumeName)}, spec.Volumes)

	// Idempotent: a second injection changes nothing.
	again := *spec.DeepCopy()
	injectToolbox(&again, &breakglassv1alpha1.DebugSessionToolbox{Image: testToolboxImage})
	assert.Equal(t, spec, again)
}

func TestInjectToolboxKeepsTemplateMountsAndVolumes(t *testing.T) {
	spec := corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "own", VolumeMounts: []corev1.VolumeMount{{Name: "docs", MountPath: "/tools"}}},
			{Name: "debug"},
		},
		Volumes: []corev1.Volume{{Name: toolboxVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
	}
	injectToolbox(&spec, &breakglassv1alpha1.DebugSessionToolbox{Image: testToolboxImage, MountPath: "/tools"})
	assert.Equal(t, []corev1.VolumeMount{{Name: "docs", MountPath: "/tools"}}, spec.Containers[0].VolumeMounts, "a template mount at the toolbox path wins")
	assert.Empty(t, spec.Containers[0].Env)
	assertToolboxMounted(t, spec.Containers[1], toolboxVolumeName+"-1", "/tools")
	assert.Equal(t, corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}, spec.Volumes[0].VolumeSource, "a template volume with the reserved name is kept")
	assert.Contains(t, spec.Volumes, toolboxVolume(toolboxVolumeName+"-1"))
}

func TestInjectToolboxNoop(t *testing.T) {
	spec := corev1.PodSpec{Containers: []corev1.Container{{Name: "a"}}}
	want := *spec.DeepCopy()
	injectToolbox(&spec, nil)
	injectToolbox(&spec, &breakglassv1alpha1.DebugSessionToolbox{})
	injectToolbox(&spec, &breakglassv1alpha1.DebugSessionToolbox{Image: testToolboxImage}, "missing")
	assert.Equal(t, want, spec, "no toolbox, no image, or no selected container: no volume is added")
}

func TestBuildWorkloadMountsTemplateToolbox(t *testing.T) {
	controller, session, template, _ := newDeploymentFenceFixture(t)
	session.UID = "session-uid"
	template.Spec.WorkloadType = breakglassv1alpha1.DebugWorkloadDeployment
	template.Spec.PodTemplateString = ""
	template.Spec.Toolbox = &breakglassv1alpha1.DebugSessionToolbox{Image: testToolboxImage}
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{Spec: breakglassv1alpha1.DebugPodTemplateSpec{TemplateString: `containers:
  - name: debug
    image: busybox
`}}
	workload, _, err := controller.buildWorkload(session, template, nil, podTemplate, "target")
	require.NoError(t, err)
	deployment, ok := workload.(*appsv1.Deployment)
	require.True(t, ok)
	spec := deployment.Spec.Template.Spec
	require.Len(t, spec.Containers, 1)
	assertToolboxMounted(t, spec.Containers[0], toolboxVolumeName, breakglassv1alpha1.DefaultDebugSessionToolboxMountPath)
	assert.Contains(t, spec.Volumes, toolboxVolume(toolboxVolumeName))
}

func TestNodeDebugPodMountsSessionToolbox(t *testing.T) {
	scheme := newKubectlTestScheme()
	session := motdKubectlSession("node-toolbox-session", &breakglassv1alpha1.KubectlDebugConfig{NodeDebug: &breakglassv1alpha1.NodeDebugConfig{Enabled: true}}, nil)
	session.Status.ResolvedTemplate.Toolbox = &breakglassv1alpha1.DebugSessionToolbox{Image: testToolboxImage}
	hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-debug", UID: "namespace-uid"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1", UID: "node-uid"}},
	).Build()
	handler := newTestKubectlDebugHandler(hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

	pod, err := handler.CreateNodeDebugPod(context.Background(), session, "worker-1", "operator@example.com")
	require.NoError(t, err)
	require.Len(t, pod.Spec.Containers, 1)
	assertToolboxMounted(t, pod.Spec.Containers[0], toolboxVolumeName, breakglassv1alpha1.DefaultDebugSessionToolboxMountPath)
	assert.Contains(t, pod.Spec.Volumes, toolboxVolume(toolboxVolumeName))
	assert.True(t, slices.ContainsFunc(pod.Spec.Volumes, func(v corev1.Volume) bool { return v.Name == "host-root" }), "the host root mount stays")
}

func TestPodCopyToolboxOnlyInDebugger(t *testing.T) {
	scheme := newKubectlTestScheme()
	session := motdKubectlSession("copy-toolbox-session", &breakglassv1alpha1.KubectlDebugConfig{
		PodCopy: &breakglassv1alpha1.PodCopyConfig{Enabled: true, TargetNamespace: "debug-copies", TTL: "1h"},
	}, nil)
	session.Status.ResolvedTemplate.Toolbox = &breakglassv1alpha1.DebugSessionToolbox{Image: testToolboxImage}
	sourcePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "production", UID: "pod-app-uid"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "myapp:v1"}},
			Volumes:    []corev1.Volume{{Name: toolboxVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
		},
	}
	targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sourcePod,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "debug-copies", UID: "debug-copies-uid"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
	).Build()
	hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	handler := newTestKubectlDebugHandler(hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

	pod, err := handler.CreatePodCopy(context.Background(), session, "production", "app-pod", "busybox:latest", "operator@example.com")
	require.NoError(t, err)
	require.Len(t, pod.Spec.Containers, 2)
	assert.Equal(t, sourcePod.Spec.Containers[0], pod.Spec.Containers[0], "copied application containers stay unchanged")
	assertToolboxMounted(t, pod.Spec.Containers[1], toolboxVolumeName+"-1", breakglassv1alpha1.DefaultDebugSessionToolboxMountPath)
	assert.Contains(t, pod.Spec.Volumes, sourcePod.Spec.Volumes[0], "copied application volumes stay unchanged")
	assert.Contains(t, pod.Spec.Volumes, toolboxVolume(toolboxVolumeName+"-1"))
}

func TestBuildWorkloadRejectsToolboxOnRestrictedCatalogueProfile(t *testing.T) {
	controller, session, template, _ := newDeploymentFenceFixture(t)
	labels := map[string]string{catalogueProfileLabel: "restricted-profile", catalogueIntentLabel: "workload-diagnostics", catalogueElevatedLabel: "false"}
	template.Labels = labels
	template.Spec.PodTemplateString = ""
	template.Spec.Toolbox = &breakglassv1alpha1.DebugSessionToolbox{Image: testToolboxImage}
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "catalogue-pod", Labels: labels},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{TemplateString: `securityContext:
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault
automountServiceAccountToken: false
containers:
  - name: debug
    image: busybox
    securityContext:
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
`},
	}
	_, _, err := controller.buildWorkload(session, template, nil, podTemplate, "target")
	require.ErrorContains(t, err, "restricted catalogue profiles cannot mount a toolbox")

	template.Spec.Toolbox = nil
	_, _, err = controller.buildWorkload(session, template, nil, podTemplate, "target")
	require.NoError(t, err, "the same restricted profile builds without a toolbox")
}

func TestCreateRecoveryMatchesWhenAPIServerDroppedImageVolumes(t *testing.T) {
	desired := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "node-debugger", Namespace: "breakglass-debug"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "debugger", Image: "busybox"}},
			Volumes:    []corev1.Volume{{Name: "host-root", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}}},
		},
	}
	desired.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "host-root", MountPath: "/host"}}
	stored := desired.DeepCopy()
	injectToolbox(&desired.Spec, &breakglassv1alpha1.DebugSessionToolbox{Image: testToolboxImage})

	// A cluster without the ImageVolume API stored the pod without the volume
	// and its mount; only the environment variable remains.
	stored.Spec.Containers[0].Env = desired.Spec.Containers[0].Env
	matches, err := recoveredCreateContentMatches(desired, stored)
	require.NoError(t, err)
	assert.True(t, matches)

	// A stored image volume must still match exactly.
	other := desired.DeepCopy()
	other.Spec.Volumes[1].Image.Reference = "registry.example/other@sha256:" + strings.Repeat("1", 64)
	matches, err = recoveredCreateContentMatches(desired, other)
	require.NoError(t, err)
	assert.False(t, matches, "a different stored toolbox image is not a dropped volume")

	// Losing an unrelated mount is still a mismatch.
	stored.Spec.Containers[0].VolumeMounts = nil
	matches, err = recoveredCreateContentMatches(desired, stored)
	require.NoError(t, err)
	assert.False(t, matches)
}
