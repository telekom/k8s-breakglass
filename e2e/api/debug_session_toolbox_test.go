// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// toolboxE2EImage stands in for a toolbox: any digest-pinned image works as an
// image volume; busybox ships /bin/busybox, which the test reads and runs.
const toolboxE2EImage = "docker.io/library/busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"

// TestDebugSessionToolboxImageVolume proves that spec.toolbox reaches an
// approved debug pod as a read-only image volume at the default path, that
// BREAKGLASS_TOOLBOX names it, and that its content is readable and runnable
// from a shell under a read-only root filesystem.
func TestDebugSessionToolboxImageVolume(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	requester := helpers.TestUsers.PlatformIdentityRequester
	approver := helpers.TestUsers.DebugSessionApprover

	kubeconfig := helpers.GetKubeconfig()
	if spoke := helpers.GetSpokeAKubeconfig(); spoke != "" {
		kubeconfig = spoke
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	kube, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)
	version, err := kube.Discovery().ServerVersion()
	require.NoError(t, err)
	if minor, _ := strconv.Atoi(strings.TrimSuffix(version.Minor, "+")); version.Major == "1" && minor < 35 {
		t.Skipf("ImageVolume is off by default before Kubernetes 1.35 (cluster %s)", version.GitVersion)
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("toolbox")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:          "Toolbox image volume",
			Mode:                 breakglassv1alpha1.DebugSessionModeWorkload,
			WorkloadType:         breakglassv1alpha1.DebugWorkloadDeployment,
			TargetNamespace:      "breakglass-debug",
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{DefaultNamespace: "breakglass-debug"},
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: ptr.To(true)},
			Toolbox:              &breakglassv1alpha1.DebugSessionToolbox{Image: toolboxE2EImage},
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: toolbox
spec:
  selector:
    matchLabels:
      toolbox-session: {{ .session.name | yamlQuote }}
  template:
    metadata:
      labels:
        toolbox-session: {{ .session.name | yamlQuote }}
    spec:
      containers:
      - name: debug
        image: busybox:latest
        imagePullPolicy: IfNotPresent
        command: ["sleep", "3600"]
        securityContext:
          runAsNonRoot: true
          runAsUser: 65532
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          seccompProfile:
            type: RuntimeDefault
`,
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "20m", DefaultDuration: "10m", RetainFor: "10s"},
		},
	}
	require.NoError(t, s.CreateResource(template))
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("toolbox"), Namespace: s.Namespace},
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
			TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m", Reason: "toolbox e2e",
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
	status, err := NewDebugSessionAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, ctx, approver)).ApproveDebugSession(ctx, t, session.Name, "toolbox e2e")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	active := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
	require.Eventually(t, func() bool {
		if s.Client.Get(ctx, client.ObjectKeyFromObject(active), active) != nil {
			return false
		}
		return len(active.Status.AllowedPods) > 0 && active.Status.AllowedPods[0].Ready
	}, helpers.WaitForStateTimeout, time.Second, "approved debug pod with the toolbox must become Ready")

	pod, err := kube.CoreV1().Pods(active.Status.AllowedPods[0].Namespace).Get(ctx, active.Status.AllowedPods[0].Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Contains(t, pod.Spec.Volumes, corev1.Volume{Name: "breakglass-toolbox", VolumeSource: corev1.VolumeSource{
		Image: &corev1.ImageVolumeSource{Reference: toolboxE2EImage, PullPolicy: corev1.PullIfNotPresent},
	}})

	request := kube.CoreV1().RESTClient().Post().Namespace(pod.Namespace).Resource("pods").Name(pod.Name).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "debug", Stdout: true, Stderr: true,
			Command: []string{"sh", "-c", `cd "$BREAKGLASS_TOOLBOX" && pwd && ./bin/busybox echo runs && (touch x 2>&1 || true)`},
		}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(config, http.MethodPost, request.URL())
	require.NoError(t, err)
	var stdout, stderr bytes.Buffer
	streamCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	require.NoError(t, executor.StreamWithContext(streamCtx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}), stderr.String())
	out := stdout.String()
	assert.Contains(t, out, breakglassv1alpha1.DefaultDebugSessionToolboxMountPath+"\n", "BREAKGLASS_TOOLBOX names the mount")
	assert.Contains(t, out, "runs\n", "toolbox binaries run from the mount")
	assert.Contains(t, out, "Read-only file system", "the toolbox is read-only")
}
