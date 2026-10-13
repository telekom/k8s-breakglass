// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
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

// TestDebugSessionMOTDInExecShells proves that a plain `kubectl exec -it <pod>
// -- sh|bash` into an approved debug pod prints the effective MOTD and runbook
// link once, under a read-only root filesystem, while non-interactive exec
// output stays untouched.
func TestDebugSessionMOTDInExecShells(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	requester := helpers.TestUsers.PlatformIdentityRequester
	approver := helpers.TestUsers.DebugSessionApprover
	const runbook = "https://example.com/runbooks/debug.md#motd-exec"

	restricted := `
        securityContext:
          runAsNonRoot: true
          runAsUser: 65532
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          seccompProfile:
            type: RuntimeDefault
        resources:
          requests:
            memory: 32Mi`
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("motd-exec")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "MOTD exec shells",
			Mode:            breakglassv1alpha1.DebugSessionModeWorkload,
			WorkloadType:    breakglassv1alpha1.DebugWorkloadDeployment,
			TargetNamespace: "breakglass-debug",
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace: "breakglass-debug",
			},
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: ptr.To(true)},
			MOTD:                 &breakglassv1alpha1.MessageOfTheDay{Message: "Purpose: template text, replaced by the binding."},
			PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: motd-exec
spec:
  selector:
    matchLabels:
      motd-session: {{ .session.name | yamlQuote }}
  template:
    metadata:
      labels:
        motd-session: {{ .session.name | yamlQuote }}
    spec:
      containers:
      - name: busybox
        image: busybox:latest
        imagePullPolicy: IfNotPresent
        command: ["sleep", "3600"]` + restricted + `
      - name: netshoot
        image: nicolaka/netshoot:latest
        imagePullPolicy: IfNotPresent
        command: ["sleep", "3600"]` + restricted + `
`,
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "20m", DefaultDuration: "10m", RetainFor: "10s"},
		},
	}
	require.NoError(t, s.CreateResource(template))
	motd := "Purpose: MOTD exec e2e.\nTerminate: bgctl debug session terminate <session>."
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("motd-exec"), Namespace: s.Namespace},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
			Clusters:    []string{s.Cluster},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Groups: requester.Groups},
			Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Users: []string{approver.Email}},
			MOTD:        &breakglassv1alpha1.MessageOfTheDay{Message: motd, RunbookURL: runbook},
		},
	}
	require.NoError(t, s.CreateResource(binding))

	var session *breakglassv1alpha1.DebugSession
	require.Eventually(t, func() bool {
		created, err := s.TC.ClientForUser(requester).CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
			TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m", Reason: "MOTD exec e2e",
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
	approverAPI := NewDebugSessionAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, ctx, approver))
	status, err := approverAPI.ApproveDebugSession(ctx, t, session.Name, "MOTD exec e2e")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	active := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
	require.Eventually(t, func() bool {
		if s.Client.Get(ctx, client.ObjectKeyFromObject(active), active) != nil {
			return false
		}
		return len(active.Status.AllowedPods) > 0 && active.Status.AllowedPods[0].Ready
	}, helpers.WaitForStateTimeout, time.Second, "approved debug pod must become Ready")
	podInfo := active.Status.AllowedPods[0]

	kubeconfig := helpers.GetKubeconfig()
	if spoke := helpers.GetSpokeAKubeconfig(); spoke != "" {
		kubeconfig = spoke
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	kube, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)
	pod, err := kube.CoreV1().Pods(podInfo.Namespace).Get(ctx, podInfo.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, pod.Annotations["breakglass.t-caas.telekom.com/motd-profile"])
	for _, c := range pod.Spec.Containers {
		assert.Contains(t, c.VolumeMounts, corev1.VolumeMount{Name: "breakglass-motd", MountPath: "/etc/breakglass-motd", ReadOnly: true}, c.Name)
		assert.Contains(t, c.Env, corev1.EnvVar{Name: "BREAKGLASS_RUNBOOK_URL", Value: runbook}, c.Name)
	}

	execIn := func(t *testing.T, container string, tty bool, stdin io.Reader, command ...string) string {
		t.Helper()
		request := kube.CoreV1().RESTClient().Post().Namespace(pod.Namespace).Resource("pods").Name(pod.Name).SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: container, Command: command, Stdin: stdin != nil, Stdout: true, Stderr: !tty, TTY: tty,
			}, scheme.ParameterCodec)
		executor, err := remotecommand.NewSPDYExecutor(config, http.MethodPost, request.URL())
		require.NoError(t, err)
		var stdout, stderr bytes.Buffer
		streamCtx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		options := remotecommand.StreamOptions{Stdin: stdin, Stdout: &stdout, Tty: tty}
		if !tty {
			options.Stderr = &stderr
		}
		require.NoError(t, executor.StreamWithContext(streamCtx, options), "%s %v: %s%s", container, command, stdout.String(), stderr.String())
		return strings.ReplaceAll(stdout.String(), "\r\n", "\n")
	}
	// Typed input, paced like a user: bash discards type-ahead that arrives
	// before readline starts.
	typed := func() io.Reader {
		reader, writer := io.Pipe()
		go func() {
			for _, line := range []string{"echo motd-prompt-$((40+2))", "sh -i", "exit", "exit"} {
				time.Sleep(2 * time.Second)
				_, _ = io.WriteString(writer, line+"\n")
			}
			time.Sleep(2 * time.Second)
			_ = writer.Close()
		}()
		return reader
	}

	for _, shell := range []struct{ container, shell string }{{"busybox", "sh"}, {"netshoot", "sh"}, {"netshoot", "bash"}} {
		t.Run(shell.container+"/"+shell.shell, func(t *testing.T) {
			out := execIn(t, shell.container, true, typed(), shell.shell)
			assert.Contains(t, out, "motd-prompt-42", "the shell must reach its prompt")
			assert.Contains(t, out, motd+"\nRunbook: "+runbook+"\n")
			assert.Equal(t, 1, strings.Count(out, "Runbook: "+runbook), "MOTD once per exec, not again in nested shells: %q", out)
			assert.Less(t, strings.Index(out, "Runbook: "), strings.Index(out, "motd-prompt-42"), "MOTD before the first command output")

			assert.Equal(t, "hi\n", execIn(t, shell.container, false, nil, shell.shell, "-c", "echo hi"))
			assert.Equal(t, "hi\n", execIn(t, shell.container, false, nil, shell.shell, "-ic", "echo hi"), "forced-interactive pipelines stay clean")
		})
	}
	assert.Equal(t, "hi\n", execIn(t, "netshoot", false, nil, "echo", "hi"), "kubectl exec <pod> -- echo hi prints only hi")
	assert.Equal(t, "hi\n", execIn(t, "busybox", true, nil, "echo", "hi"), "a TTY without a shell prints only the command output")
	assert.Contains(t, execIn(t, "busybox", false, nil, "sh", "-c", "touch /etc/breakglass-motd/x 2>&1 || true"), "Read-only file system")
}
