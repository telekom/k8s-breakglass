// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestInjectMOTDReplacesTemplateValues(t *testing.T) {
	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "shell", Env: []corev1.EnvVar{{Name: "KEEP", Value: "1"}, {Name: motdEnvName, Value: "spoofed"}}},
			{Name: "sidecar"},
		},
		InitContainers: []corev1.Container{{Name: "init"}},
	}
	injectMOTD(spec, &breakglassv1alpha1.MessageOfTheDay{Message: "Purpose: test\nTerminate: bgctl", RunbookURL: "https://example.com/rb#x"})

	hooks := []corev1.EnvVar{{Name: "ENV", Value: motdProfilePath}, {Name: "PROMPT_COMMAND", Value: ". " + motdProfilePath}}
	assert.Equal(t, append([]corev1.EnvVar{
		{Name: "KEEP", Value: "1"},
		{Name: motdEnvName, Value: "Purpose: test\nTerminate: bgctl"},
		{Name: runbookURLEnvName, Value: "https://example.com/rb#x"},
	}, hooks...), spec.Containers[0].Env)
	assert.Equal(t, append([]corev1.EnvVar{
		{Name: motdEnvName, Value: "Purpose: test\nTerminate: bgctl"},
		{Name: runbookURLEnvName, Value: "https://example.com/rb#x"},
	}, hooks...), spec.Containers[1].Env)
	assert.Empty(t, spec.InitContainers[0].Env, "init containers have no interactive shell")
	assert.Empty(t, spec.InitContainers[0].VolumeMounts)

	injectMOTD(spec, &breakglassv1alpha1.MessageOfTheDay{Message: "no link"})
	assert.Equal(t, append([]corev1.EnvVar{{Name: "KEEP", Value: "1"}, {Name: motdEnvName, Value: "no link"}}, hooks...), spec.Containers[0].Env,
		"a re-render without a runbook URL must not keep a stale one")
	assert.Len(t, spec.Volumes, 1, "re-injection must not duplicate the hook volume")
	assert.Len(t, spec.Containers[0].VolumeMounts, 1)
}

func TestInjectMOTDMountsReadOnlyShellHook(t *testing.T) {
	spec := &corev1.PodSpec{
		Containers: []corev1.Container{{
			Name: "shell",
			Env:  []corev1.EnvVar{{Name: "ENV", Value: "/custom/env"}, {Name: "BREAKGLASS_MOTD_SHOWN", Value: "1"}},
			VolumeMounts: []corev1.VolumeMount{
				{Name: "data", MountPath: "/data"},
				{Name: "spoof", MountPath: motdMountPath},
			},
			SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: ptrTo(true)},
		}},
		Volumes: []corev1.Volume{{Name: "data"}, {Name: motdVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
	}
	injectMOTD(spec, &breakglassv1alpha1.MessageOfTheDay{Message: "m"})
	injectMOTD(spec, &breakglassv1alpha1.MessageOfTheDay{Message: "m"})

	c := spec.Containers[0]
	assert.Contains(t, c.Env, corev1.EnvVar{Name: "ENV", Value: "/custom/env"}, "a template ENV is kept")
	assert.NotContains(t, c.Env, corev1.EnvVar{Name: "ENV", Value: motdProfilePath})
	assert.Contains(t, c.Env, corev1.EnvVar{Name: "PROMPT_COMMAND", Value: ". " + motdProfilePath})
	assert.NotContains(t, c.Env, corev1.EnvVar{Name: "BREAKGLASS_MOTD_SHOWN", Value: "1"}, "templates cannot suppress the MOTD")
	assert.Equal(t, []corev1.VolumeMount{
		{Name: "data", MountPath: "/data"},
		{Name: motdVolumeName + "-1", MountPath: motdMountPath, ReadOnly: true},
	}, c.VolumeMounts)
	require.Len(t, spec.Volumes, 3, "re-injection reuses the hook volume")
	assert.Equal(t, "data", spec.Volumes[0].Name)
	assert.Equal(t, corev1.Volume{Name: motdVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}, spec.Volumes[1], "a template volume with the reserved name is kept")
	hook := spec.Volumes[2]
	assert.Equal(t, motdVolumeName+"-1", hook.Name)
	require.NotNil(t, hook.DownwardAPI, "downward API volumes are allowed by restricted Pod Security")
	require.Len(t, hook.DownwardAPI.Items, 1)
	assert.Equal(t, motdProfileFile, hook.DownwardAPI.Items[0].Path)
	assert.Equal(t, "metadata.annotations['"+motdProfileAnnotation+"']", hook.DownwardAPI.Items[0].FieldRef.FieldPath)
}

func ptrTo[T any](v T) *T { return &v }

// TestMOTDProfileScriptInShells runs the hook the way interactive exec shells
// do: POSIX sh, dash and ash through ENV, bash through PROMPT_COMMAND, with
// stdout on a terminal as with kubectl exec -it.
func TestMOTDProfileScriptInShells(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, motdProfileFile)
	require.NoError(t, os.WriteFile(profile, []byte(motdProfileScript), 0o444))
	motdEnv := []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + dir,
		"BREAKGLASS_MOTD=Purpose: diag\nTerminate: bgctl",
		"BREAKGLASS_RUNBOOK_URL=https://example.com/rb#x",
		"ENV=" + profile, "PROMPT_COMMAND=. " + profile,
	}
	run := func(t *testing.T, tty bool, env []string, name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Env = env
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader("sh -i </dev/null\nexit\n")
		if !tty {
			out, err := cmd.Output()
			require.NoError(t, err)
			return string(out)
		}
		master, slave := openTestPTY(t)
		defer master.Close()
		cmd.Stdout = slave
		require.NoError(t, cmd.Start())
		require.NoError(t, slave.Close())
		read := make(chan string, 1)
		go func() {
			out, _ := io.ReadAll(master) // EIO once the shell closed the terminal
			read <- strings.ReplaceAll(string(out), "\r\n", "\n")
		}()
		require.NoError(t, cmd.Wait())
		return <-read
	}
	shells := map[string][]string{"sh": {"-i"}, "dash": {"-i"}, "bash": {"--norc", "--noprofile", "-i"}, "busybox": {"sh", "-i"}}
	found := 0
	for name, args := range shells {
		if _, err := exec.LookPath(name); err != nil {
			continue
		}
		found++
		nonInteractive := append(args[:len(args)-1:len(args)-1], "-c", "echo scripted")
		t.Run(name, func(t *testing.T) {
			out := run(t, false, motdEnv, name, nonInteractive...)
			assert.Equal(t, "scripted\n", out, "non-interactive exec commands must not print the MOTD")

			out = run(t, false, motdEnv, name, args...)
			assert.NotContains(t, out, "Runbook:", "an interactive shell whose stdout is not a terminal must not print the MOTD")

			out = run(t, false, motdEnv, name, append(slices.Clone(args), "-c", "echo scripted")...)
			assert.True(t, strings.HasSuffix(out, "scripted\n"), out)
			assert.NotContains(t, out, "Runbook:", "forced-interactive pipelines (sh -ic cmd > file) must stay clean")

			out = run(t, true, motdEnv, name, args...)
			assert.Equal(t, 1, strings.Count(out, "Runbook: https://example.com/rb#x"), "printed exactly once, also with nested shells: %q", out)
			assert.Contains(t, out, "Purpose: diag\nTerminate: bgctl\n")

			out = run(t, true, append(slices.Clone(motdEnv), "BREAKGLASS_MOTD="), name, args...)
			assert.NotContains(t, out, "Runbook:", "no MOTD, no banner")
		})
	}
	if found == 0 {
		t.Skip("no POSIX shell available")
	}
}

func TestInjectMOTDWithoutMOTDKeepsSpec(t *testing.T) {
	spec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "shell"}}}
	injectMOTD(spec, nil)
	injectMOTD(nil, &breakglassv1alpha1.MessageOfTheDay{Message: "x"})
	assert.Empty(t, spec.Containers[0].Env)
}

func TestTemplateAndBindingResponsesExposeEffectiveMOTD(t *testing.T) {
	templateMOTD := &breakglassv1alpha1.MessageOfTheDay{Message: "template", RunbookURL: "https://example.com/rb#template"}
	bindingMOTD := &breakglassv1alpha1.MessageOfTheDay{Message: "persona", RunbookURL: "https://example.com/rb#persona"}
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{MOTD: templateMOTD}}
	withMOTD := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "persona", Namespace: "ns"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{MOTD: bindingMOTD}}
	withoutMOTD := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "ns"}}
	controller := &DebugSessionAPIController{log: zaptest.NewLogger(t).Sugar()}

	resp := controller.buildTemplateResponse(template, debugTemplateRequester{}, nil, 0, nil)
	assert.Equal(t, templateMOTD, resp.MOTD)
	payload, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.Contains(t, string(payload), `"motd":{"message":"template","runbookURL":"https://example.com/rb#template"}`)

	detail := controller.buildClusterDetailWithBindings(template, []*breakglassv1alpha1.DebugSessionClusterBinding{withMOTD, withoutMOTD}, &breakglassv1alpha1.ClusterConfig{}, debugTemplateRequester{})
	require.Len(t, detail.BindingOptions, 2)
	assert.Equal(t, bindingMOTD, detail.MOTD)
	assert.Equal(t, bindingMOTD, detail.BindingOptions[0].MOTD)
	assert.Equal(t, templateMOTD, detail.BindingOptions[1].MOTD)

	direct := controller.buildClusterDetailWithBindings(template, nil, &breakglassv1alpha1.ClusterConfig{}, debugTemplateRequester{})
	assert.Equal(t, templateMOTD, direct.MOTD)
}

func TestBuildWorkloadExportsEffectiveMOTD(t *testing.T) {
	for name, manifest := range map[string]string{
		"Pod": `apiVersion: v1
kind: Pod
spec:
  restartPolicy: Never
  containers:
    - name: debug
      image: busybox
`,
		"Job": `apiVersion: batch/v1
kind: Job
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: debug
          image: busybox
`,
	} {
		t.Run(name, func(t *testing.T) {
			controller, session, template, _ := newDeploymentFenceFixture(t)
			session.UID = "session-uid"
			template.Spec.WorkloadType = breakglassv1alpha1.DebugWorkloadJob
			template.Spec.PodTemplateString = ""
			template.Spec.MOTD = &breakglassv1alpha1.MessageOfTheDay{Message: "template", RunbookURL: "https://example.com/rb#template"}
			binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				MOTD: &breakglassv1alpha1.MessageOfTheDay{Message: "logs-only job", RunbookURL: "https://example.com/rb#job"},
			}}
			podTemplate := &breakglassv1alpha1.DebugPodTemplate{Spec: breakglassv1alpha1.DebugPodTemplateSpec{TemplateString: manifest}}
			workload, _, err := controller.buildWorkload(session, template, binding, podTemplate, "target")
			require.NoError(t, err)
			job, ok := workload.(*batchv1.Job)
			require.True(t, ok)
			assert.Contains(t, job.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{Name: motdEnvName, Value: "logs-only job"})
			assert.Contains(t, job.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{Name: runbookURLEnvName, Value: "https://example.com/rb#job"})
			assert.Equal(t, motdProfileScript, job.Spec.Template.Annotations[motdProfileAnnotation], "the downward API volume reads the hook from the pod template")
			assert.Contains(t, job.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: motdVolumeName, MountPath: motdMountPath, ReadOnly: true})
		})
	}
}

func TestBuildWorkloadMOTDKeepsReservedTemplateVolume(t *testing.T) {
	controller, session, template, _ := newDeploymentFenceFixture(t)
	session.UID = "session-uid"
	template.Spec.WorkloadType = breakglassv1alpha1.DebugWorkloadJob
	template.Spec.PodTemplateString = ""
	template.Spec.MOTD = &breakglassv1alpha1.MessageOfTheDay{Message: "template"}
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{Spec: breakglassv1alpha1.DebugPodTemplateSpec{TemplateString: `apiVersion: batch/v1
kind: Job
spec:
  template:
    spec:
      restartPolicy: Never
      initContainers:
        - name: seed
          image: busybox
          volumeMounts:
            - name: breakglass-motd
              mountPath: /seed
      containers:
        - name: debug
          image: busybox
          volumeMounts:
            - name: breakglass-motd
              mountPath: /data
      volumes:
        - name: breakglass-motd
          emptyDir: {}
`}}
	workload, _, err := controller.buildWorkload(session, template, nil, podTemplate, "target")
	require.NoError(t, err)
	job, ok := workload.(*batchv1.Job)
	require.True(t, ok)
	spec := job.Spec.Template.Spec
	assert.Contains(t, spec.Volumes, corev1.Volume{Name: motdVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}, "the template volume is not replaced")
	assert.Equal(t, []corev1.VolumeMount{{Name: motdVolumeName, MountPath: "/seed"}}, spec.InitContainers[0].VolumeMounts)
	assert.Contains(t, spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: motdVolumeName, MountPath: "/data"})
	assertMOTDHook(t, spec.Containers[0], "template", motdVolumeName+"-1")
	assert.True(t, slices.ContainsFunc(spec.Volumes, func(v corev1.Volume) bool { return v.Name == motdVolumeName+"-1" && v.DownwardAPI != nil }))
}

func motdKubectlSession(name string, kd *breakglassv1alpha1.KubectlDebugConfig, bindingMOTD *breakglassv1alpha1.MessageOfTheDay) *breakglassv1alpha1.DebugSession {
	expiresAt := metav1.NewTime(time.Now().UTC().Add(time.Hour))
	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", UID: types.UID(name + "-uid")},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster", RequestedBy: "operator@example.com"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expiresAt,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode:            breakglassv1alpha1.DebugSessionModeKubectlDebug,
				TargetNamespace: "breakglass-debug",
				KubectlDebug:    kd,
				MOTD:            &breakglassv1alpha1.MessageOfTheDay{Message: "template motd"},
			},
		},
	}
	if bindingMOTD != nil {
		raw, _ := json.Marshal(breakglassv1alpha1.DebugSessionClusterBindingSpec{MOTD: bindingMOTD})
		ds.Status.ResolvedBindingSpec = &apiextensionsv1.JSON{Raw: raw}
	}
	return ds
}

func assertMOTDHook(t *testing.T, c corev1.Container, motd, volume string) {
	t.Helper()
	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
	}
	assert.Equal(t, motd, env[motdEnvName])
	assert.Equal(t, motdProfilePath, env["ENV"])
	assert.Contains(t, c.VolumeMounts, corev1.VolumeMount{Name: volume, MountPath: motdMountPath, ReadOnly: true})
}

func TestNodeDebugPodGetsSessionMOTD(t *testing.T) {
	scheme := newKubectlTestScheme()
	runbook := &breakglassv1alpha1.MessageOfTheDay{Message: "binding motd", RunbookURL: "https://example.com/rb#node"}
	session := motdKubectlSession("node-motd-session", &breakglassv1alpha1.KubectlDebugConfig{NodeDebug: &breakglassv1alpha1.NodeDebugConfig{Enabled: true}}, runbook)
	hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-debug", UID: "namespace-uid"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1", UID: "node-uid"}},
	).Build()
	handler := newTestKubectlDebugHandler(hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

	pod, err := handler.CreateNodeDebugPod(context.Background(), session, "worker-1", "operator@example.com")
	require.NoError(t, err)
	assert.Equal(t, motdProfileScript, pod.Annotations[motdProfileAnnotation])
	assert.Equal(t, string(session.UID), pod.Annotations[sourceSessionUIDAnnotation])
	require.Len(t, pod.Spec.Containers, 1)
	assertMOTDHook(t, pod.Spec.Containers[0], "binding motd", motdVolumeName)
	assert.Contains(t, pod.Spec.Containers[0].Env, corev1.EnvVar{Name: runbookURLEnvName, Value: runbook.RunbookURL})
	assert.True(t, slices.ContainsFunc(pod.Spec.Volumes, func(v corev1.Volume) bool { return v.Name == motdVolumeName && v.DownwardAPI != nil }))
}

func TestPodCopyMOTDOnlyInDebugger(t *testing.T) {
	scheme := newKubectlTestScheme()
	session := motdKubectlSession("copy-motd-session", &breakglassv1alpha1.KubectlDebugConfig{
		PodCopy: &breakglassv1alpha1.PodCopyConfig{Enabled: true, TargetNamespace: "debug-copies", TTL: "1h"},
	}, nil)
	sourcePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "production", UID: "pod-app-uid"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app", Image: "myapp:v1", Env: []corev1.EnvVar{{Name: "ENV", Value: "production"}},
				VolumeMounts: []corev1.VolumeMount{{Name: motdVolumeName, MountPath: "/etc/app"}},
			}},
			Volumes: []corev1.Volume{{Name: motdVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
		},
	}
	otherPod := sourcePod.DeepCopy()
	otherPod.Name, otherPod.UID = "other-pod", "pod-other-uid"
	targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sourcePod, otherPod,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "debug-copies", UID: "debug-copies-uid"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
	).Build()
	hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	handler := newTestKubectlDebugHandler(hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

	pod, err := handler.CreatePodCopy(context.Background(), session, "production", "app-pod", "busybox:latest", "operator@example.com")
	require.NoError(t, err)
	require.Len(t, pod.Spec.Containers, 2)
	assert.Equal(t, sourcePod.Spec.Containers[0], pod.Spec.Containers[0], "copied application containers stay unchanged")
	assertMOTDHook(t, pod.Spec.Containers[1], "template motd", motdVolumeName+"-1")
	assert.Equal(t, motdProfileScript, pod.Annotations[motdProfileAnnotation])
	assert.Contains(t, pod.Spec.Volumes, sourcePod.Spec.Volumes[0], "copied application volumes stay unchanged")
	assert.True(t, slices.ContainsFunc(pod.Spec.Volumes, func(v corev1.Volume) bool { return v.Name == motdVolumeName+"-1" && v.DownwardAPI != nil }))

	noImage, err := handler.CreatePodCopy(context.Background(), session, "production", "other-pod", "", "operator@example.com")
	require.NoError(t, err)
	assert.NotContains(t, noImage.Annotations, motdProfileAnnotation)
	assert.Equal(t, sourcePod.Spec.Volumes, noImage.Spec.Volumes)
}

func TestSessionMOTDRejectsCorruptBindingSnapshot(t *testing.T) {
	ds := motdKubectlSession("bad", nil, nil)
	ds.Status.ResolvedBindingSpec = &apiextensionsv1.JSON{Raw: []byte("{")}
	_, err := sessionMOTD(ds)
	require.Error(t, err)
	motd, err := sessionMOTD(&breakglassv1alpha1.DebugSession{})
	require.NoError(t, err)
	assert.Nil(t, motd)
}
