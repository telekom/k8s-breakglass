// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package job

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestCollectorExecutionRejectsMutations(t *testing.T) {
	config := testConfig(archive.SystemSummaryRecipe)
	config.MaxBytes = archive.MaxSystemSummaryArchiveBytes
	expected, err := Build(config)
	require.NoError(t, err)
	require.NoError(t, ValidateExecution(*expected, *expected))
	for name, mutate := range map[string]func(*batchv1.Job){
		"image":       func(j *batchv1.Job) { j.Spec.Template.Spec.InitContainers[0].Image = "evil" },
		"command":     func(j *batchv1.Job) { j.Spec.Template.Spec.Containers[0].Command = []string{"evil"} },
		"environment": func(j *batchv1.Job) { j.Spec.Template.Spec.Containers[0].Env[0].Value = "other" },
		"secret": func(j *batchv1.Job) {
			j.Spec.Template.Spec.Containers[0].Env = append(j.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "other"}, Key: "token"}}})
		},
		"mount":          func(j *batchv1.Job) { j.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath = "/evil" },
		"privilege":      func(j *batchv1.Job) { j.Spec.Template.Spec.Containers[0].SecurityContext.Privileged = boolPtr(true) },
		"hostPID":        func(j *batchv1.Job) { j.Spec.Template.Spec.HostPID = true },
		"serviceAccount": func(j *batchv1.Job) { j.Spec.Template.Spec.ServiceAccountName = "privileged" },
		"deadline":       func(j *batchv1.Job) { j.Spec.Template.Spec.ActiveDeadlineSeconds = int64Ptr(3600) },
		"retries":        func(j *batchv1.Job) { j.Spec.BackoffLimit = int32Ptr(100) },
		"sidecar": func(j *batchv1.Job) {
			j.Spec.Template.Spec.Containers = append(j.Spec.Template.Spec.Containers, corev1.Container{Name: "sidecar", Image: "evil"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := expected.DeepCopy()
			mutate(changed)
			require.Error(t, ValidateExecution(*changed, *expected))
		})
	}
}

func TestCollectorExecutionAcceptsRealAPIDefaults(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("envtest assets required")
	}
	environment := &envtest.Environment{}
	cfg, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))
	live, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	config := testConfig(archive.SystemSummaryRecipe)
	config.MaxBytes = archive.MaxSystemSummaryArchiveBytes
	expected, err := Build(config)
	require.NoError(t, err)
	expected.OwnerReferences = nil
	ctx := context.Background()
	require.NoError(t, live.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: expected.Namespace}}))
	actual := expected.DeepCopy()
	require.NoError(t, live.Create(ctx, actual))
	require.NoError(t, live.Get(ctx, client.ObjectKeyFromObject(actual), actual))
	require.NoError(t, ValidateExecution(*actual, *expected), "API-defaulted spec: %#v", actual.Spec)
	actual.Spec.Template.Spec.Containers[0].Image = "evil"
	require.Error(t, ValidateExecution(*actual, *expected))
}
