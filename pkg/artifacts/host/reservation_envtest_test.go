// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	artifactcontroller "github.com/telekom/k8s-breakglass/pkg/artifacts/controller"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/kube"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func TestArtifactReservationRealAPIAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("envtest assets required")
	}
	environment := &envtest.Environment{CRDDirectoryPaths: []string{"../../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	config, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))
	require.NoError(t, rbacv1.AddToScheme(scheme))
	live, err := client.New(config, client.Options{Scheme: scheme})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, live.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "controller"}}))
	repository, err := kube.NewRepositoryInNamespace(live, "controller")
	require.NoError(t, err)
	service, _, _, keys, now, _ := lifecycleFixture(t)
	reservation, err := service.Reserve(ctx, lifecycleRecord(*now))
	require.NoError(t, err)
	reservation.ArtifactUID = ""
	reservation.ResourceVersion = ""
	persisted, err := repository.Create(ctx, reservation)
	require.NoError(t, err)
	require.NotEmpty(t, persisted.ArtifactUID)
	require.Equal(t, reservation.ReservationNonce, persisted.ReservationNonce)
	var object breakglassv1alpha1.DebugSessionArtifact
	require.NoError(t, live.Get(ctx, client.ObjectKey{Namespace: "controller", Name: persisted.ArtifactID}, &object))
	object.Spec.ReservationNonce = "0123456789abcdef0123456789abcdef"
	require.Error(t, live.Update(ctx, &object), "immutable reservation nonce must reject mutation")
	recording := lifecycleRecord(*now)
	// The actual terminal route supplies no collector metadata policy.
	recording.Expected.RedactionProfile = ""
	recording.Expected.RedactionVersion = 0
	recording.Recording = &backend.RecordingMetadata{FormatVersion: 1, StartedAt: *now, StreamExpiresAt: now.Add(time.Minute), PodNamespace: "target", PodName: "debug", PodUID: "pod-uid", Operation: "exec", LeaseUID: "lease-uid", LeaseEpoch: "1", Generation: "1"}
	reservedRecording, err := service.ReserveRecording(ctx, recording, func(context.Context) error { return nil })
	require.NoError(t, err)
	reservedRecording.ArtifactUID = ""
	reservedRecording.ResourceVersion = ""
	realRecording, err := repository.Create(ctx, reservedRecording)
	require.NoError(t, err)
	require.Equal(t, "pod-uid", realRecording.Recording.PodUID)
	require.Equal(t, backend.TerminalRecordingRecipe, realRecording.Expected.RedactionProfile)
	require.Equal(t, 1, realRecording.Expected.RedactionVersion)
	require.NoError(t, live.Get(ctx, client.ObjectKey{Namespace: "controller", Name: realRecording.ArtifactID}, &object))
	object.Spec.Recording.PodUID = "replacement"
	require.Error(t, live.Update(ctx, &object), "recording target capability must remain immutable")

	t.Run("controller starts without hub Job permissions", func(t *testing.T) {
		role := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "artifact-controller-test"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{breakglassv1alpha1.GroupVersion.Group}, Resources: []string{"debugsessionartifacts"}, Verbs: []string{"get", "list", "watch", "update", "patch"}}},
		}
		require.NoError(t, live.Create(ctx, role))
		require.NoError(t, live.Create(ctx, &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: role.Name},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
			Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "User", Name: role.Name}},
		}))
		restricted := rest.CopyConfig(config)
		restricted.Impersonate = rest.ImpersonationConfig{UserName: role.Name, Groups: []string{"system:authenticated"}}
		manager, err := ctrl.NewManager(restricted, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0"})
		require.NoError(t, err)
		require.True(t, apierrors.IsForbidden(manager.GetAPIReader().List(ctx, &batchv1.JobList{})))
		reconciler := &artifactcontroller.Reconciler{
			Client: manager.GetClient(), LiveReader: live, Service: service,
			TokenIssuer:     &uploadTokenIssuer{keyring: keys, now: func() time.Time { return *now }},
			ClusterProvider: lifecycleTarget{client: live}, Now: func() time.Time { return *now },
		}
		require.NoError(t, reconciler.SetupWithManager(manager))
		managerCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- manager.Start(managerCtx) }()
		t.Cleanup(func() {
			cancel()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Error("artifact manager did not stop")
			}
		})
		require.Eventually(t, func() bool {
			var current breakglassv1alpha1.DebugSessionArtifact
			return live.Get(ctx, client.ObjectKey{Namespace: "controller", Name: realRecording.ArtifactID}, &current) == nil && len(current.Finalizers) > 0
		}, 15*time.Second, 100*time.Millisecond, "artifact reconciler must process reservations without watching hub Jobs")
	})
}
