// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	artifactkube "github.com/telekom/k8s-breakglass/pkg/artifacts/kube"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/token"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
	"github.com/telekom/k8s-breakglass/pkg/config"
)

func TestBuildDisabledDoesNotReadOrRequireHostDependencies(t *testing.T) {
	components, err := Build(context.Background(), config.Artifacts{}, "not-a-namespace", Dependencies{})
	require.NoError(t, err)
	require.Nil(t, components)
}

func TestLoadKeyringReadsOnlyConfiguredNamespaceAndEnforcesKeyFloor(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tokens", Namespace: "breakglass"}, Data: map[string][]byte{"old": make([]byte, 32), "new": make([]byte, 32)}}).Build()
	keyring, err := loadKeyring(context.Background(), client, "breakglass", "tokens", "new", "https://breakglass.example")
	require.NoError(t, err)
	_, err = keyring.Sign(tokenClaimsForTest())
	require.Error(t, err)
	_, err = loadKeyring(context.Background(), client, "other", "tokens", "new", "https://breakglass.example")
	require.Error(t, err)
}

func TestOpenStoreRejectsMixedBackendsAndCrossNamespaceCredentials(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s3-creds", Namespace: "other"}, Data: map[string][]byte{"accessKeyID": []byte("access"), "secretAccessKey": []byte("secret")}}).Build()
	cfg := config.Artifacts{Backend: "s3", UploadMaxBytes: 1024, S3: &config.ArtifactS3{Region: "eu-central-1", Bucket: "breakglass-artifacts", InstanceID: "instance-0123456789", RequireVersioned: true, CredentialsSecretName: "s3-creds"}, Local: &config.ArtifactLocal{ArtifactRoot: "/a", StagingRoot: "/b"}}
	_, _, err := openStore(context.Background(), cfg, client, "breakglass")
	require.Error(t, err)
	cfg.Local = nil
	_, _, err = openStore(context.Background(), cfg, client, "breakglass")
	require.Error(t, err)
}

func TestConnectionLeaseFenceChecksLiveLeaseIdentity(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	now := time.Now().UTC()
	leaseUID := types.UID("lease-uid")
	targetUID := types.UID("target-uid")
	holderUID := types.UID("session-uid")
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "breakglass", UID: holderUID},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: ptrTime(metav1.NewTime(now.Add(time.Minute))),
			ConnectionLease: &breakglassv1alpha1.DebugSessionConnectionLease{
				Namespace: "breakglass", Name: "connection", UID: leaseUID, HolderUID: holderUID,
				TargetUID: targetUID, ProfileDigest: "sha256:profile", Epoch: 4,
				ExpiresAt: metav1.NewTime(now.Add(time.Minute)),
			},
		},
	}
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: "connection", Namespace: "breakglass", UID: leaseUID, Annotations: map[string]string{
			"breakglass.telekom.com/connection-epoch":          "4",
			"breakglass.telekom.com/connection-target-uid":     string(targetUID),
			"breakglass.telekom.com/connection-profile-digest": "sha256:profile",
		}},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: ptrString(string(holderUID)), LeaseDurationSeconds: ptrInt32(60), RenewTime: ptrMicroTime(metav1.NewMicroTime(now))},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session, lease).Build()
	service := debug.NewConnectionLeaseService(client).WithLiveReader(client)
	fence := NewConnectionLeaseFence(client, service)
	binding := backend.SessionBinding{Namespace: "breakglass", Name: "session", UID: string(holderUID), TargetClusterUID: string(targetUID), TargetIdentityDigest: strings.Repeat("a", 64), OperationEpoch: 4, ConnectionLeaseUID: "lease-uid"}
	require.NoError(t, fence.AuthorizeArtifact(context.Background(), binding))
	binding.TargetClusterUID = "other-target"
	require.ErrorIs(t, fence.AuthorizeArtifact(context.Background(), binding), backend.ErrForbidden)
	binding.TargetClusterUID = string(targetUID)
	deletingReader := &markDeletingSessionReader{Reader: client, always: true}
	deletingService := debug.NewConnectionLeaseService(client).WithLiveReader(deletingReader)
	deletingFence := NewConnectionLeaseFence(deletingReader, deletingService)
	require.ErrorIs(t, deletingFence.AuthorizeArtifact(context.Background(), binding), backend.ErrForbidden)

	lateClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session.DeepCopy(), lease.DeepCopy()).Build()
	lateReader := &markDeletingSessionReader{Reader: lateClient}
	lateService := debug.NewConnectionLeaseService(lateClient).WithLiveReader(lateReader)
	lateFence := NewConnectionLeaseFence(lateReader, lateService)
	require.ErrorIs(t, lateFence.AuthorizeArtifact(context.Background(), binding), backend.ErrForbidden)
	// Recreating the same lease with an equal epoch must not revive old artifact authority.
	require.NoError(t, client.Delete(context.Background(), lease))
	replacement := lease.DeepCopy()
	replacement.UID = "replacement-lease"
	replacement.ResourceVersion = ""
	require.NoError(t, client.Create(context.Background(), replacement))
	require.NoError(t, client.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), session))
	session.Status.ConnectionLease.UID = replacement.UID
	require.NoError(t, client.Update(context.Background(), session))
	require.ErrorIs(t, fence.AuthorizeArtifact(context.Background(), binding), backend.ErrForbidden)
	binding.ConnectionLeaseUID = string(replacement.UID)
	require.NoError(t, fence.AuthorizeArtifact(context.Background(), binding))
}

type markDeletingSessionReader struct {
	ctrlclient.Reader
	always    bool
	leaseSeen bool
}

func (reader *markDeletingSessionReader) Get(ctx context.Context, key types.NamespacedName, object ctrlclient.Object, options ...ctrlclient.GetOption) error {
	if err := reader.Reader.Get(ctx, key, object, options...); err != nil {
		return err
	}
	if _, isLease := object.(*coordinationv1.Lease); isLease {
		reader.leaseSeen = true
	}
	if session, isSession := object.(*breakglassv1alpha1.DebugSession); isSession && (reader.always || reader.leaseSeen) {
		session.DeletionTimestamp = ptrTime(metav1.Now())
	}
	return nil
}

func TestRepositoryBindingSourceUsesImmutableArtifactBinding(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	object := &breakglassv1alpha1.DebugSessionArtifact{
		ObjectMeta: metav1.ObjectMeta{Name: "dsa-0123456789abcdef01234567", Namespace: "artifact-system"},
		Spec: breakglassv1alpha1.DebugSessionArtifactSpec{
			ArtifactID:       "dsa-0123456789abcdef01234567",
			SessionRef:       breakglassv1alpha1.ArtifactSessionReference{Namespace: "sessions", Name: "session", UID: "session-uid"},
			TargetClusterUID: "target-uid", TargetIdentityDigest: strings.Repeat("b", 64), OperationEpoch: 7,
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(object).Build()
	repository, err := artifactkube.NewRepositoryInNamespace(client, "artifact-system")
	require.NoError(t, err)
	source := repositoryBindingSource{repository: repository}
	binding, err := source.ResolveArtifactBinding(context.Background(), "sessions", "session", object.Spec.ArtifactID)
	require.NoError(t, err)
	require.Equal(t, backend.SessionBinding{Namespace: "sessions", Name: "session", UID: "session-uid", TargetClusterUID: "target-uid", TargetIdentityDigest: strings.Repeat("b", 64), OperationEpoch: 7}, binding)
	_, err = source.ResolveArtifactBinding(context.Background(), "sessions", "other-session", object.Spec.ArtifactID)
	require.ErrorIs(t, err, backend.ErrForbidden)
}

func ptrTime(value metav1.Time) *metav1.Time                { return &value }
func ptrString(value string) *string                        { return &value }
func ptrInt32(value int32) *int32                           { return &value }
func ptrMicroTime(value metav1.MicroTime) *metav1.MicroTime { return &value }

func tokenClaimsForTest() token.Claims {
	return token.Claims{Method: "PUT", Route: "/api/debugSessionArtifactUploads/ns/session/dsa-0123456789abcdef01234567", SessionNamespace: "ns", SessionName: "session", SessionUID: "uid", ArtifactID: "dsa-0123456789abcdef01234567", ArtifactPlanDigest: strings.Repeat("a", 64), RuntimeBindingDigest: strings.Repeat("b", 64), TargetIdentityDigest: strings.Repeat("c", 64), OperationEpoch: 1, Recipe: "system-summary.v1", RecipeVersion: 1, JTI: "AAAAAAAAAAAAAAAAAAAAAA"}
}

func TestArtifactSessionFenceHonorsExactIdleBoundary(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	start, expiry := metav1.NewTime(now.Add(-time.Minute)), metav1.NewTime(now.Add(time.Hour))
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{UID: "session-uid"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, StartsAt: &start, ExpiresAt: &expiry, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "1m"}}}}
	binding := backend.SessionBinding{UID: "session-uid"}
	require.True(t, artifactSessionIsLive(session, binding, now.Add(-time.Nanosecond)))
	require.False(t, artifactSessionIsLive(session, binding, now))
	session.Status.ResolvedTemplate.Constraints.IdleTimeout = ""
	require.True(t, artifactSessionIsLive(session, binding, now))
}
