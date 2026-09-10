package debug

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestConnectionLeaseAcquireValidateRecreateFencesOldReference(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	service := NewConnectionLeaseService(client)
	proof := ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)}
	ref, err := service.Acquire(ctx, proof)
	require.NoError(t, err)
	require.NoError(t, service.Validate(ctx, ref, 0))
	refB, err := service.Acquire(ctx, ConnectionLeaseProof{Namespace: proof.Namespace, SessionUID: "session-b", TargetUID: proof.TargetUID, ProfileDigest: proof.ProfileDigest, ExpiresAt: proof.ExpiresAt})
	require.NoError(t, err)
	require.NoError(t, service.Revoke(ctx, ref))
	require.NoError(t, service.Revoke(ctx, refB))
	newRef, err := service.Acquire(ctx, ConnectionLeaseProof{Namespace: proof.Namespace, SessionUID: "session-b", TargetUID: proof.TargetUID, ProfileDigest: proof.ProfileDigest, ExpiresAt: proof.ExpiresAt})
	require.NoError(t, err)
	require.NotEqual(t, ref.HolderUID, newRef.HolderUID)
	require.Error(t, service.Validate(ctx, ref, 0), "deleted/recreated lease must reject old incarnation")
}

func TestConnectionLeaseExpiredCannotBeAcquiredByDifferentSession(t *testing.T) {
	ctx := context.Background()
	old := metav1.NewMicroTime(time.Now().Add(-2 * time.Second))
	d := int32(1)
	proof := ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)}
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: connectionLeaseName(proof), Namespace: "controller", Annotations: map[string]string{connectionLeaseEpochAnnotation: "3", connectionLeaseTargetUIDAnnotation: "cluster-a", connectionLeaseProfileAnnotation: "sha256:a", connectionLeaseSessionAnnotation: "session-a", connectionLeaseGenerationAnnotation: "0"}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: connPtr("session-a"), RenewTime: &old, LeaseDurationSeconds: &d}}
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lease).Build()
	service := NewConnectionLeaseService(client)
	_, err := service.Acquire(ctx, ConnectionLeaseProof{Namespace: "controller", SessionUID: types.UID("session-b"), TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)})
	require.NoError(t, err)
}

func TestConnectionLeaseExpiredSameSessionAdvancesEpoch(t *testing.T) {
	ctx := context.Background()
	proof := ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)}
	old := metav1.NewMicroTime(time.Now().Add(-2 * time.Second))
	d := int32(1)
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: connectionLeaseName(proof), Namespace: proof.Namespace, Annotations: map[string]string{connectionLeaseEpochAnnotation: "3", connectionLeaseTargetUIDAnnotation: string(proof.TargetUID), connectionLeaseProfileAnnotation: proof.ProfileDigest, connectionLeaseSessionAnnotation: string(proof.SessionUID), connectionLeaseGenerationAnnotation: "0"}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: connPtr(string(proof.SessionUID)), RenewTime: &old, LeaseDurationSeconds: &d}}
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lease).Build()
	ref, err := NewConnectionLeaseService(client).Acquire(ctx, proof)
	require.NoError(t, err)
	require.Equal(t, int64(4), ref.Epoch)
	require.NoError(t, NewConnectionLeaseService(client).Validate(ctx, ref, -1))
}

func TestConnectionLeaseStaleRevokeCannotDeleteTakeover(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	service := NewConnectionLeaseService(client)
	proof := ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)}
	ref, err := service.Acquire(ctx, proof)
	require.NoError(t, err)
	lease := &coordinationv1.Lease{}
	require.NoError(t, client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, lease))
	lease.Spec.HolderIdentity = connPtr("session-b")
	lease.Annotations[connectionLeaseEpochAnnotation] = "2"
	require.NoError(t, client.Update(ctx, lease))
	require.Error(t, service.Revoke(ctx, ref))
	remaining := &coordinationv1.Lease{}
	require.NoError(t, client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, remaining))
	require.Equal(t, "session-b", *remaining.Spec.HolderIdentity)
}

func TestConnectionLeaseGenerationRequiresReadinessAndKeepsSecretsOpaque(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	service := NewConnectionLeaseService(client)
	ref, err := service.Acquire(ctx, ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)})
	require.NoError(t, err)
	staged, err := service.StageGeneration(ctx, ref, 1)
	require.NoError(t, err)
	_, err = service.PublishReady(ctx, staged, nil)
	require.Error(t, err)
	published, err := service.PublishReady(ctx, staged, func(context.Context) (types.UID, error) { return "secret-uid", nil })
	require.NoError(t, err)
	require.Equal(t, types.UID("secret-uid"), published.SecretUID)
	staged, err = service.StageGeneration(ctx, published.Lease, 2)
	require.NoError(t, err)
	_, err = service.PublishReady(ctx, staged, func(ctx context.Context) (types.UID, error) {
		return "", service.Revoke(ctx, published.Lease)
	})
	require.Error(t, err)
}
