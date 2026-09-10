package debug

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// fake clients do not allocate Kubernetes UIDs. Real lease capabilities always
// carry one, so make the test client model that API-server behavior.
type leaseUIDClient struct{ ctrlclient.Client }

func (c *leaseUIDClient) Create(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
	if lease, ok := obj.(*coordinationv1.Lease); ok && lease.UID == "" {
		lease.UID = types.UID("uid-" + lease.Name)
	}
	return c.Client.Create(ctx, obj, opts...)
}

func newLeaseClient(builder *fake.ClientBuilder) ctrlclient.Client {
	return &leaseUIDClient{Client: builder.Build()}
}

type delayedLeaseReader struct {
	ctrlclient.Reader
	delay time.Duration
	gets  int
}

func (r *delayedLeaseReader) Get(ctx context.Context, key types.NamespacedName, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
	r.gets++
	time.Sleep(r.delay)
	return r.Reader.Get(ctx, key, obj, opts...)
}

func TestConnectionLeaseAcquireValidateRecreateFencesOldReference(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
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
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: connectionLeaseName(proof), Namespace: "controller", UID: "uid-seeded", Annotations: map[string]string{connectionLeaseEpochAnnotation: "3", connectionLeaseTargetUIDAnnotation: "cluster-a", connectionLeaseProfileAnnotation: "sha256:a", connectionLeaseSessionAnnotation: "session-a", connectionLeaseGenerationAnnotation: "0"}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: connPtr("session-a"), RenewTime: &old, LeaseDurationSeconds: &d}}
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme).WithObjects(lease))
	service := NewConnectionLeaseService(client)
	_, err := service.Acquire(ctx, ConnectionLeaseProof{Namespace: "controller", SessionUID: types.UID("session-b"), TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)})
	require.NoError(t, err)
}

func TestConnectionLeaseExpiredSameSessionAdvancesEpoch(t *testing.T) {
	ctx := context.Background()
	proof := ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)}
	old := metav1.NewMicroTime(time.Now().Add(-2 * time.Second))
	d := int32(1)
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: connectionLeaseName(proof), Namespace: proof.Namespace, UID: "uid-seeded", Annotations: map[string]string{connectionLeaseEpochAnnotation: "3", connectionLeaseTargetUIDAnnotation: string(proof.TargetUID), connectionLeaseProfileAnnotation: proof.ProfileDigest, connectionLeaseSessionAnnotation: string(proof.SessionUID), connectionLeaseGenerationAnnotation: "0"}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: connPtr(string(proof.SessionUID)), RenewTime: &old, LeaseDurationSeconds: &d}}
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme).WithObjects(lease))
	ref, err := NewConnectionLeaseService(client).Acquire(ctx, proof)
	require.NoError(t, err)
	require.Equal(t, int64(4), ref.Epoch)
	require.NoError(t, NewConnectionLeaseService(client).Validate(ctx, ref, -1))
}

func TestConnectionLeaseStaleRevokeCannotDeleteTakeover(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
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

func TestConnectionLeaseRenewRejectsExpiredLease(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
	service := NewConnectionLeaseService(client)
	proof := ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)}
	ref, err := service.Acquire(ctx, proof)
	require.NoError(t, err)
	lease := &coordinationv1.Lease{}
	require.NoError(t, client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, lease))
	lease.Spec.RenewTime = connPtr(metav1.NewMicroTime(time.Now().Add(-time.Hour)))
	require.NoError(t, client.Update(ctx, lease))
	require.Error(t, service.Renew(ctx, ref, time.Now().Add(time.Minute)))
}

func TestConnectionLeaseAcquireRejectsExpiryCrossedDuringLiveRead(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
	reader := &delayedLeaseReader{Reader: client, delay: 30 * time.Millisecond}
	service := NewConnectionLeaseService(client).WithLiveReader(reader)
	proof := ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(10 * time.Millisecond)}
	_, err := service.Acquire(ctx, proof)
	require.Error(t, err)
	require.GreaterOrEqual(t, reader.gets, 1)
}

func TestConnectionLeaseValidateUsesLiveReaderAndCompleteCapability(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
	service := NewConnectionLeaseService(client)
	proof := ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)}
	ref, err := service.Acquire(ctx, proof)
	require.NoError(t, err)
	reader := &delayedLeaseReader{Reader: client}
	service.WithLiveReader(reader)
	require.NoError(t, service.Validate(ctx, ref, 0))
	require.Equal(t, 1, reader.gets)
	missingUID := ref
	missingUID.UID = ""
	require.Error(t, service.Validate(ctx, missingUID, 0))
	missingExpiry := ref
	missingExpiry.ExpiresAt = time.Time{}
	require.Error(t, service.Validate(ctx, missingExpiry, 0))

	lease := &coordinationv1.Lease{}
	require.NoError(t, client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, lease))
	lease.Annotations[connectionLeaseEpochAnnotation] = "99"
	require.NoError(t, client.Update(ctx, lease))
	require.Error(t, service.Validate(ctx, ref, 0), "a live lease replacement must defeat a cached capability")
}

func TestConnectionLeaseRenewRejectsStaleCapabilityOnLiveLease(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
	service := NewConnectionLeaseService(client)
	proof := ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)}
	ref, err := service.Acquire(ctx, proof)
	require.NoError(t, err)
	lease := &coordinationv1.Lease{}
	require.NoError(t, client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, lease))
	lease.Annotations[connectionLeaseEpochAnnotation] = "2"
	require.NoError(t, client.Update(ctx, lease))
	require.Error(t, service.Renew(ctx, ref, time.Now().Add(time.Minute)))
}

func TestConnectionLeaseDeletingFinalizerDeniesCapabilityAfterRevoke(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
	service := NewConnectionLeaseService(client)
	proof := ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)}
	ref, err := service.Acquire(ctx, proof)
	require.NoError(t, err)
	lease := &coordinationv1.Lease{}
	require.NoError(t, client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, lease))
	lease.Finalizers = []string{"breakglass.test/cleanup"}
	require.NoError(t, client.Update(ctx, lease))
	require.NoError(t, service.Revoke(ctx, ref), "revoke remains idempotent while a finalizer delays deletion")
	deleting := &coordinationv1.Lease{}
	require.NoError(t, client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, deleting))
	require.NotNil(t, deleting.DeletionTimestamp)
	require.Error(t, service.Validate(ctx, ref, 0))
	require.Error(t, service.Renew(ctx, ref, time.Now().Add(time.Minute)))
	_, err = service.Acquire(ctx, proof)
	require.Error(t, err)
	_, err = service.StageGeneration(ctx, ref, 1)
	require.Error(t, err)
}

func TestConnectionLeaseGenerationRequiresReadinessAndKeepsSecretsOpaque(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
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
		current := &coordinationv1.Lease{}
		require.NoError(t, client.Get(ctx, types.NamespacedName{Namespace: published.Lease.Namespace, Name: published.Lease.Name}, current))
		current.Spec.HolderIdentity = connPtr("takeover")
		current.Annotations[connectionLeaseEpochAnnotation] = "99"
		require.NoError(t, client.Update(ctx, current))
		return "secret-uid-2", nil
	})
	require.Error(t, err)
	current := &coordinationv1.Lease{}
	require.NoError(t, client.Get(ctx, types.NamespacedName{Namespace: published.Lease.Namespace, Name: published.Lease.Name}, current))
	require.Equal(t, "1", current.Annotations[connectionLeaseGenerationAnnotation])
}
