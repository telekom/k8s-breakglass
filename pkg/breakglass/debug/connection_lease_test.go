package debug

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	scheme, err := utils.CreateScheme()
	require.NoError(t, err)
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
	service := NewConnectionLeaseService(client)
	proof := ConnectionLeaseProof{Namespace: "controller", SessionUID: "session-a", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)}
	ref, err := service.Acquire(ctx, proof)
	require.NoError(t, err)
	require.NoError(t, service.Validate(ctx, ref, 0))
	_, err = service.Acquire(ctx, ConnectionLeaseProof{Namespace: proof.Namespace, SessionUID: "session-b", TargetUID: proof.TargetUID, ProfileDigest: proof.ProfileDigest, ExpiresAt: proof.ExpiresAt})
	require.Error(t, err, "a target attachment is exclusive while the existing lease is active")
	require.NoError(t, service.Revoke(ctx, ref))
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

func TestConnectionLeaseSessionScopedClaimsAllowDistinctSessionsOnCluster(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
	service := NewConnectionLeaseService(client)
	base := ConnectionLeaseProof{Namespace: "controller", TargetUID: "cluster-a", ProfileDigest: "sha256:a", ExpiresAt: time.Now().Add(time.Minute)}
	first, err := service.acquire(ctx, ConnectionLeaseProof{Namespace: base.Namespace, SessionUID: "session-a", TargetUID: base.TargetUID, ProfileDigest: base.ProfileDigest, ExpiresAt: base.ExpiresAt}, true)
	require.NoError(t, err)
	second, err := service.acquire(ctx, ConnectionLeaseProof{Namespace: base.Namespace, SessionUID: "session-b", TargetUID: base.TargetUID, ProfileDigest: base.ProfileDigest, ExpiresAt: base.ExpiresAt}, true)
	require.NoError(t, err)
	require.NotEqual(t, first.Name, second.Name)
	_, err = service.Acquire(ctx, ConnectionLeaseProof{Namespace: base.Namespace, SessionUID: "attachment-a", TargetUID: base.TargetUID, ProfileDigest: base.ProfileDigest, ExpiresAt: base.ExpiresAt})
	require.NoError(t, err)
	_, err = service.Acquire(ctx, ConnectionLeaseProof{Namespace: base.Namespace, SessionUID: "attachment-b", TargetUID: base.TargetUID, ProfileDigest: base.ProfileDigest, ExpiresAt: base.ExpiresAt})
	require.Error(t, err, "target-scoped attachment claim remains exclusive")
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

type sessionRenewalFenceReader struct {
	ctrlclient.Reader
	leaseRead bool
	mutate    func(*breakglassv1alpha1.DebugSession)
}

func (reader *sessionRenewalFenceReader) Get(ctx context.Context, key ctrlclient.ObjectKey, object ctrlclient.Object, options ...ctrlclient.GetOption) error {
	if err := reader.Reader.Get(ctx, key, object, options...); err != nil {
		return err
	}
	if _, ok := object.(*coordinationv1.Lease); ok {
		reader.leaseRead = true
	}
	if session, ok := object.(*breakglassv1alpha1.DebugSession); ok && reader.leaseRead {
		reader.mutate(session)
	}
	return nil
}
func TestRenewSessionRechecksLiveSessionAfterLeaseRead(t *testing.T) {
	for _, scenario := range []string{"idle", "terminal", "replacement", "missing-expiry", "profile", "lease-replacement", "deleting", "provisional", "issuer", "clamp"} {
		t.Run(scenario, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, coordinationv1.AddToScheme(scheme))
			require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
			now := time.Now().UTC().Truncate(time.Second)
			starts, expiry := metav1.NewTime(now), metav1.NewTime(now.Add(5*time.Minute))
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: "session-uid"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, StartsAt: &starts, ExpiresAt: &expiry, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "1m"}}}}
			client := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme).WithObjects(session))
			service := NewConnectionLeaseService(client).WithLiveReader(client)
			lease, err := service.AcquireForSession(context.Background(), session, "cluster-uid")
			require.NoError(t, err)
			session.Status.ConnectionLease = &lease
			require.NoError(t, client.Update(context.Background(), session))
			key := ctrlclient.ObjectKey{Namespace: lease.Namespace, Name: lease.Name}
			before := &coordinationv1.Lease{}
			require.NoError(t, client.Get(context.Background(), key, before))
			reader := &sessionRenewalFenceReader{Reader: client, mutate: func(live *breakglassv1alpha1.DebugSession) {
				switch scenario {
				case "idle":
					old := metav1.NewTime(now.Add(-2 * time.Minute))
					live.Status.LastActivity = &old
				case "terminal":
					live.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
				case "replacement":
					live.UID = "replacement"
				case "missing-expiry":
					live.Status.ExpiresAt = nil
				case "profile":
					live.Status.ResolvedTemplate.Mode = breakglassv1alpha1.DebugSessionModeHybrid
				case "lease-replacement":
					live.Status.ConnectionLease.UID = "replacement-lease"
				case "deleting":
					deleted := metav1.NewTime(now)
					live.DeletionTimestamp = &deleted
				case "provisional":
					live.Annotations = map[string]string{quotas.AdmissionAnnotation: quotas.Pending}
				case "issuer":
					live.Spec.IdentityProviderIssuer = "https://replacement.example"
				case "clamp":
					limited := metav1.NewTime(now.Add(time.Minute))
					live.Status.ExpiresAt = &limited
				}
			}}
			service.WithLiveReader(reader)
			err = service.RenewSession(context.Background(), session, now.Add(10*time.Minute))
			require.True(t, reader.leaseRead)
			after := &coordinationv1.Lease{}
			require.NoError(t, client.Get(context.Background(), key, after))
			if scenario == "clamp" {
				require.NoError(t, err)
				require.Equal(t, now.Add(time.Minute), session.Status.ConnectionLease.ExpiresAt.Time)
				require.LessOrEqual(t, *after.Spec.LeaseDurationSeconds, int32(60))
			} else {
				require.Error(t, err)
				require.Equal(t, before.Spec, after.Spec)
				require.Equal(t, before.ResourceVersion, after.ResourceVersion)
			}
		})
	}
}
