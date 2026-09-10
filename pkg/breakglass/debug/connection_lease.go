package debug

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	connectionLeaseEpochAnnotation             = "breakglass.telekom.com/connection-epoch"
	connectionLeaseTargetUIDAnnotation         = "breakglass.telekom.com/connection-target-uid"
	connectionLeaseProfileAnnotation           = "breakglass.telekom.com/connection-profile-digest"
	connectionLeaseSessionAnnotation           = "breakglass.telekom.com/connection-session-uid"
	connectionLeaseGenerationAnnotation        = "breakglass.telekom.com/connection-generation"
	connectionLeasePendingGenerationAnnotation = "breakglass.telekom.com/connection-pending-generation"
	connectionLeaseSecretUIDAnnotation         = "breakglass.telekom.com/connection-secret-uid"
)

// ConnectionLeaseProof identifies the immutable authorization decision used to
// acquire a connection lease. TargetUID is the live ClusterConfig UID until a
// target-specific attachment transport supplies a more specific identity.
type ConnectionLeaseProof struct {
	Namespace     string
	SessionUID    types.UID
	TargetUID     types.UID
	ProfileDigest string
	ExpiresAt     time.Time
}

// ConnectionLeaseRef is safe to pass between controller-owned consumers. It
// contains no Secret name, credential, endpoint, or provider location.
type ConnectionLeaseRef struct {
	Namespace       string
	Name            string
	UID             types.UID
	ResourceVersion string
	HolderUID       types.UID
	TargetUID       types.UID
	ProfileDigest   string
	Epoch           int64
	ExpiresAt       time.Time
}

// ConnectionGeneration is an opaque generation capability. Secret material is
// deliberately kept out of this interface and all API/status representations.
type ConnectionGeneration struct {
	Lease      ConnectionLeaseRef
	Generation int64
	SecretUID  types.UID
}

// ConnectionLeaseBackend is the narrow capability contract for connection,
// recording, and artifact transports. Implementations must keep credential
// material outside the capability and must not publish a generation until the
// supplied readiness proof succeeds.
type ConnectionLeaseBackend interface {
	Acquire(context.Context, ConnectionLeaseProof) (ConnectionLeaseRef, error)
	Validate(context.Context, ConnectionLeaseRef, int64) error
	StageGeneration(context.Context, ConnectionLeaseRef, int64) (ConnectionGeneration, error)
	PublishReady(context.Context, ConnectionGeneration, func(context.Context) (types.UID, error)) (ConnectionGeneration, error)
	Revoke(context.Context, ConnectionLeaseRef) error
}

// StageGeneration reserves an opaque generation for a ready callback. The
// callback is the transport-specific endpoint/Secret readiness proof.
func (s *ConnectionLeaseService) StageGeneration(ctx context.Context, ref ConnectionLeaseRef, generation int64) (ConnectionGeneration, error) {
	if generation < 1 {
		return ConnectionGeneration{}, fmt.Errorf("connection generation must be positive")
	}
	lease, err := s.validatedLease(ctx, ref)
	if err != nil {
		return ConnectionGeneration{}, err
	}
	current, err := strconv.ParseInt(lease.Annotations[connectionLeaseGenerationAnnotation], 10, 64)
	if err != nil {
		return ConnectionGeneration{}, fmt.Errorf("connection generation is invalid")
	}
	if generation <= current {
		return ConnectionGeneration{}, fmt.Errorf("connection generation is not monotonic")
	}
	lease = lease.DeepCopy()
	lease.Annotations[connectionLeasePendingGenerationAnnotation] = strconv.FormatInt(generation, 10)
	if err := s.client.Update(ctx, lease); err != nil {
		return ConnectionGeneration{}, fmt.Errorf("stage connection generation: %w", err)
	}
	ref.ResourceVersion = lease.ResourceVersion
	return ConnectionGeneration{Lease: ref, Generation: generation}, nil
}

// PublishReady atomically accepts a generation only after the transport has
// returned the controller-created Secret UID proving readiness. The service
// does not accept names or values, preventing credential leakage.
func (s *ConnectionLeaseService) PublishReady(ctx context.Context, staged ConnectionGeneration, ready func(context.Context) (types.UID, error)) (ConnectionGeneration, error) {
	if ready == nil {
		return ConnectionGeneration{}, fmt.Errorf("connection generation readiness callback is required")
	}
	if _, err := s.validatedLease(ctx, staged.Lease); err != nil {
		return ConnectionGeneration{}, err
	}
	uid, err := ready(ctx)
	if err != nil || uid == "" {
		if err == nil {
			err = fmt.Errorf("readiness callback returned no Secret UID")
		}
		return ConnectionGeneration{}, fmt.Errorf("publish connection generation: %w", err)
	}
	lease, err := s.validatedLease(ctx, staged.Lease)
	if err != nil {
		return ConnectionGeneration{}, fmt.Errorf("connection lease changed during generation readiness: %w", err)
	}
	if lease.Annotations[connectionLeasePendingGenerationAnnotation] != strconv.FormatInt(staged.Generation, 10) {
		return ConnectionGeneration{}, fmt.Errorf("connection generation changed during readiness")
	}
	lease = lease.DeepCopy()
	lease.Annotations[connectionLeaseGenerationAnnotation] = strconv.FormatInt(staged.Generation, 10)
	delete(lease.Annotations, connectionLeasePendingGenerationAnnotation)
	lease.Annotations[connectionLeaseSecretUIDAnnotation] = string(uid)
	if err := s.client.Update(ctx, lease); err != nil {
		return ConnectionGeneration{}, fmt.Errorf("publish connection generation: %w", err)
	}
	staged.Lease.ResourceVersion = lease.ResourceVersion
	if err := s.Validate(ctx, staged.Lease, staged.Generation); err != nil {
		return ConnectionGeneration{}, fmt.Errorf("connection lease changed after generation publish: %w", err)
	}
	staged.SecretUID = uid
	return staged, nil
}

// ConnectionLeaseService provides durable, CAS-backed fencing for controller-
// owned connection and attachment consumers.
type ConnectionLeaseService struct {
	client    ctrlclient.Client
	namespace string
}

func NewConnectionLeaseService(client ctrlclient.Client) *ConnectionLeaseService {
	return &ConnectionLeaseService{client: client}
}

// WithNamespace restricts leases to the controller-owned execution namespace.
func (s *ConnectionLeaseService) WithNamespace(namespace string) *ConnectionLeaseService {
	s.namespace = namespace
	return s
}

// ProfileDigestForSession is the immutable digest used by lease consumers.
func ProfileDigestForSession(ds *breakglassv1alpha1.DebugSession) (string, error) {
	if ds == nil || ds.Status.ResolvedTemplate == nil {
		return "", fmt.Errorf("resolved session profile is missing")
	}
	b, err := json.Marshal(ds.Status.ResolvedTemplate)
	if err != nil {
		return "", fmt.Errorf("marshal resolved session profile: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (s *ConnectionLeaseService) AcquireForSession(ctx context.Context, ds *breakglassv1alpha1.DebugSession, targetUID types.UID) (breakglassv1alpha1.DebugSessionConnectionLease, error) {
	if ds == nil || ds.UID == "" || ds.Status.ExpiresAt == nil {
		return breakglassv1alpha1.DebugSessionConnectionLease{}, fmt.Errorf("session lease identity or expiry is missing")
	}
	digest, err := ProfileDigestForSession(ds)
	if err != nil {
		return breakglassv1alpha1.DebugSessionConnectionLease{}, err
	}
	namespace := s.namespace
	if namespace == "" {
		namespace = ds.Namespace
	}
	ref, err := s.Acquire(ctx, ConnectionLeaseProof{Namespace: namespace, SessionUID: ds.UID, TargetUID: targetUID, ProfileDigest: digest, ExpiresAt: ds.Status.ExpiresAt.Time})
	if err != nil {
		return breakglassv1alpha1.DebugSessionConnectionLease{}, err
	}
	return breakglassv1alpha1.DebugSessionConnectionLease{Namespace: ref.Namespace, Name: ref.Name, UID: ref.UID, HolderUID: ref.HolderUID, TargetUID: ref.TargetUID, ProfileDigest: ref.ProfileDigest, Epoch: ref.Epoch, ExpiresAt: metav1.NewTime(ref.ExpiresAt)}, nil
}

func (s *ConnectionLeaseService) ValidateSession(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	if ds == nil || ds.Status.ConnectionLease == nil {
		return fmt.Errorf("connection lease is missing")
	}
	l := ds.Status.ConnectionLease
	return s.Validate(ctx, ConnectionLeaseRef{Namespace: l.Namespace, Name: l.Name, UID: l.UID, HolderUID: l.HolderUID, TargetUID: l.TargetUID, ProfileDigest: l.ProfileDigest, Epoch: l.Epoch, ExpiresAt: l.ExpiresAt.Time}, -1)
}

func (s *ConnectionLeaseService) RevokeSession(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	if ds == nil || ds.Status.ConnectionLease == nil {
		return nil
	}
	l := ds.Status.ConnectionLease
	return s.Revoke(ctx, ConnectionLeaseRef{Namespace: l.Namespace, Name: l.Name, UID: l.UID, HolderUID: l.HolderUID, TargetUID: l.TargetUID, ProfileDigest: l.ProfileDigest, Epoch: l.Epoch, ExpiresAt: l.ExpiresAt.Time})
}

func connectionLeaseName(p ConnectionLeaseProof) string {
	// One durable lease per session/target prevents duplicate attachments while
	// allowing independent sessions to use the same target concurrently.
	sum := sha256.Sum256([]byte(string(p.SessionUID) + "\x00" + string(p.TargetUID)))
	return "debug-connection-" + hex.EncodeToString(sum[:])[:20]
}

func (s *ConnectionLeaseService) Acquire(ctx context.Context, proof ConnectionLeaseProof) (ConnectionLeaseRef, error) {
	if s == nil || s.client == nil {
		return ConnectionLeaseRef{}, fmt.Errorf("connection lease client is not configured")
	}
	if proof.Namespace == "" || proof.SessionUID == "" || proof.TargetUID == "" || proof.ProfileDigest == "" || proof.ExpiresAt.IsZero() || !time.Now().Before(proof.ExpiresAt) {
		return ConnectionLeaseRef{}, fmt.Errorf("connection lease proof is incomplete or expired")
	}
	key := types.NamespacedName{Namespace: proof.Namespace, Name: connectionLeaseName(proof)}
	for attempt := 0; attempt < 3; attempt++ {
		lease := &coordinationv1.Lease{}
		err := s.client.Get(ctx, key, lease)
		now := time.Now().UTC()
		if apierrors.IsNotFound(err) {
			obj := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace, Annotations: map[string]string{
				connectionLeaseEpochAnnotation: "1", connectionLeaseTargetUIDAnnotation: string(proof.TargetUID), connectionLeaseProfileAnnotation: proof.ProfileDigest, connectionLeaseSessionAnnotation: string(proof.SessionUID), connectionLeaseGenerationAnnotation: "0",
			}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: connPtr(string(proof.SessionUID)), LeaseDurationSeconds: connPtr(int32(leaseMax(1, int(proof.ExpiresAt.Sub(now).Seconds())))), RenewTime: connPtr(metav1.MicroTime{Time: now})}}
			if err := s.client.Create(ctx, obj); err != nil {
				if apierrors.IsAlreadyExists(err) {
					continue
				}
				return ConnectionLeaseRef{}, fmt.Errorf("create connection lease: %w", err)
			}
			return connectionLeaseRef(obj, proof), nil
		}
		if err != nil {
			return ConnectionLeaseRef{}, fmt.Errorf("read connection lease: %w", err)
		}
		if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != string(proof.SessionUID) && leaseActive(lease, now) {
			return ConnectionLeaseRef{}, fmt.Errorf("connection target is already leased")
		}
		if lease.Annotations[connectionLeaseTargetUIDAnnotation] != string(proof.TargetUID) || lease.Annotations[connectionLeaseProfileAnnotation] != proof.ProfileDigest {
			return ConnectionLeaseRef{}, fmt.Errorf("connection lease identity changed")
		}
		epoch, err := leaseEpoch(lease)
		if err != nil {
			return ConnectionLeaseRef{}, err
		}
		expired := !leaseActive(lease, now)
		if expired {
			epoch++
		}
		lease = lease.DeepCopy()
		lease.Spec.HolderIdentity = connPtr(string(proof.SessionUID))
		lease.Spec.LeaseDurationSeconds = connPtr(int32(leaseMax(1, int(proof.ExpiresAt.Sub(now).Seconds()))))
		lease.Spec.RenewTime = connPtr(metav1.MicroTime{Time: now})
		lease.Annotations[connectionLeaseSessionAnnotation] = string(proof.SessionUID)
		lease.Annotations[connectionLeaseEpochAnnotation] = strconv.FormatInt(epoch, 10)
		if err := s.client.Update(ctx, lease); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return ConnectionLeaseRef{}, fmt.Errorf("renew connection lease: %w", err)
		}
		return connectionLeaseRefWithEpoch(lease, proof, epoch), nil
	}
	return ConnectionLeaseRef{}, fmt.Errorf("connection lease acquisition conflicted")
}

func (s *ConnectionLeaseService) Validate(ctx context.Context, ref ConnectionLeaseRef, generation int64) error {
	lease, err := s.validatedLease(ctx, ref)
	if err != nil {
		return err
	}
	if generation >= 0 && lease.Annotations[connectionLeaseGenerationAnnotation] != strconv.FormatInt(generation, 10) {
		return fmt.Errorf("connection lease is stale or expired")
	}
	return nil
}

func (s *ConnectionLeaseService) validatedLease(ctx context.Context, ref ConnectionLeaseRef) (*coordinationv1.Lease, error) {
	lease := &coordinationv1.Lease{}
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, lease); err != nil {
		return nil, fmt.Errorf("read connection lease: %w", err)
	}
	epoch, err := leaseEpoch(lease)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if lease.UID != ref.UID || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != string(ref.HolderUID) || epoch != ref.Epoch || lease.Annotations[connectionLeaseTargetUIDAnnotation] != string(ref.TargetUID) || lease.Annotations[connectionLeaseProfileAnnotation] != ref.ProfileDigest || !leaseActive(lease, now) || (!ref.ExpiresAt.IsZero() && !now.Before(ref.ExpiresAt)) {
		return nil, fmt.Errorf("connection lease is stale or expired")
	}
	return lease, nil
}

func (s *ConnectionLeaseService) Revoke(ctx context.Context, ref ConnectionLeaseRef) error {
	current := &coordinationv1.Lease{}
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, current); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("read connection lease before revoke: %w", err)
	}
	epoch, err := leaseEpoch(current)
	if err != nil {
		return err
	}
	if current.UID != ref.UID || epoch != ref.Epoch || current.Spec.HolderIdentity == nil || *current.Spec.HolderIdentity != string(ref.HolderUID) || current.Annotations[connectionLeaseTargetUIDAnnotation] != string(ref.TargetUID) || current.Annotations[connectionLeaseProfileAnnotation] != ref.ProfileDigest {
		return fmt.Errorf("connection lease ownership changed before revoke")
	}
	uid := ref.UID
	rv := current.ResourceVersion
	err = s.client.Delete(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: ref.Namespace}}, &ctrlclient.DeleteOptions{Raw: &metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("revoke connection lease: %w", err)
	}
	return nil
}

// Renew extends only the current holder's lease and never changes its epoch.
func (s *ConnectionLeaseService) Renew(ctx context.Context, ref ConnectionLeaseRef, expiresAt time.Time) error {
	if expiresAt.IsZero() || !time.Now().Before(expiresAt) {
		return fmt.Errorf("connection lease renewal is expired")
	}
	for attempt := 0; attempt < 3; attempt++ {
		lease := &coordinationv1.Lease{}
		if err := s.client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, lease); err != nil {
			return fmt.Errorf("read connection lease for renewal: %w", err)
		}
		epoch, err := leaseEpoch(lease)
		if err != nil {
			return err
		}
		if lease.UID != ref.UID || epoch != ref.Epoch || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != string(ref.HolderUID) || lease.Annotations[connectionLeaseTargetUIDAnnotation] != string(ref.TargetUID) || lease.Annotations[connectionLeaseProfileAnnotation] != ref.ProfileDigest || !leaseActive(lease, time.Now().UTC()) {
			return fmt.Errorf("connection lease ownership changed before renewal")
		}
		lease = lease.DeepCopy()
		now := time.Now().UTC()
		lease.Spec.RenewTime = connPtr(metav1.MicroTime{Time: now})
		lease.Spec.LeaseDurationSeconds = connPtr(int32(leaseMax(1, int(expiresAt.Sub(now).Seconds()))))
		if err := s.client.Update(ctx, lease); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return fmt.Errorf("renew connection lease: %w", err)
		}
		return nil
	}
	return fmt.Errorf("connection lease renewal conflicted")
}

func (s *ConnectionLeaseService) RenewSession(ctx context.Context, ds *breakglassv1alpha1.DebugSession, expiresAt time.Time) error {
	if ds == nil || ds.Status.ConnectionLease == nil {
		return nil
	}
	l := ds.Status.ConnectionLease
	ref := ConnectionLeaseRef{Namespace: l.Namespace, Name: l.Name, UID: l.UID, HolderUID: l.HolderUID, TargetUID: l.TargetUID, ProfileDigest: l.ProfileDigest, Epoch: l.Epoch, ExpiresAt: l.ExpiresAt.Time}
	if err := s.Renew(ctx, ref, expiresAt); err != nil {
		return err
	}
	l.ExpiresAt = metav1.NewTime(expiresAt)
	return nil
}

func leaseEpoch(l *coordinationv1.Lease) (int64, error) {
	n, err := strconv.ParseInt(l.Annotations[connectionLeaseEpochAnnotation], 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("connection lease epoch is invalid")
	}
	return n, nil
}
func connectionLeaseRef(l *coordinationv1.Lease, p ConnectionLeaseProof) ConnectionLeaseRef {
	e, _ := leaseEpoch(l)
	return connectionLeaseRefWithEpoch(l, p, e)
}
func connectionLeaseRefWithEpoch(l *coordinationv1.Lease, p ConnectionLeaseProof, e int64) ConnectionLeaseRef {
	return ConnectionLeaseRef{Namespace: l.Namespace, Name: l.Name, UID: l.UID, ResourceVersion: l.ResourceVersion, HolderUID: p.SessionUID, TargetUID: p.TargetUID, ProfileDigest: p.ProfileDigest, Epoch: e, ExpiresAt: p.ExpiresAt}
}
func leaseActive(l *coordinationv1.Lease, now time.Time) bool {
	if l.Spec.RenewTime == nil || l.Spec.LeaseDurationSeconds == nil {
		return false
	}
	return now.Before(l.Spec.RenewTime.Add(time.Duration(*l.Spec.LeaseDurationSeconds) * time.Second))
}
func connPtr[T any](v T) *T { return &v }
func leaseMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}
