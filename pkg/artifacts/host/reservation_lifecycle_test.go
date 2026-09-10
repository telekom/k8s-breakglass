//go:build linux || darwin

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	artifactapi "github.com/telekom/k8s-breakglass/pkg/artifacts/api"
	artifactcontroller "github.com/telekom/k8s-breakglass/pkg/artifacts/controller"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/kube"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage/local"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/token"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	clienttesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type allowLifecycle struct{}

func (allowLifecycle) AuthorizeArtifact(context.Context, backend.SessionBinding) error { return nil }

type ambiguousStore struct {
	storage.Store
	lost      bool
	beforePut func()
}

func (s *ambiguousStore) InventoryKey(ctx context.Context, key string) ([]storage.Version, error) {
	return s.Store.(storage.KeyInventory).InventoryKey(ctx, key)
}

func (s *ambiguousStore) PutIfAbsent(ctx context.Context, o storage.Object, r io.Reader) (storage.Metadata, error) {
	if s.beforePut != nil {
		s.beforePut()
	}
	m, e := s.Store.PutIfAbsent(ctx, o, r)
	if e == nil && s.lost {
		s.lost = false
		return storage.Metadata{}, context.DeadlineExceeded
	}
	return m, e
}

func lifecycleFixture(t *testing.T) (*backend.Service, *kube.Repository, *ambiguousStore, *token.Keyring, *time.Time, client.Client) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	config := local.Config{ExplicitlyEnabled: true, PrivateRootAcknowledged: true, ArtifactRoot: filepath.Join(root, "objects"), StagingRoot: filepath.Join(root, "staging"), InstanceID: "reservation-lifecycle", ExpectedUID: os.Getuid(), ExpectedGID: os.Getgid(), ServingReplicas: 1, AccessMode: local.AccessModeReadWriteOnce, DeploymentStrategy: local.StrategyRecreate, EncryptionAcknowledged: true, SnapshotPolicy: local.SnapshotsProhibited}
	require.NoError(t, os.Mkdir(config.ArtifactRoot, 0700))
	require.NoError(t, os.Mkdir(config.StagingRoot, 0700))
	require.NoError(t, local.ProvisionSentinels(config))
	localStore, err := local.Open(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, localStore.Close()) })
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	var next atomic.Int64
	hub := interceptor.NewClient(fake.NewClientBuilder().WithScheme(scheme).WithObjectTracker(clienttesting.NewObjectTracker(scheme, serializer.NewCodecFactory(scheme).UniversalDecoder())).WithStatusSubresource(&breakglassv1alpha1.DebugSessionArtifact{}).Build(), interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.CreateOption) error {
		number := next.Add(1)
		if o.GetUID() == "" {
			o.SetUID(types.UID("created-" + strings.Repeat("x", int(number))))
		}
		return c.Create(ctx, o, opts...)
	}})
	repo, err := kube.NewRepositoryInNamespace(hub, "controller")
	require.NoError(t, err)
	keys, err := token.NewKeyring("https://breakglass.example", "artifact", "key", []token.Key{{ID: "key", Secret: bytes.Repeat([]byte{1}, 32)}}, token.Limits{MaxTTL: 15 * time.Minute})
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	store := &ambiguousStore{Store: localStore}
	svc, err := backend.New(backend.Config{Repository: repo, Store: store, Authorizer: allowLifecycle{}, Tokens: keys, StagingDir: config.StagingRoot, Now: func() time.Time { return now }})
	require.NoError(t, err)
	return svc, repo, store, keys, &now, hub
}
func lifecycleRecord(now time.Time) backend.Record {
	detail := "basic"
	return backend.Record{ConnectionLeaseUID: "lease-uid", Namespace: "hub", SessionName: "session", SessionUID: "session-uid", TargetClusterUID: "cluster-uid", TargetIdentityDigest: strings.Repeat("a", 64), RuntimeBindingDigest: strings.Repeat("b", 64), PlanDigest: strings.Repeat("c", 64), Recipe: archive.SystemSummaryRecipe, RecipeVersion: 1, ExpiresAt: now.Add(time.Hour), MaxBytes: archive.MaxSystemSummaryArchiveBytes, OperationEpoch: 1, Expected: archive.Expected{Recipe: archive.SystemSummaryRecipe, RecipeVersion: 1, SessionNamespace: "hub", SessionName: "session", SessionUID: "session-uid", RedactionProfile: "credential-text.v1", RedactionVersion: 1, Inputs: archive.Inputs{MaxArchiveBytes: archive.MaxSystemSummaryArchiveBytes, DetailLevel: &detail}}}
}
func TestDurableCollectorReservationTokenAndLocalRoundtrip(t *testing.T) {
	svc, repo, _, keys, now, hub := lifecycleFixture(t)
	ctx := context.Background()
	record, err := svc.Reserve(ctx, lifecycleRecord(*now))
	require.NoError(t, err)
	require.NotEmpty(t, record.ArtifactUID)
	persisted, err := repo.Get(ctx, record.Namespace, record.SessionName, record.ArtifactID)
	require.NoError(t, err)
	require.Empty(t, persisted.UploadJTI)
	require.Len(t, persisted.UploadJTIHash, 64)
	route := "/api/debugSessionArtifactUploads/" + record.Namespace + "/" + record.SessionName + "/" + record.ArtifactID
	signed, err := backend.ReservationToken(keys, persisted, route, *now, 15*time.Minute)
	require.NoError(t, err)
	again, err := backend.ReservationToken(keys, persisted, route, *now, 15*time.Minute)
	require.NoError(t, err)
	require.Equal(t, signed, again)
	body := validLocalArchive(t, record.Expected)
	public, err := svc.Upload(ctx, signed, route, bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, backend.StateAvailable, public.State)
	_, err = svc.Upload(ctx, signed, route, bytes.NewReader(body))
	require.ErrorIs(t, err, backend.ErrReplay)
	reader, _, err := svc.Download(ctx, record.Namespace, record.SessionName, record.ArtifactID, backend.SessionBinding{Namespace: record.Namespace, Name: record.SessionName, UID: record.SessionUID, TargetClusterUID: record.TargetClusterUID, TargetIdentityDigest: record.TargetIdentityDigest, OperationEpoch: record.OperationEpoch})
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	require.Equal(t, body, got)
	fresh, err := repo.Get(ctx, record.Namespace, record.SessionName, record.ArtifactID)
	require.NoError(t, err)
	require.NoError(t, svc.Cleanup(ctx, fresh, backend.StateDeleted))
	object := &breakglassv1alpha1.DebugSessionArtifact{}
	require.NoError(t, hub.Get(ctx, client.ObjectKey{Namespace: "controller", Name: record.ArtifactID}, object))
	require.NoError(t, hub.Delete(ctx, object))
	replacement, err := svc.Reserve(ctx, lifecycleRecord(*now))
	require.NoError(t, err)
	require.Equal(t, record.ArtifactID, replacement.ArtifactID)
	require.NotEqual(t, record.ReservationNonce, replacement.ReservationNonce)
	require.NotEqual(t, record.UploadJTIHash, replacement.UploadJTIHash)
	_, err = svc.Upload(ctx, signed, route, bytes.NewReader(body))
	require.ErrorIs(t, err, backend.ErrForbidden)
	retained, err := repo.Get(ctx, replacement.Namespace, replacement.SessionName, replacement.ArtifactID)
	require.NoError(t, err)
	require.Equal(t, backend.StatePending, retained.State)
}
func TestRecordingDurableRecoveryAfterLostPutAndAccessExpiry(t *testing.T) {
	svc, repo, store, _, now, _ := lifecycleFixture(t)
	ctx := context.Background()
	record := lifecycleRecord(*now)
	record.Recording = &backend.RecordingMetadata{FormatVersion: 1, StartedAt: *now, StreamExpiresAt: now.Add(time.Minute), PodNamespace: "target", PodName: "debug", PodUID: "pod-uid", Operation: "exec", LeaseUID: "lease-uid", LeaseEpoch: "1", Generation: "1"}
	calls := 0
	reserved, err := svc.ReserveRecording(ctx, record, func(context.Context) error { calls++; return nil })
	require.NoError(t, err)
	require.Equal(t, 2, calls)
	*now = now.Add(2 * time.Minute)
	metadata := *reserved.Recording
	metadata.FinishedAt = *now
	metadata.Complete = false
	frame := make([]byte, 42)
	frame[0], frame[1] = 1, 'o'
	store.lost = true
	_, err = svc.FinalizeRecording(ctx, reserved, bytes.NewReader(frame), metadata)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	persisted, err := repo.Get(ctx, reserved.Namespace, reserved.SessionName, reserved.ArtifactID)
	require.NoError(t, err)
	require.Equal(t, backend.StateUnknown, persisted.State)
	require.EqualValues(t, 42, persisted.Size)
	require.Len(t, persisted.SHA256, 64)
	public, err := svc.RecoverRecording(ctx, reserved)
	require.NoError(t, err)
	require.Equal(t, backend.StateAvailable, public.State)
	reader, _, err := svc.DownloadRecording(ctx, reserved, func(context.Context) error { return nil })
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	require.Equal(t, frame, got)
	_, _, err = svc.DownloadRecording(ctx, reserved, func(context.Context) error { return errors.New("session deleted") })
	require.ErrorContains(t, err, "deleted")
}
func validLocalArchive(t *testing.T, expected archive.Expected) []byte {
	t.Helper()
	payload := []byte(`{"hostname":"worker"}`)
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, entry := range []struct {
		name string
		data []byte
		kind byte
	}{{"files", nil, tar.TypeDir}, {"files/system-summary.json", payload, tar.TypeReg}, {"stdout.log", nil, tar.TypeReg}, {"stderr.log", nil, tar.TypeReg}} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.data)), Typeflag: entry.kind}))
		_, err := tw.Write(entry.data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Flush())
	digest := sha256.New()
	_, err := digest.Write(raw.Bytes())
	require.NoError(t, err)
	_, err = digest.Write(make([]byte, 1024))
	require.NoError(t, err)
	manifest := archive.Manifest{SchemaVersion: archive.SchemaV1, Recipe: expected.Recipe, RecipeVersion: 1, ArtifactID: expected.ArtifactID, ArchiveFormat: archive.ArchiveFormatTarGzip, Inputs: expected.Inputs, DeclaredOutputs: []string{"files/system-summary.json", "manifest.json", "stderr.log", "stdout.log"}, PayloadSHA256: hex.EncodeToString(digest.Sum(nil)), FileCount: 1, Bytes: int64(len(payload)), ExitSemantics: archive.ExitSemanticsCompleteOnly}
	manifest.Session.Namespace = expected.SessionNamespace
	manifest.Session.Name = expected.SessionName
	manifest.Session.UID = expected.SessionUID
	manifest.Redaction.Profile = expected.RedactionProfile
	manifest.Redaction.Version = expected.RedactionVersion
	encoded, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(encoded))}))
	_, err = tw.Write(encoded)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, err = gz.Write(raw.Bytes())
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return compressed.Bytes()
}

type lifecycleTarget struct {
	client client.Client
	config *breakglassv1alpha1.ClusterConfig
}

func (p lifecycleTarget) GetClientForPrivilegedOperation(context.Context, string) (client.Client, *breakglassv1alpha1.ClusterConfig, error) {
	return p.client, p.config, nil
}
func (p lifecycleTarget) ValidatePrivilegedOperationClusterConfig(context.Context, *breakglassv1alpha1.ClusterConfig) error {
	return nil
}
func (p lifecycleTarget) ReleasePrivilegedOperationClusterConfig(*breakglassv1alpha1.ClusterConfig) {}
func TestRegisteredCollectorAdmissionCreatesJobWithReservedToken(t *testing.T) {
	svc, repo, _, keys, now, hub := lifecycleFixture(t)
	ctx := context.Background()
	require.NoError(t, corev1.AddToScheme(hub.Scheme()))
	require.NoError(t, batchv1.AddToScheme(hub.Scheme()))
	expires := metav1.NewTime(now.Add(time.Hour))
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: "session-uid"}, Spec: breakglassv1alpha1.DebugSessionSpec{RequestedBy: "owner", Cluster: "spoke", TargetNamespace: "target"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expires, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{ArtifactCollection: &breakglassv1alpha1.DebugSessionArtifactCollection{AllowedRecipes: []string{archive.SystemSummaryRecipe}}}, AllowedPods: []breakglassv1alpha1.AllowedPodRef{{Namespace: "target", Name: "approved", UID: "pod-uid"}}, ConnectionLease: &breakglassv1alpha1.DebugSessionConnectionLease{UID: "lease-uid", TargetUID: "cluster-uid", Epoch: 1}}}
	require.NoError(t, hub.Create(ctx, session))
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "approved", Namespace: "target", UID: "pod-uid"}}
	spoke := interceptor.NewClient(fake.NewClientBuilder().WithScheme(hub.Scheme()).WithObjects(pod).Build(), interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.CreateOption) error {
		o.SetUID(types.UID("target-" + o.GetName()))
		return c.Create(ctx, o, opts...)
	}})
	provider := lifecycleTarget{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: "cluster-uid"}}}
	debugAPI := debug.NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil).WithAPIReader(hub)
	controller := &collectionController{service: svc, debug: debugAPI, provider: provider, maximum: archive.MaxSystemSummaryArchiveBytes}
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("legacy_identity_allowed", true); c.Set("username", "owner"); c.Next() })
	require.NoError(t, controller.Register(router.Group("/artifacts")))
	send := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/artifacts/hub/session", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	denied := send(`{"recipe":"system-summary.v1","podNamespace":"target","podName":"approved","image":"evil"}`)
	require.Equal(t, http.StatusBadRequest, denied.Code)
	response := send(`{"recipe":"system-summary.v1","podNamespace":"target","podName":"approved"}`)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var public backend.PublicRecord
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &public))
	record, err := repo.Get(ctx, "hub", "session", public.ArtifactID)
	require.NoError(t, err)
	require.Equal(t, "pod-uid", record.TargetPodUID)
	reconciler := &artifactcontroller.Reconciler{Client: hub, LiveReader: hub, Service: svc, TokenIssuer: &uploadTokenIssuer{keyring: keys, now: func() time.Time { return *now }}, Image: "registry.example/collector@sha256:" + strings.Repeat("c", 64), ControllerURL: "https://breakglass.example", ClusterProvider: provider}
	key := client.ObjectKey{Namespace: "controller", Name: record.ArtifactID}
	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key})
	require.NoError(t, err)
	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key})
	require.NoError(t, err)
	secret := &corev1.Secret{}
	require.NoError(t, spoke.Get(ctx, client.ObjectKey{Namespace: "target", Name: record.ArtifactID + "-upload"}, secret))
	job := &batchv1.Job{}
	require.NoError(t, spoke.Get(ctx, client.ObjectKey{Namespace: "target", Name: record.ArtifactID + "-collect"}, job))
	require.Equal(t, "registry.example/collector@sha256:"+strings.Repeat("c", 64), job.Spec.Template.Spec.InitContainers[0].Image)
	route := "/api/debugSessionArtifactUploads/hub/session/" + record.ArtifactID
	body := validLocalArchive(t, record.Expected)
	result, err := svc.Upload(ctx, string(secret.Data["token"]), route, bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, backend.StateAvailable, result.State)

	readController, err := artifactapi.NewReadController(svc, newReadBindingResolver(debugAPI, repositoryBindingSource{repository: repo}))
	require.NoError(t, err)
	require.NoError(t, readController.Register(router.Group("/artifacts")))
	listed := httptest.NewRecorder()
	router.ServeHTTP(listed, httptest.NewRequest(http.MethodGet, "/artifacts/hub/session", nil))
	require.Equal(t, http.StatusOK, listed.Code, listed.Body.String())
	var listedArtifacts []backend.PublicRecord
	require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &listedArtifacts))
	require.Len(t, listedArtifacts, 1)
	require.Equal(t, record.ArtifactID, listedArtifacts[0].ArtifactID)
	downloaded := httptest.NewRecorder()
	router.ServeHTTP(downloaded, httptest.NewRequest(http.MethodGet, "/artifacts/hub/session/"+record.ArtifactID, nil))
	require.Equal(t, http.StatusOK, downloaded.Code, downloaded.Body.String())
	require.Equal(t, body, downloaded.Body.Bytes())

	second := send(`{"recipe":"system-summary.v1","podNamespace":"target","podName":"approved"}`)
	require.Equal(t, http.StatusCreated, second.Code, second.Body.String())
	var next backend.PublicRecord
	require.NoError(t, json.Unmarshal(second.Body.Bytes(), &next))
	require.NoError(t, spoke.Delete(ctx, pod))
	replacement := pod.DeepCopy()
	replacement.ResourceVersion = ""
	replacement.UID = "replacement"
	require.NoError(t, spoke.Create(ctx, replacement))
	nextKey := client.ObjectKey{Namespace: "controller", Name: next.ArtifactID}
	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: nextKey})
	require.NoError(t, err)
	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: nextKey})
	require.Error(t, err)
	require.True(t, apierrors.IsNotFound(spoke.Get(ctx, client.ObjectKey{Namespace: "target", Name: next.ArtifactID + "-upload"}, &corev1.Secret{})))
}

func TestConcurrentCollectorReservationsHaveTwoDurableSlots(t *testing.T) {
	svc, _, _, _, now, hub := lifecycleFixture(t)
	var successes atomic.Int64
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := svc.Reserve(context.Background(), lifecycleRecord(*now)); err == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	require.Equal(t, int64(2), successes.Load())
	var list breakglassv1alpha1.DebugSessionArtifactList
	require.NoError(t, hub.List(context.Background(), &list))
	require.Len(t, list.Items, 2)
	require.NotEqual(t, list.Items[0].Spec.ReservationNonce, list.Items[1].Spec.ReservationNonce)
	require.Equal(t, "session-uid", list.Items[0].Spec.SessionRef.UID)
	require.Equal(t, "session-uid", list.Items[1].Spec.SessionRef.UID)
}

func TestPendingReservationCleanupUsesDurableStatusTransition(t *testing.T) {
	svc, repo, _, _, now, _ := lifecycleFixture(t)
	ctx := context.Background()
	record, err := svc.Reserve(ctx, lifecycleRecord(*now))
	require.NoError(t, err)
	require.NoError(t, svc.Cleanup(ctx, record, backend.StateExpired))
	current, err := repo.Get(ctx, record.Namespace, record.SessionName, record.ArtifactID)
	require.NoError(t, err)
	require.Equal(t, backend.StateExpired, current.State)
}

func TestCleanupRetainsThenRecoversPublicationPausedBeforePut(t *testing.T) {
	svc, repo, store, keys, now, hub := lifecycleFixture(t)
	ctx := context.Background()
	record, err := svc.Reserve(ctx, lifecycleRecord(*now))
	require.NoError(t, err)
	route := "/api/debugSessionArtifactUploads/hub/session/" + record.ArtifactID
	signed, err := backend.ReservationToken(keys, record, route, *now, 15*time.Minute)
	require.NoError(t, err)
	store.beforePut = func() {
		intent, err := repo.Get(ctx, record.Namespace, record.SessionName, record.ArtifactID)
		require.NoError(t, err)
		require.Equal(t, backend.StateUploading, intent.State)
		require.Positive(t, intent.Size)
		require.ErrorIs(t, svc.Cleanup(ctx, intent, backend.StateDeleted), storage.ErrAmbiguous)
		retained, err := repo.Get(ctx, record.Namespace, record.SessionName, record.ArtifactID)
		require.NoError(t, err)
		require.Equal(t, record.ArtifactUID, retained.ArtifactUID)
		require.Equal(t, backend.StateUnknown, retained.State)
	}
	_, err = svc.Upload(ctx, signed, route, bytes.NewReader(validLocalArchive(t, record.Expected)))
	require.Error(t, err)
	current, err := repo.Get(ctx, record.Namespace, record.SessionName, record.ArtifactID)
	require.NoError(t, err)
	require.Equal(t, record.ArtifactUID, current.ArtifactUID)
	require.Equal(t, backend.StateRevoked, current.State)
	object := &breakglassv1alpha1.DebugSessionArtifact{}
	require.NoError(t, hub.Get(ctx, client.ObjectKey{Namespace: "controller", Name: record.ArtifactID}, object))
	require.NoError(t, hub.Delete(ctx, object))
	replacement, err := svc.Reserve(ctx, lifecycleRecord(*now))
	require.NoError(t, err)
	require.Equal(t, record.ArtifactID, replacement.ArtifactID)
	require.NotEqual(t, record.ArtifactUID, replacement.ArtifactUID)
}

func TestRecordingReservationRejectsCollapsedSubsecondLifetime(t *testing.T) {
	svc, _, _, _, now, hub := lifecycleFixture(t)
	record := lifecycleRecord(*now)
	record.Recording = &backend.RecordingMetadata{FormatVersion: 1, StartedAt: now.Add(time.Millisecond), StreamExpiresAt: now.Add(2 * time.Millisecond), PodNamespace: "target", PodName: "pod", PodUID: "uid", Operation: "exec", LeaseUID: "lease", LeaseEpoch: "1", Generation: "1"}
	_, err := svc.ReserveRecording(context.Background(), record, func(context.Context) error { return nil })
	require.ErrorIs(t, err, backend.ErrForbidden)
	var list breakglassv1alpha1.DebugSessionArtifactList
	require.NoError(t, hub.List(context.Background(), &list))
	require.Empty(t, list.Items)
}

func TestCollectorLeaseRecreationDeniesOldUploadTokenAndDownload(t *testing.T) {
	_, repo, store, keys, now, hub := lifecycleFixture(t)
	require.NoError(t, coordinationv1.AddToScheme(hub.Scheme()))
	ctx := context.Background()
	expiry := metav1.NewTime(now.Add(time.Hour))
	renew := metav1.NewMicroTime(*now)
	holder := "session-uid"
	duration := int32(3600)
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "connection", Namespace: "hub", UID: "lease-uid", Annotations: map[string]string{"breakglass.telekom.com/connection-epoch": "1", "breakglass.telekom.com/connection-target-uid": "cluster-uid", "breakglass.telekom.com/connection-profile-digest": "sha256:profile"}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, RenewTime: &renew}}
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: "session-uid"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry, ConnectionLease: &breakglassv1alpha1.DebugSessionConnectionLease{Namespace: "hub", Name: "connection", UID: "lease-uid", HolderUID: "session-uid", TargetUID: "cluster-uid", ProfileDigest: "sha256:profile", Epoch: 1, ExpiresAt: expiry}}}
	require.NoError(t, hub.Create(ctx, lease))
	require.NoError(t, hub.Create(ctx, session))
	leaseService := debug.NewConnectionLeaseService(hub).WithLiveReader(hub)
	service, err := backend.New(backend.Config{Repository: repo, Store: store, Tokens: keys, StagingDir: t.TempDir(), Now: func() time.Time { return *now }, Authorizer: NewLiveSessionAuthorizer(hub, NewConnectionLeaseFence(hub, leaseService), func() time.Time { return *now })})
	require.NoError(t, err)
	record, err := service.Reserve(ctx, lifecycleRecord(*now))
	require.NoError(t, err)
	route := "/api/debugSessionArtifactUploads/hub/session/" + record.ArtifactID
	signed, err := backend.ReservationToken(keys, record, route, *now, 15*time.Minute)
	require.NoError(t, err)
	body := validLocalArchive(t, record.Expected)
	_, err = service.Upload(ctx, signed, route, bytes.NewReader(body))
	require.NoError(t, err)
	binding := backend.SessionBinding{Namespace: "hub", Name: "session", UID: "session-uid", TargetClusterUID: "cluster-uid", TargetIdentityDigest: record.TargetIdentityDigest, OperationEpoch: 1, ConnectionLeaseUID: "lease-uid"}
	reader, _, err := service.Download(ctx, "hub", "session", record.ArtifactID, binding)
	require.NoError(t, err)
	_, err = io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	require.NoError(t, hub.Delete(ctx, lease))
	replacement := lease.DeepCopy()
	replacement.UID = "replacement-lease"
	replacement.ResourceVersion = ""
	require.NoError(t, hub.Create(ctx, replacement))
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), session))
	session.Status.ConnectionLease.UID = replacement.UID
	require.NoError(t, hub.Update(ctx, session))
	_, err = service.Upload(ctx, signed, route, bytes.NewReader(body))
	require.ErrorIs(t, err, backend.ErrForbidden)
	_, _, err = service.Download(ctx, "hub", "session", record.ArtifactID, binding)
	require.ErrorIs(t, err, backend.ErrForbidden)
}
