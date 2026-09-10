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
	rootapi "github.com/telekom/k8s-breakglass/pkg/api"
	artifactcontroller "github.com/telekom/k8s-breakglass/pkg/artifacts/controller"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
	"github.com/telekom/k8s-breakglass/pkg/config"
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
	lost         bool
	beforePut    func()
	inventoryErr error
}

func (s *ambiguousStore) Inventory(ctx context.Context, object storage.Object) ([]storage.Version, error) {
	if s.inventoryErr != nil {
		return nil, s.inventoryErr
	}
	return s.Store.Inventory(ctx, object)
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
	require.NoError(t, coordinationv1.AddToScheme(hub.Scheme()))
	leaseRef, leaseErr := debug.NewConnectionLeaseService(hub).WithLiveReader(hub).AcquireForSession(ctx, session, "cluster-uid")
	require.NoError(t, leaseErr)
	session.Status.ConnectionLease = &leaseRef
	require.NoError(t, hub.Update(ctx, session))

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "approved", Namespace: "target", UID: "pod-uid"}}
	spoke := interceptor.NewClient(fake.NewClientBuilder().WithScheme(hub.Scheme()).WithObjects(pod).Build(), interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.CreateOption) error {
		o.SetUID(types.UID("target-" + o.GetName()))
		return c.Create(ctx, o, opts...)
	}})
	provider := lifecycleTarget{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: "cluster-uid"}}}
	authCalls := 0
	middleware := func(c *gin.Context) {
		authCalls++
		if c.GetHeader("Authorization") != "Bearer authenticated-test-user" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("legacy_identity_allowed", true)
		c.Set("username", "owner")
		c.Next()
	}
	debugAPI := debug.NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, middleware).WithAPIReader(hub)
	controllers, err := artifactAPIControllers(svc, Dependencies{DebugAPI: debugAPI, ClusterProvider: provider, BindingSource: repositoryBindingSource{repository: repo}}, archive.MaxSystemSummaryArchiveBytes)
	require.NoError(t, err)
	server := rootapi.NewServer(zap.NewNop(), config.Config{Server: config.Server{AllowedOrigins: []string{"https://test.example"}}}, true, nil)
	require.NoError(t, server.RegisterAll(controllers))
	router := server.Handler()
	for _, endpoint := range []struct{ method, path string }{{http.MethodPost, "/api/debugSessionArtifacts/hub/session"}, {http.MethodGet, "/api/debugSessionArtifacts/hub/session"}, {http.MethodGet, "/api/debugSessionArtifacts/hub/session/artifact"}} {
		for _, credential := range []string{"", "Bearer invalid"} {
			request := httptest.NewRequest(endpoint.method, endpoint.path, nil)
			request.Header.Set("Authorization", credential)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			require.Equal(t, http.StatusUnauthorized, response.Code)
		}
	}
	beforeUpload := authCalls
	unauthorizedUpload := httptest.NewRecorder()
	router.ServeHTTP(unauthorizedUpload, httptest.NewRequest(http.MethodPut, "/api/debugSessionArtifactUploads/hub/session/artifact", nil))
	require.Equal(t, http.StatusNotFound, unauthorizedUpload.Code)
	require.Equal(t, beforeUpload, authCalls, "upload uses its token gate, not human authentication")
	send := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/debugSessionArtifacts/hub/session", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer authenticated-test-user")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	for _, epoch := range []int64{-1, 0} {
		session.Status.ConnectionLease.Epoch = epoch
		require.NoError(t, hub.Update(ctx, session))
		denied := send(`{"recipe":"system-summary.v1","podNamespace":"target","podName":"approved"}`)
		require.Equal(t, http.StatusForbidden, denied.Code)
		var reservations breakglassv1alpha1.DebugSessionArtifactList
		require.NoError(t, hub.List(ctx, &reservations))
		require.Empty(t, reservations.Items)
	}
	session.Status.ConnectionLease.Epoch = 1
	require.NoError(t, hub.Update(ctx, session))
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
	uploadRequest := httptest.NewRequest(http.MethodPut, route, bytes.NewReader(body))
	uploadRequest.Header.Set("Authorization", "Bearer "+string(secret.Data["token"]))
	uploadResponse := httptest.NewRecorder()
	beforeUpload = authCalls
	router.ServeHTTP(uploadResponse, uploadRequest)
	require.Equal(t, http.StatusCreated, uploadResponse.Code, uploadResponse.Body.String())
	require.Equal(t, beforeUpload, authCalls)
	var result backend.PublicRecord
	require.NoError(t, json.Unmarshal(uploadResponse.Body.Bytes(), &result))
	require.Equal(t, backend.StateAvailable, result.State)

	listed := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/api/debugSessionArtifacts/hub/session", nil)
	listRequest.Header.Set("Authorization", "Bearer authenticated-test-user")
	router.ServeHTTP(listed, listRequest)
	require.Equal(t, http.StatusOK, listed.Code, listed.Body.String())
	var listedArtifacts []backend.PublicRecord
	require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &listedArtifacts))
	require.Len(t, listedArtifacts, 1)
	require.Equal(t, record.ArtifactID, listedArtifacts[0].ArtifactID)
	downloaded := httptest.NewRecorder()
	downloadRequest := httptest.NewRequest(http.MethodGet, "/api/debugSessionArtifacts/hub/session/"+record.ArtifactID, nil)
	downloadRequest.Header.Set("Authorization", "Bearer authenticated-test-user")
	router.ServeHTTP(downloaded, downloadRequest)
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

func TestRejectedRecordingReservationIsDurablyCanceled(t *testing.T) {
	for _, reason := range []string{"authorization", "canceled request", "expiry"} {
		t.Run(reason, func(t *testing.T) {
			svc, repo, _, _, now, _ := lifecycleFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			record := lifecycleRecord(*now)
			record.Recording = &backend.RecordingMetadata{FormatVersion: 1, StartedAt: *now, StreamExpiresAt: now.Add(time.Minute), PodNamespace: "target", PodName: "debug", PodUID: "pod-uid", Operation: "exec", LeaseUID: "lease-uid", LeaseEpoch: "1", Generation: "1"}
			calls := 0
			_, err := svc.ReserveRecording(ctx, record, func(context.Context) error {
				calls++
				if calls == 1 {
					return nil
				}
				if reason == "expiry" {
					*now = record.ExpiresAt
					return nil
				}
				if reason == "canceled request" {
					cancel()
					return context.Canceled
				}
				return backend.ErrForbidden
			})
			require.Error(t, err)
			if reason == "expiry" {
				require.ErrorIs(t, err, backend.ErrExpired)
			}
			records, err := repo.ListBySession(context.Background(), record.Namespace, record.SessionName, record.SessionUID)
			require.NoError(t, err)
			require.Len(t, records, 1)
			require.NotEmpty(t, records[0].ArtifactUID)
			expected := backend.StateRevoked
			if reason == "expiry" {
				expected = backend.StateExpired
			}
			require.Equal(t, expected, records[0].State)
			require.Zero(t, records[0].Size)
		})
	}
}

func TestCollectorReconcileCleansDefinitiveRevocation(t *testing.T) {
	for _, scenario := range []string{"terminal before create", "terminal after secret create", "terminal after lost UID", "lease revoked", "lease holder changed", "lease epoch changed", "lease expired", "lease target changed", "lease profile changed", "transient session read", "transient lease read"} {
		t.Run(scenario, func(t *testing.T) {
			svc, repo, _, keys, now, hub := lifecycleFixture(t)
			ctx := context.Background()
			require.NoError(t, corev1.AddToScheme(hub.Scheme()))
			require.NoError(t, batchv1.AddToScheme(hub.Scheme()))
			require.NoError(t, coordinationv1.AddToScheme(hub.Scheme()))
			expires := metav1.NewTime(now.Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: "session-uid"}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", TargetNamespace: "target"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expires, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{}}}
			require.NoError(t, hub.Create(ctx, session))
			leaseRef, err := debug.NewConnectionLeaseService(hub).WithLiveReader(hub).AcquireForSession(ctx, session, "cluster-uid")
			require.NoError(t, err)
			session.Status.ConnectionLease = &leaseRef
			require.NoError(t, hub.Update(ctx, session))
			record := lifecycleRecord(*now)
			record.ConnectionLeaseUID = string(leaseRef.UID)
			reserved, err := svc.Reserve(ctx, record)
			require.NoError(t, err)
			revoke := func() {
				require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), session))
				session.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
				require.NoError(t, hub.Update(ctx, session))
			}
			spoke := interceptor.NewClient(fake.NewClientBuilder().WithScheme(hub.Scheme()).Build(), interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.CreateOption) error {
				o.SetUID(types.UID("target-" + o.GetName()))
				if err := c.Create(ctx, o, opts...); err != nil {
					return err
				}
				if scenario == "terminal after secret create" || scenario == "terminal after lost UID" {
					revoke()
				}
				return nil
			}})
			provider := lifecycleTarget{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: "cluster-uid"}}}
			reconciler := &artifactcontroller.Reconciler{Client: hub, LiveReader: hub, Service: svc, TokenIssuer: &uploadTokenIssuer{keyring: keys, now: func() time.Time { return *now }}, Image: "registry.example/collector@sha256:" + strings.Repeat("c", 64), ControllerURL: "https://breakglass.example", ClusterProvider: provider}
			if scenario == "terminal after lost UID" {
				reconciler.Client = interceptor.NewClient(hub.(client.WithWatch), interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, o client.Object, opts ...client.SubResourceUpdateOption) error {
					if a, ok := o.(*breakglassv1alpha1.DebugSessionArtifact); ok {
						for _, resource := range a.Status.Resources {
							if resource.UID != "" {
								return errors.New("lost UID outcome")
							}
						}
					}
					return c.SubResource(sub).Update(ctx, o, opts...)
				}})
			}
			request := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "controller", Name: reserved.ArtifactID}}
			_, err = reconciler.Reconcile(ctx, request)
			require.NoError(t, err)
			switch scenario {
			case "terminal before create":
				revoke()
			case "lease revoked":
				require.NoError(t, hub.Delete(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: leaseRef.Namespace, Name: leaseRef.Name}}))
			case "lease holder changed", "lease epoch changed", "lease expired", "lease target changed", "lease profile changed":
				var lease coordinationv1.Lease
				require.NoError(t, hub.Get(ctx, client.ObjectKey{Namespace: leaseRef.Namespace, Name: leaseRef.Name}, &lease))
				switch scenario {
				case "lease holder changed":
					holder := "other-session"
					lease.Spec.HolderIdentity = &holder
				case "lease epoch changed":
					lease.Annotations["breakglass.telekom.com/connection-epoch"] = "99"
				case "lease expired":
					lease.Spec.RenewTime = &metav1.MicroTime{Time: now.Add(-2 * time.Hour)}
				case "lease target changed":
					lease.Annotations["breakglass.telekom.com/connection-target-uid"] = "replacement-target"
				case "lease profile changed":
					lease.Annotations["breakglass.telekom.com/connection-profile-digest"] = "replacement-profile"
				}
				require.NoError(t, hub.Update(ctx, &lease))
			case "transient session read", "transient lease read":
				reconciler.LiveReader = interceptor.NewClient(hub.(client.WithWatch), interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, o client.Object, opts ...client.GetOption) error {
					_, sessionRead := o.(*breakglassv1alpha1.DebugSession)
					_, leaseRead := o.(*coordinationv1.Lease)
					if sessionRead && scenario == "transient session read" || leaseRead && scenario == "transient lease read" {
						return errors.New("temporary API outage")
					}
					return c.Get(ctx, key, o, opts...)
				}})
			}
			_, err = reconciler.Reconcile(ctx, request)
			if strings.HasPrefix(scenario, "transient") {
				require.ErrorContains(t, err, "temporary API outage")
			} else if scenario == "terminal after lost UID" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			persisted, getErr := repo.Get(ctx, record.Namespace, record.SessionName, reserved.ArtifactID)
			require.NoError(t, getErr)
			require.Equal(t, reserved.ArtifactUID, persisted.ArtifactUID)
			if strings.HasPrefix(scenario, "transient") {
				require.Equal(t, backend.StatePending, persisted.State)
			} else {
				require.Equal(t, backend.StateRevoked, persisted.State)
			}
			var secrets corev1.SecretList
			var jobs batchv1.JobList
			require.NoError(t, spoke.List(ctx, &secrets))
			require.NoError(t, spoke.List(ctx, &jobs))
			if scenario == "terminal after lost UID" {
				require.Len(t, secrets.Items, 1)
				var retained breakglassv1alpha1.DebugSessionArtifact
				require.NoError(t, hub.Get(ctx, request.NamespacedName, &retained))
				require.Len(t, retained.Status.Resources, 1)
				require.Empty(t, retained.Status.Resources[0].UID)
				require.NotEmpty(t, retained.Finalizers)
				_, err = reconciler.Reconcile(ctx, request)
				require.Error(t, err)
				require.NoError(t, hub.Get(ctx, request.NamespacedName, &retained))
				return
			}
			require.Empty(t, secrets.Items)
			require.Empty(t, jobs.Items)
			if !strings.HasPrefix(scenario, "transient") {
				_, err = reconciler.Reconcile(ctx, request)
				require.NoError(t, err)
				var deleted breakglassv1alpha1.DebugSessionArtifact
				require.True(t, apierrors.IsNotFound(hub.Get(ctx, request.NamespacedName, &deleted)))
			}
		})
	}
}

func TestUploadReplacementDuringProviderPutCannotMutateReplacement(t *testing.T) {
	svc, _, store, keys, now, hub := lifecycleFixture(t)
	ctx := context.Background()
	reserved, err := svc.Reserve(ctx, lifecycleRecord(*now))
	require.NoError(t, err)
	route := "/api/debugSessionArtifactUploads/" + reserved.Namespace + "/" + reserved.SessionName + "/" + reserved.ArtifactID
	signed, err := backend.ReservationToken(keys, reserved, route, *now, 15*time.Minute)
	require.NoError(t, err)
	body := validLocalArchive(t, reserved.Expected)
	var replacement breakglassv1alpha1.DebugSessionArtifact
	var replacementKey string
	store.beforePut = func() {
		var original breakglassv1alpha1.DebugSessionArtifact
		key := client.ObjectKey{Namespace: "controller", Name: reserved.ArtifactID}
		require.NoError(t, hub.Get(ctx, key, &original))
		require.NoError(t, hub.Delete(ctx, &original))
		replacement = *original.DeepCopy()
		replacement.UID = "replacement-artifact"
		replacement.ResourceVersion = ""
		require.NoError(t, hub.Create(ctx, &replacement))
		require.NoError(t, hub.Get(ctx, key, &replacement))
		hash := sha256.Sum256([]byte("breakglass-artifact-v1:" + string(replacement.UID)))
		replacementKey = hex.EncodeToString(hash[:])
		digest := sha256.Sum256(body)
		_, putErr := store.Store.PutIfAbsent(ctx, storage.Object{Key: replacementKey, RuntimeBindingDigest: reserved.RuntimeBindingDigest, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}, bytes.NewReader(body))
		require.NoError(t, putErr)
	}
	_, err = svc.Upload(ctx, signed, route, bytes.NewReader(body))
	require.ErrorIs(t, err, backend.ErrConflict)
	var current breakglassv1alpha1.DebugSessionArtifact
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(&replacement), &current))
	require.Equal(t, replacement, current, "old upload must not publish or clean a replacement")
	versions, err := store.InventoryKey(ctx, replacementKey)
	require.NoError(t, err)
	require.Len(t, versions, 1)
}

type conflictingReservationRepository struct {
	*kube.Repository
	injected bool
}

func (r *conflictingReservationRepository) Update(ctx context.Context, record backend.Record, expected int64) error {
	if !r.injected {
		r.injected = true
		concurrent, err := r.Get(ctx, record.Namespace, record.SessionName, record.ArtifactID)
		if err != nil {
			return err
		}
		concurrent.Generation++
		if err := r.Repository.Update(ctx, concurrent, concurrent.Generation-1); err != nil {
			return err
		}
	}
	return r.Repository.Update(ctx, record, expected)
}
func TestRejectedReservationRetriesActualDurableConflict(t *testing.T) {
	_, repo, store, keys, now, _ := lifecycleFixture(t)
	conflicting := &conflictingReservationRepository{Repository: repo}
	svc, err := backend.New(backend.Config{Repository: conflicting, Store: store, Authorizer: allowLifecycle{}, Tokens: keys, StagingDir: t.TempDir(), Now: func() time.Time { return *now }})
	require.NoError(t, err)
	record := lifecycleRecord(*now)
	record.Recording = &backend.RecordingMetadata{FormatVersion: 1, StartedAt: *now, StreamExpiresAt: now.Add(time.Minute), PodNamespace: "target", PodName: "debug", PodUID: "pod-uid", Operation: "exec", LeaseUID: "lease-uid", LeaseEpoch: "1", Generation: "1"}
	calls := 0
	_, err = svc.ReserveRecording(context.Background(), record, func(context.Context) error {
		calls++
		if calls == 2 {
			return backend.ErrForbidden
		}
		return nil
	})
	require.ErrorIs(t, err, backend.ErrForbidden)
	require.NotErrorIs(t, err, backend.ErrConflict)
	require.True(t, conflicting.injected)
	records, err := repo.ListBySession(context.Background(), record.Namespace, record.SessionName, record.SessionUID)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, backend.StateRevoked, records[0].State)
	require.GreaterOrEqual(t, records[0].Generation, int64(3))
}

func TestAvailableCollectorEvidenceFollowsSessionLifecycle(t *testing.T) {
	for _, scenario := range []string{"terminate", "delete", "expire", "unreadable session", "provider outage"} {
		t.Run(scenario, func(t *testing.T) {
			svc, repo, store, keys, now, hub := lifecycleFixture(t)
			ctx := context.Background()
			require.NoError(t, coordinationv1.AddToScheme(hub.Scheme()))
			expires := metav1.NewTime(now.Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: "session-uid"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expires, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{}}}
			require.NoError(t, hub.Create(ctx, session))
			leaseRef, err := debug.NewConnectionLeaseService(hub).WithLiveReader(hub).AcquireForSession(ctx, session, "cluster-uid")
			require.NoError(t, err)
			session.Status.ConnectionLease = &leaseRef
			require.NoError(t, hub.Update(ctx, session))
			record := lifecycleRecord(*now)
			record.ConnectionLeaseUID = string(leaseRef.UID)
			reserved, err := svc.Reserve(ctx, record)
			require.NoError(t, err)
			route := "/api/debugSessionArtifactUploads/" + record.Namespace + "/" + record.SessionName + "/" + reserved.ArtifactID
			signed, err := backend.ReservationToken(keys, reserved, route, *now, 15*time.Minute)
			require.NoError(t, err)
			body := validLocalArchive(t, reserved.Expected)
			_, err = svc.Upload(ctx, signed, route, bytes.NewReader(body))
			require.NoError(t, err)
			available, err := repo.Get(ctx, record.Namespace, record.SessionName, reserved.ArtifactID)
			require.NoError(t, err)
			require.Equal(t, backend.StateAvailable, available.State)
			reconciler := &artifactcontroller.Reconciler{Client: hub, LiveReader: hub, Service: svc}
			request := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "controller", Name: reserved.ArtifactID}}
			_, err = reconciler.Reconcile(ctx, request)
			require.NoError(t, err)
			result, err := reconciler.Reconcile(ctx, request)
			require.NoError(t, err, "Available must not require a workload provider/image/token issuer")
			require.Positive(t, result.RequeueAfter)
			require.LessOrEqual(t, result.RequeueAfter, 30*time.Second)
			hash := sha256.Sum256([]byte("breakglass-artifact-v1:" + reserved.ArtifactUID))
			key := hex.EncodeToString(hash[:])
			versions, err := store.InventoryKey(ctx, key)
			require.NoError(t, err)
			require.Len(t, versions, 1)
			switch scenario {
			case "delete":
				require.NoError(t, hub.Delete(ctx, session))
			case "expire":
				past := metav1.NewTime(now.Add(-time.Second))
				session.Status.ExpiresAt = &past
				require.NoError(t, hub.Update(ctx, session))
			case "unreadable session":
				reconciler.LiveReader = interceptor.NewClient(hub.(client.WithWatch), interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, o client.Object, opts ...client.GetOption) error {
					if _, ok := o.(*breakglassv1alpha1.DebugSession); ok {
						return errors.New("session API unavailable")
					}
					return c.Get(ctx, key, o, opts...)
				}})
			default:
				session.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
				require.NoError(t, hub.Update(ctx, session))
			}
			if scenario == "provider outage" {
				store.inventoryErr = errors.New("provider unavailable")
			}
			_, err = reconciler.Reconcile(ctx, request)
			if scenario == "unreadable session" || scenario == "provider outage" {
				require.Error(t, err)
				var retained breakglassv1alpha1.DebugSessionArtifact
				require.NoError(t, hub.Get(ctx, request.NamespacedName, &retained))
				require.NotEmpty(t, retained.Finalizers)
				versions, readErr := store.InventoryKey(ctx, key)
				require.NoError(t, readErr)
				require.Len(t, versions, 1)
				if scenario == "unreadable session" {
					require.Equal(t, breakglassv1alpha1.ArtifactStateAvailable, retained.Status.State)
					return
				}
				store.inventoryErr = nil
			} else {
				require.NoError(t, err)
			}
			for attempt := 0; attempt < 3; attempt++ {
				_, err = reconciler.Reconcile(ctx, request)
				require.NoError(t, err)
			}
			versions, err = store.InventoryKey(ctx, key)
			require.NoError(t, err)
			require.Empty(t, versions)
			var deleted breakglassv1alpha1.DebugSessionArtifact
			require.True(t, apierrors.IsNotFound(hub.Get(ctx, request.NamespacedName, &deleted)))
		})
	}
}

func TestAvailableRecordingRetainsEvidenceAfterSessionDeletion(t *testing.T) {
	svc, repo, store, _, now, hub := lifecycleFixture(t)
	record := lifecycleRecord(*now)
	record.Recording = &backend.RecordingMetadata{FormatVersion: 1, StartedAt: *now, StreamExpiresAt: now.Add(time.Minute), PodNamespace: "target", PodName: "debug", PodUID: "pod-uid", Operation: "exec", LeaseUID: "lease-uid", LeaseEpoch: "1", Generation: "1"}
	reserved, err := svc.ReserveRecording(context.Background(), record, func(context.Context) error { return nil })
	require.NoError(t, err)
	frame := make([]byte, 42)
	frame[0], frame[1] = 1, 'o'
	metadata := *reserved.Recording
	metadata.FinishedAt = now.Add(time.Second)
	metadata.Complete = true
	_, err = svc.FinalizeRecording(context.Background(), reserved, bytes.NewReader(frame), metadata)
	require.NoError(t, err)
	// No live session exists. Recording evidence has independent retention and
	// must not enter collector revocation cleanup merely because it was deleted.
	reconciler := &artifactcontroller.Reconciler{Client: hub, LiveReader: hub, Service: svc}
	request := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "controller", Name: reserved.ArtifactID}}
	for attempt := 0; attempt < 2; attempt++ {
		_, err = reconciler.Reconcile(context.Background(), request)
		require.NoError(t, err)
	}
	retained, err := repo.Get(context.Background(), record.Namespace, record.SessionName, reserved.ArtifactID)
	require.NoError(t, err)
	require.Equal(t, backend.StateAvailable, retained.State)
	require.Equal(t, reserved.ArtifactUID, retained.ArtifactUID)
	hash := sha256.Sum256([]byte("breakglass-artifact-v1:" + reserved.ArtifactUID))
	versions, err := store.InventoryKey(context.Background(), hex.EncodeToString(hash[:]))
	require.NoError(t, err)
	require.Len(t, versions, 1)
}
