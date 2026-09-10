// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

type testTokenIssuer struct{}

func (testTokenIssuer) IssueUploadToken(context.Context, backend.Record, string) (string, error) {
	return "signed", nil
}

type testTargetProvider struct {
	client client.Client
	config *breakglassv1alpha1.ClusterConfig
}

type uidAssigningClient struct {
	client.Client
	next        int
	afterCreate func()
}

func (c *uidAssigningClient) Create(ctx context.Context, object client.Object, options ...client.CreateOption) error {
	c.next++
	if object.GetUID() == "" {
		object.SetUID(types.UID(fmt.Sprintf("spoke-%d", c.next)))
	}
	if err := c.Client.Create(ctx, object, options...); err != nil {
		return err
	}
	if c.afterCreate != nil {
		c.afterCreate()
	}
	return nil
}

func (p *testTargetProvider) GetClientForPrivilegedOperation(context.Context, string) (client.Client, *breakglassv1alpha1.ClusterConfig, error) {
	return p.client, p.config, nil
}
func (p *testTargetProvider) ValidatePrivilegedOperationClusterConfig(context.Context, *breakglassv1alpha1.ClusterConfig) error {
	return nil
}
func (*testTargetProvider) ReleasePrivilegedOperationClusterConfig(*breakglassv1alpha1.ClusterConfig) {
}

func artifactForValidation() breakglassv1alpha1.DebugSessionArtifact {
	return breakglassv1alpha1.DebugSessionArtifact{
		ObjectMeta: metav1.ObjectMeta{Name: "dsa-000000000000000000000000", Namespace: "breakglass", UID: types.UID("artifact-uid")},
		Spec:       breakglassv1alpha1.DebugSessionArtifactSpec{ArtifactID: "dsa-000000000000000000000000", SessionRef: breakglassv1alpha1.ArtifactSessionReference{Namespace: "breakglass", Name: "session", UID: "session-uid"}},
		Status:     breakglassv1alpha1.DebugSessionArtifactStatus{},
	}
}

func TestValidateTokenSecretRequiresArtifactOwnerAndImmutableToken(t *testing.T) {
	artifact := artifactForValidation()
	valid := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: artifact.Namespace, Annotations: map[string]string{"breakglass.t-caas.telekom.com/artifact-uid": string(artifact.UID), "breakglass.t-caas.telekom.com/operation-id": "op"}}, Immutable: boolPtr(true), Data: map[string][]byte{"token": []byte("signed")}}
	if err := validateTokenSecret(valid, artifact, artifact.Namespace, "op"); err != nil {
		t.Fatalf("valid token Secret rejected: %v", err)
	}
	for name, mutate := range map[string]func(*corev1.Secret){
		"mutable":       func(secret *corev1.Secret) { secret.Immutable = boolPtr(false) },
		"missing token": func(secret *corev1.Secret) { delete(secret.Data, "token") },
		"wrong owner": func(secret *corev1.Secret) {
			secret.Annotations["breakglass.t-caas.telekom.com/artifact-uid"] = "other"
		},
	} {
		t.Run(name, func(t *testing.T) {
			modified := valid.DeepCopy()
			mutate(modified)
			if err := validateTokenSecret(*modified, artifact, artifact.Namespace, "op"); err == nil {
				t.Fatal("invalid token Secret accepted")
			}
		})
	}
}

func TestValidateCollectorJobRequiresMatchingArtifactOwnership(t *testing.T) {
	artifact := artifactForValidation()
	group := int64(65532)
	valid := batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: artifact.Namespace, Annotations: map[string]string{"breakglass.t-caas.telekom.com/plan-sha256": artifact.Spec.PlanDigest, "breakglass.t-caas.telekom.com/artifact-uid": string(artifact.UID), "breakglass.t-caas.telekom.com/operation-id": "op"}, Labels: map[string]string{"breakglass.t-caas.telekom.com/artifact": artifact.Spec.ArtifactID, "breakglass.t-caas.telekom.com/session-uid": artifact.Spec.SessionRef.UID}}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"breakglass.t-caas.telekom.com/plan-sha256": artifact.Spec.PlanDigest}}, Spec: corev1.PodSpec{AutomountServiceAccountToken: boolPtr(false), SecurityContext: &corev1.PodSecurityContext{FSGroup: &group}, InitContainers: []corev1.Container{{Name: "collector"}}, Containers: []corev1.Container{{Name: "uploader"}}}}}}
	if err := validateCollectorJob(valid, artifact, artifact.Namespace, "op"); err != nil {
		t.Fatalf("valid collector Job rejected: %v", err)
	}
	for name, mutate := range map[string]func(*batchv1.Job){
		"wrong artifact label":    func(job *batchv1.Job) { job.Labels["breakglass.t-caas.telekom.com/artifact"] = "other" },
		"wrong owner":             func(job *batchv1.Job) { job.Annotations["breakglass.t-caas.telekom.com/artifact-uid"] = "other" },
		"wrong namespace":         func(job *batchv1.Job) { job.Namespace = "other" },
		"side-by-side containers": func(job *batchv1.Job) { job.Spec.Template.Spec.InitContainers = nil },
	} {
		t.Run(name, func(t *testing.T) {
			modified := valid.DeepCopy()
			mutate(modified)
			if err := validateCollectorJob(*modified, artifact, artifact.Namespace, "op"); err == nil {
				t.Fatal("invalid collector Job accepted")
			}
		})
	}
}

func TestEnsureUploadResourcesWritesOnlyToTargetClientAndCapturesUIDs(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))
	expires := metav1.NewTime(time.Now().Add(time.Hour))
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "breakglass", UID: types.UID("session-uid")}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", TargetNamespace: "target"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expires}}
	artifact := artifactForValidation()
	artifact.Spec.TargetClusterUID = "cluster-uid"
	artifact.Spec.Recipe = "system-summary.v1"
	artifact.Spec.RecipeVersion = 1
	artifact.Spec.PlanDigest = strings.Repeat("a", 64)
	artifact.Spec.RuntimeBindingDigest = strings.Repeat("b", 64)
	artifact.Spec.RedactionProfile = "default"
	artifact.Spec.RedactionVersion = 1
	artifact.Spec.MaxBytes = 1024
	artifact.Spec.TimeoutSeconds = 30
	artifact.Spec.Inputs.MaxArchiveBytes = 1024
	artifact.Spec.ExpiresAt = expires
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session, &artifact).WithStatusSubresource(&breakglassv1alpha1.DebugSessionArtifact{}).Build()
	spoke := &uidAssigningClient{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
	provider := &testTargetProvider{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: types.UID("cluster-uid")}}}
	reconciler := &Reconciler{Client: hub, LiveReader: hub, TokenIssuer: testTokenIssuer{}, Image: "registry.example/collector@sha256:" + strings.Repeat("c", 64), ControllerURL: "https://breakglass.example", ClusterProvider: provider}
	require.NoError(t, reconciler.ensureUploadResources(context.Background(), artifact, backend.Record{ArtifactID: artifact.Spec.ArtifactID, ArtifactUID: string(artifact.UID), SessionUID: artifact.Spec.SessionRef.UID, Namespace: artifact.Spec.SessionRef.Namespace, SessionName: artifact.Spec.SessionRef.Name, ExpiresAt: expires.Time}))
	var spokeJob batchv1.Job
	require.NoError(t, spoke.Get(context.Background(), types.NamespacedName{Namespace: "target", Name: artifact.Spec.ArtifactID + "-collect"}, &spokeJob))
	var spokeSecret corev1.Secret
	require.NoError(t, spoke.Get(context.Background(), types.NamespacedName{Namespace: "target", Name: artifact.Spec.ArtifactID + "-upload"}, &spokeSecret))
	var hubJob batchv1.Job
	require.Error(t, hub.Get(context.Background(), types.NamespacedName{Namespace: artifact.Namespace, Name: artifact.Spec.ArtifactID + "-collect"}, &hubJob))
	var updated breakglassv1alpha1.DebugSessionArtifact
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(&artifact), &updated))
	require.Equal(t, string(spokeSecret.UID), updated.Status.Resources[0].UID)
	require.Equal(t, string(spokeJob.UID), updated.Status.Resources[1].UID)
	// A same-name replacement must never be adopted after the persisted UID
	// changes. The controller fails closed and leaves cleanup evidence intact.
	require.NoError(t, spoke.Delete(context.Background(), &spokeSecret))
	replacement := spokeSecret.DeepCopy()
	replacement.UID = types.UID("replacement-secret")
	replacement.ResourceVersion = ""
	require.NoError(t, spoke.Create(context.Background(), replacement))
	require.ErrorContains(t, reconciler.ensureUploadResources(context.Background(), artifact, backend.Record{ArtifactID: artifact.Spec.ArtifactID, ArtifactUID: string(artifact.UID), SessionUID: artifact.Spec.SessionRef.UID, Namespace: artifact.Spec.SessionRef.Namespace, SessionName: artifact.Spec.SessionRef.Name, ExpiresAt: expires.Time}), "UID")
}

func TestCreateOutcomePersistsUIDBeforePostWriteRevocation(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))
	expires := metav1.NewTime(time.Now().Add(time.Hour))
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "breakglass", UID: types.UID("session-uid")}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", TargetNamespace: "target"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expires}}
	artifact := artifactForValidation()
	artifact.Spec.TargetClusterUID = "cluster-uid"
	artifact.Spec.Recipe, artifact.Spec.RecipeVersion = "system-summary.v1", 1
	artifact.Spec.PlanDigest, artifact.Spec.RuntimeBindingDigest = strings.Repeat("a", 64), strings.Repeat("b", 64)
	artifact.Spec.RedactionProfile, artifact.Spec.RedactionVersion = "default", 1
	artifact.Spec.MaxBytes, artifact.Spec.TimeoutSeconds, artifact.Spec.Inputs.MaxArchiveBytes, artifact.Spec.ExpiresAt = 1024, 30, 1024, expires
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session, &artifact).WithStatusSubresource(&breakglassv1alpha1.DebugSessionArtifact{}, &breakglassv1alpha1.DebugSession{}).Build()
	spoke := &uidAssigningClient{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
	spoke.afterCreate = func() {
		live := &breakglassv1alpha1.DebugSession{}
		_ = hub.Get(context.Background(), client.ObjectKeyFromObject(session), live)
		live.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
		if err := hub.Status().Update(context.Background(), live); err != nil {
			panic(err)
		}
	}
	provider := &testTargetProvider{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: types.UID("cluster-uid")}}}
	reconciler := &Reconciler{Client: hub, LiveReader: hub, TokenIssuer: testTokenIssuer{}, Image: "registry.example/collector@sha256:" + strings.Repeat("c", 64), ControllerURL: "https://breakglass.example", ClusterProvider: provider}
	require.Error(t, reconciler.ensureUploadResources(context.Background(), artifact, backend.Record{ArtifactID: artifact.Spec.ArtifactID, ArtifactUID: string(artifact.UID), SessionUID: artifact.Spec.SessionRef.UID, Namespace: artifact.Spec.SessionRef.Namespace, SessionName: artifact.Spec.SessionRef.Name, ExpiresAt: expires.Time}))
	updated := &breakglassv1alpha1.DebugSessionArtifact{}
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(&artifact), updated))
	require.NotEmpty(t, updated.Status.Resources[0].UID)
	require.NoError(t, reconciler.cleanupSpokeResources(context.Background(), updated))
	require.Error(t, spoke.Get(context.Background(), types.NamespacedName{Namespace: "target", Name: artifact.Spec.ArtifactID + "-upload"}, &corev1.Secret{}))
}

func TestCleanupRetainsUIDLessIntentAndBlocksFinalization(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	artifact := artifactForValidation()
	artifact.Status.TargetCluster = "spoke"
	artifact.Status.TargetNamespace = "target"
	artifact.Spec.TargetClusterUID = "cluster-uid"
	artifact.Status.Resources = []breakglassv1alpha1.ArtifactResourceReference{{Kind: "Secret", Namespace: "target", Name: "orphan-upload", OperationID: "artifact-uid/secret"}}
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&artifact).WithStatusSubresource(&breakglassv1alpha1.DebugSessionArtifact{}).Build()
	spoke := &uidAssigningClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "orphan-upload", Namespace: "target", UID: types.UID("live-secret")}}).Build()}
	provider := &testTargetProvider{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: types.UID("cluster-uid")}}}
	reconciler := &Reconciler{Client: hub, LiveReader: hub, ClusterProvider: provider}
	require.ErrorContains(t, reconciler.cleanupSpokeResources(context.Background(), &artifact), "pending")
	var current breakglassv1alpha1.DebugSessionArtifact
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(&artifact), &current))
	require.Len(t, current.Status.Resources, 1)
	require.Empty(t, current.Status.Resources[0].UID)
	var live corev1.Secret
	require.NoError(t, spoke.Get(context.Background(), types.NamespacedName{Namespace: "target", Name: "orphan-upload"}, &live))
}

func TestCleanupRemovesOnlyProvenResources(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))
	artifact := artifactForValidation()
	artifact.Spec.TargetClusterUID = "cluster-uid"
	artifact.Status.TargetCluster = "spoke"
	artifact.Status.TargetNamespace = "target"
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "upload", Namespace: "target", UID: types.UID("secret-uid")}}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "collect", Namespace: "target", UID: types.UID("job-uid")}}
	artifact.Status.Resources = []breakglassv1alpha1.ArtifactResourceReference{{Kind: "Secret", Namespace: "target", Name: "upload", UID: string(secret.UID), OperationID: "artifact-uid/secret"}, {Kind: "Job", Namespace: "target", Name: "collect", UID: string(job.UID), OperationID: "artifact-uid/job"}}
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&artifact).WithStatusSubresource(&breakglassv1alpha1.DebugSessionArtifact{}).Build()
	spoke := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret, job).Build()
	provider := &testTargetProvider{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: types.UID("cluster-uid")}}}
	reconciler := &Reconciler{Client: hub, LiveReader: hub, ClusterProvider: provider}
	require.NoError(t, reconciler.cleanupSpokeResources(context.Background(), &artifact))
	var current breakglassv1alpha1.DebugSessionArtifact
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(&artifact), &current))
	require.Empty(t, current.Status.Resources)
	require.Error(t, spoke.Get(context.Background(), client.ObjectKeyFromObject(secret), &corev1.Secret{}))
	require.Error(t, spoke.Get(context.Background(), client.ObjectKeyFromObject(job), &batchv1.Job{}))
}

func TestPersistResourceIntentRejectsTerminalArtifactButRecordsExistingUID(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	artifact := artifactForValidation()
	artifact.Status.State = breakglassv1alpha1.ArtifactStateExpired
	artifact.Status.Resources = []breakglassv1alpha1.ArtifactResourceReference{{Kind: "Secret", Namespace: "target", Name: "upload", UID: "secret-uid", OperationID: "artifact-uid/secret"}}
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&artifact).WithStatusSubresource(&breakglassv1alpha1.DebugSessionArtifact{}).Build()
	reconciler := &Reconciler{Client: hub, LiveReader: hub}
	_, err := reconciler.persistResourceIntent(context.Background(), &artifact, "Job", "target", "collect")
	require.ErrorContains(t, err, "no longer accepts")
	ref, err := reconciler.persistResourceIntent(context.Background(), &artifact, "Secret", "target", "upload")
	require.NoError(t, err)
	require.Equal(t, "secret-uid", ref.UID)
}
