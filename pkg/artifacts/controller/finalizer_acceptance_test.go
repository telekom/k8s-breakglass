// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

type scriptedProvider struct {
	client      client.Client
	config      *breakglassv1alpha1.ClusterConfig
	getErr      error
	validateErr error
}

func (p *scriptedProvider) GetClientForPrivilegedOperation(context.Context, string) (client.Client, *breakglassv1alpha1.ClusterConfig, error) {
	if p.getErr != nil {
		return nil, nil, p.getErr
	}
	return p.client, p.config, nil
}
func (p *scriptedProvider) ValidatePrivilegedOperationClusterConfig(context.Context, *breakglassv1alpha1.ClusterConfig) error {
	return p.validateErr
}
func (*scriptedProvider) ReleasePrivilegedOperationClusterConfig(*breakglassv1alpha1.ClusterConfig) {
}

// TCAAS-1627: while tracked collector resources may still exist, the finalizer and
// inventory are retained unless cleanup is positively proven. Absent (missing
// ClusterConfig, deleted session) and unreachable (API error) are both ambiguous.
func TestReconcileRetainsFinalizerWhenTargetStateIsAmbiguous(t *testing.T) {
	notFound := apierrors.NewNotFound(schema.GroupResource{Group: "breakglass.t-caas.telekom.com", Resource: "clusterconfigs"}, "spoke")
	for _, tc := range []struct {
		name       string
		provider   func(spoke client.Client) *scriptedProvider
		noTarget   bool // exercise the path that resolves the cluster through the live session
		spokeError bool
	}{
		{name: "ClusterConfig absent", provider: func(client.Client) *scriptedProvider { return &scriptedProvider{getErr: notFound} }},
		{name: "target unreachable", provider: func(client.Client) *scriptedProvider {
			return &scriptedProvider{getErr: errors.New("dial tcp: i/o timeout")}
		}},
		{name: "ClusterConfig UID mismatch", provider: func(spoke client.Client) *scriptedProvider {
			return &scriptedProvider{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: "replacement"}}}
		}},
		{name: "ClusterConfig no longer valid", provider: func(spoke client.Client) *scriptedProvider {
			return &scriptedProvider{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: "cluster-uid"}}, validateErr: errors.New("spoke credentials unreadable")}
		}},
		{name: "spoke read fails", spokeError: true, provider: func(spoke client.Client) *scriptedProvider {
			return &scriptedProvider{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: "cluster-uid"}}}
		}},
		{name: "no persisted target and session absent", noTarget: true, provider: func(spoke client.Client) *scriptedProvider {
			return &scriptedProvider{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: "cluster-uid"}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hub, spoke, artifact := ambiguityFixture(t, tc.noTarget, tc.spokeError)
			reconciler := &Reconciler{Client: hub, LiveReader: hub, ClusterProvider: tc.provider(spoke)}
			// Two independent guards: cleanup itself must fail, and Reconcile must also
			// refuse to finalize while the inventory is non-empty.
			require.Error(t, reconciler.cleanupSpokeResources(context.Background(), artifact.DeepCopy()))
			_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(artifact)})
			require.Error(t, err)
			var current breakglassv1alpha1.DebugSessionArtifact
			require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(artifact), &current), "artifact must not be finalized")
			require.Contains(t, current.Finalizers, artifactFinalizer)
			require.Len(t, current.Status.Resources, 2, "tracked inventory must be retained")
			if !tc.spokeError { // the injected read error also hides the Secret from this assertion
				require.NoError(t, spoke.Get(context.Background(), types.NamespacedName{Namespace: "target", Name: "upload"}, &corev1.Secret{}), "nothing may be deleted when the target is ambiguous")
			}
		})
	}
}

// Control: the same artifact is finalized once the target is definitively clean,
// proving the retention above comes from the ambiguity checks and not the fixture.
func TestReconcileReleasesFinalizerWhenTargetIsProvenClean(t *testing.T) {
	hub, spoke, artifact := ambiguityFixture(t, false, false)
	provider := &scriptedProvider{client: spoke, config: &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{UID: "cluster-uid"}}}
	reconciler := &Reconciler{Client: hub, LiveReader: hub, ClusterProvider: provider}
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(artifact)})
	require.NoError(t, err)
	require.True(t, apierrors.IsNotFound(hub.Get(context.Background(), client.ObjectKeyFromObject(artifact), &breakglassv1alpha1.DebugSessionArtifact{})))
	require.True(t, apierrors.IsNotFound(spoke.Get(context.Background(), types.NamespacedName{Namespace: "target", Name: "upload"}, &corev1.Secret{})))
}

func ambiguityFixture(t *testing.T, noTarget, spokeError bool) (client.Client, client.Client, *breakglassv1alpha1.DebugSessionArtifact) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))
	base := artifactForValidation()
	artifact := &base
	now := metav1.Now()
	artifact.DeletionTimestamp = &now
	artifact.Finalizers = []string{artifactFinalizer}
	artifact.Status.State = "Deleted"
	artifact.Spec.TargetClusterUID = "cluster-uid"
	artifact.Status.TargetNamespace = "target"
	if !noTarget {
		artifact.Status.TargetCluster = "spoke"
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "upload", Namespace: "target", UID: "secret-uid"}}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "collect", Namespace: "target", UID: "job-uid"}}
	artifact.Status.Resources = []breakglassv1alpha1.ArtifactResourceReference{
		{Kind: "Secret", Namespace: "target", Name: "upload", UID: "secret-uid", OperationID: "artifact-uid/secret"},
		{Kind: "Job", Namespace: "target", Name: "collect", UID: "job-uid", OperationID: "artifact-uid/job"},
	}
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(artifact).WithStatusSubresource(artifact).Build()
	spokeBuilder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret, job)
	if spokeError {
		spokeBuilder = spokeBuilder.WithInterceptorFuncs(interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok && key.Name == "upload" {
				return errors.New("etcdserver: request timed out")
			}
			return c.Get(ctx, key, obj, opts...)
		}})
	}
	return hub, spokeBuilder.Build(), artifact
}
