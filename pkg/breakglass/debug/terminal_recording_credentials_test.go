// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestClusterConfigCredentialSourceBindsToClusterUID(t *testing.T) {
	require.Nil(t, ClusterConfigCredentialSource(nil))
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	config := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Namespace: "hub", Name: "spoke", UID: "cluster-uid"}, Spec: breakglassv1alpha1.ClusterConfigSpec{
		KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Namespace: "hub", Name: "kubeconfig"},
	}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "hub", Name: "kubeconfig", UID: "secret-uid"}}
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(config, secret).Build()
	source := ClusterConfigCredentialSource(cluster.NewClientProvider(cli, zap.NewNop().Sugar()))

	credential, err := source(context.Background(), TerminalRecordingConnectionBinding{ClusterName: "spoke", TargetClusterUID: "cluster-uid"})
	require.NoError(t, err)
	require.Equal(t, "secret-uid", string(credential.UID))
	require.NotEmpty(t, credential.ResourceVersion)

	_, err = source(context.Background(), TerminalRecordingConnectionBinding{ClusterName: "spoke", TargetClusterUID: "replaced-uid"})
	require.ErrorContains(t, err, "cluster identity changed", "a replaced ClusterConfig must not inherit readiness")
	_, err = source(context.Background(), TerminalRecordingConnectionBinding{ClusterName: "absent", TargetClusterUID: "cluster-uid"})
	require.Error(t, err)
}
