// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func nativeTargetClusterConfig(t *testing.T, ctx context.Context, cli client.Client, reference string) *breakglassv1alpha1.ClusterConfig {
	t.Helper()
	var configs breakglassv1alpha1.ClusterConfigList
	require.NoError(t, cli.List(ctx, &configs))
	var exact, aliases []*breakglassv1alpha1.ClusterConfig
	for i := range configs.Items {
		config := &configs.Items[i]
		if config.Name == reference {
			exact = append(exact, config)
		}
		if config.Spec.Tenant == reference {
			aliases = append(aliases, config)
		}
	}
	if len(exact) > 0 {
		require.Len(t, exact, 1, "native target must resolve to one exact ClusterConfig")
		return exact[0]
	}
	require.Len(t, aliases, 1, "native target tenant alias must resolve to one real ClusterConfig")
	return aliases[0]
}

func TestNativeTargetClusterConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	canonical := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "real-cluster", Namespace: "controller-system"},
		Spec:       breakglassv1alpha1.ClusterConfigSpec{Tenant: "tenant-alias"},
	}
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(canonical).Build()
	resolved := nativeTargetClusterConfig(t, context.Background(), cli, "tenant-alias")
	require.Equal(t, canonical.Name, resolved.Name)
	require.Equal(t, canonical.Namespace, resolved.Namespace)

	exact := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-alias", Namespace: "another-system"},
	}
	require.NoError(t, cli.Create(context.Background(), exact))
	resolved = nativeTargetClusterConfig(t, context.Background(), cli, "tenant-alias")
	require.Equal(t, exact.Name, resolved.Name)
	require.Equal(t, exact.Namespace, resolved.Namespace)
}
