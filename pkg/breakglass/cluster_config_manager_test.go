package breakglass

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetClusterConfigByName(t *testing.T) {
	ctx := context.Background()

	t.Run("found", func(t *testing.T) {
		cc := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "default"},
		}
		cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc).Build()
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigByName(ctx, "my-cluster")
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, "my-cluster", got.Name)
	})

	t.Run("not found", func(t *testing.T) {
		cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigByName(ctx, "missing")
		require.Error(t, err)
		require.Nil(t, got)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("duplicate cluster configs returns error", func(t *testing.T) {
		cc1 := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "namespace1"},
		}
		cc2 := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "namespace2"},
		}
		cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc1, cc2).Build()
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigByName(ctx, "my-cluster")
		require.Error(t, err)
		require.Nil(t, got)
		require.Contains(t, err.Error(), "is not unique")
		require.Contains(t, err.Error(), "namespace1")
		require.Contains(t, err.Error(), "namespace2")
	})
}
