package breakglass

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetClusterConfigByName(t *testing.T) {
	ctx := context.Background()

	t.Run("found", func(t *testing.T) {
		cc := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cluster"},
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
	})
}
