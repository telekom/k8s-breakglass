package breakglass

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
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

func TestClusterConfigManager_GetClusterConfigInNamespace(t *testing.T) {
	ctx := context.Background()

	t.Run("found in specified namespace", func(t *testing.T) {
		cc := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "test-ns"},
		}
		cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc).Build()
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigInNamespace(ctx, "test-ns", "my-cluster")
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, "my-cluster", got.Name)
		require.Equal(t, "test-ns", got.Namespace)
	})

	t.Run("not found in different namespace", func(t *testing.T) {
		cc := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "other-ns"},
		}
		cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc).Build()
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigInNamespace(ctx, "test-ns", "my-cluster")
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("not found when no cluster configs exist", func(t *testing.T) {
		cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigInNamespace(ctx, "test-ns", "missing")
		require.Error(t, err)
		require.Nil(t, got)
	})
}

func TestNewClusterConfigManager_Logger(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()

	t.Run("with explicit logger", func(t *testing.T) {
		testLogger := zaptest.NewLogger(t).Sugar()
		mgr := NewClusterConfigManager(cli, testLogger)

		assert.Same(t, testLogger, mgr.log)
		assert.Same(t, testLogger, mgr.getLog())
	})

	t.Run("without logger uses global", func(t *testing.T) {
		mgr := NewClusterConfigManager(cli)

		// Should default to the global sugared logger
		assert.Same(t, zap.S(), mgr.log)
	})

	t.Run("getLog returns nopLogger for zero-value", func(t *testing.T) {
		mgr := &ClusterConfigManager{} // zero-value, log is nil
		got := mgr.getLog()

		assert.NotNil(t, got)
		assert.Same(t, nopLogger, got)
	})

	t.Run("getLog returns nopLogger for nil receiver", func(t *testing.T) {
		var mgr *ClusterConfigManager
		got := mgr.getLog()

		assert.NotNil(t, got)
		assert.Same(t, nopLogger, got)
	})
}
