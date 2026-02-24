package breakglass

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetClusterConfigByName(t *testing.T) {
	ctx := context.Background()

	t.Run("found", func(t *testing.T) {
		cc := &breakglassv1alpha1.ClusterConfig{
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
		cc1 := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "namespace1"},
		}
		cc2 := &breakglassv1alpha1.ClusterConfig{
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
		cc := &breakglassv1alpha1.ClusterConfig{
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
		cc := &breakglassv1alpha1.ClusterConfig{
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

func TestClusterConfigManager_LoggerInjection(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()

	t.Run("injected logger is used", func(t *testing.T) {
		logger, err := zap.NewDevelopment()
		require.NoError(t, err)
		t.Cleanup(func() { _ = logger.Sync() })
		sugar := logger.Sugar()
		mgr := NewClusterConfigManager(cli, WithClusterConfigLogger(sugar))

		require.Same(t, sugar, mgr.getLogger())
	})

	t.Run("fallback to global logger when no logger provided", func(t *testing.T) {
		mgr := NewClusterConfigManager(cli)

		require.Nil(t, mgr.log, "log field should be nil when no logger injected")
		// getLogger() should still return a non-nil logger (global fallback)
		require.NotNil(t, mgr.getLogger())
	})

	t.Run("nil option is safely skipped", func(t *testing.T) {
		mgr := NewClusterConfigManager(cli, nil)

		require.Nil(t, mgr.log, "nil option should not set the log field")
	})

	t.Run("WithClusterConfigLogger with nil logger is no-op", func(t *testing.T) {
		mgr := NewClusterConfigManager(cli, WithClusterConfigLogger(nil))

		require.Nil(t, mgr.log, "WithClusterConfigLogger(nil) should not set the log field")
	})
}
