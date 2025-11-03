package breakglass

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/das-schiff-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestClusterConfigChecker_MissingSecret(t *testing.T) {
	// Setup: ClusterConfig referencing a secret that doesn't exist
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-a", Namespace: "default"},
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "missing", Namespace: "default"}},
	}
	cl := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc).Build()
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	// run once
	checker.runOnce(context.Background(), checker.Log)
	// read updated CC from client
	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	require.Equal(t, "Failed", got.Status.Phase)
}

func TestClusterConfigChecker_MissingKey(t *testing.T) {
	// secret exists but missing key 'value'
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "default"}, Data: map[string][]byte{"other": []byte("x")}}
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-b", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "s1", Namespace: "default"}}}
	cl := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc, sec).Build()
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	checker.runOnce(context.Background(), checker.Log)
	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	require.Equal(t, "Failed", got.Status.Phase)
}

func TestClusterConfigChecker_ParseFail(t *testing.T) {
	// secret contains key but invalid kubeconfig
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s2", Namespace: "default"}, Data: map[string][]byte{"value": []byte("not-a-kubeconfig")}}
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-c", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "s2", Namespace: "default"}}}
	cl := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc, sec).Build()
	fakeRecorder := record.NewFakeRecorder(10)
	// stub RestConfigFromKubeConfig to return error
	old := RestConfigFromKubeConfig
	RestConfigFromKubeConfig = func(b []byte) (*rest.Config, error) { return nil, errors.New("parse error") }
	defer func() { RestConfigFromKubeConfig = old }()
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	checker.runOnce(context.Background(), checker.Log)
	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	require.Equal(t, "Failed", got.Status.Phase)
}

func TestClusterConfigChecker_Unreachable(t *testing.T) {
	// secret contains key and parse OK, but cluster unreachable
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s3", Namespace: "default"}, Data: map[string][]byte{"value": []byte("fake-kubeconfig")}}
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-d", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "s3", Namespace: "default"}}}
	cl := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc, sec).Build()
	fakeRecorder := record.NewFakeRecorder(10)
	// stub RestConfigFromKubeConfig to return non-nil config
	old := RestConfigFromKubeConfig
	RestConfigFromKubeConfig = func(b []byte) (*rest.Config, error) { return &rest.Config{}, nil }
	defer func() { RestConfigFromKubeConfig = old }()
	// stub CheckClusterReachable to return error
	oldCheck := CheckClusterReachable
	CheckClusterReachable = func(cfg *rest.Config) error { return errors.New("timeout") }
	defer func() { CheckClusterReachable = oldCheck }()
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	checker.runOnce(context.Background(), checker.Log)
	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	require.Equal(t, "Failed", got.Status.Phase)
}

// helper: construct a client.ObjectKey for a ClusterConfig stored in the fake client
func clientKey(cc *telekomv1alpha1.ClusterConfig) client.ObjectKey {
	return client.ObjectKey{Namespace: cc.Namespace, Name: cc.Name}
}
