package breakglass

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newTestFakeClient creates a fake client with status subresource support for ClusterConfig.
// This is critical: when status subresource is enabled (via +kubebuilder:subresource:status),
// Status().Update() must be used to update status, and the fake client must be configured accordingly.
func newTestFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(objs...).
		WithStatusSubresource(&telekomv1alpha1.ClusterConfig{}).
		Build()
}

func TestClusterConfigChecker_MissingSecret(t *testing.T) {
	// Setup: ClusterConfig referencing a secret that doesn't exist
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-a", Namespace: "default"},
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "missing", Namespace: "default"}},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	// run once
	checker.runOnce(context.Background(), checker.Log)
	// read updated CC from client
	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	// Check Ready condition is False
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition, "Ready condition should be set after runOnce")
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Equal(t, "SecretMissing", readyCondition.Reason)
}

func TestClusterConfigChecker_MissingKey(t *testing.T) {
	// secret exists but missing key 'value'
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "default"}, Data: map[string][]byte{"other": []byte("x")}}
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-b", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "s1", Namespace: "default"}}}
	cl := newTestFakeClient(cc, sec)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	checker.runOnce(context.Background(), checker.Log)
	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	// Check Ready condition is False
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition, "Ready condition should be set after runOnce")
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Equal(t, "SecretMissing", readyCondition.Reason)
}

func TestClusterConfigChecker_ParseFail(t *testing.T) {
	// secret contains key but invalid kubeconfig
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s2", Namespace: "default"}, Data: map[string][]byte{"value": []byte("not-a-kubeconfig")}}
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-c", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "s2", Namespace: "default"}}}
	cl := newTestFakeClient(cc, sec)
	fakeRecorder := fakeEventRecorder{}
	// stub RestConfigFromKubeConfig to return error
	old := RestConfigFromKubeConfig
	RestConfigFromKubeConfig = func(b []byte) (*rest.Config, error) { return nil, errors.New("parse error") }
	defer func() { RestConfigFromKubeConfig = old }()
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	checker.runOnce(context.Background(), checker.Log)
	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	// Check Ready condition is False
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition, "Ready condition should be set after runOnce")
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Equal(t, "KubeconfigParseFailed", readyCondition.Reason)
}

func TestClusterConfigChecker_Unreachable(t *testing.T) {
	// secret contains key and parse OK, but cluster unreachable
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s3", Namespace: "default"}, Data: map[string][]byte{"value": []byte("fake-kubeconfig")}}
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-d", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "s3", Namespace: "default"}}}
	cl := newTestFakeClient(cc, sec)
	fakeRecorder := fakeEventRecorder{}
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
	// Check Ready condition is False
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition, "Ready condition should be set after runOnce")
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Equal(t, "ClusterUnreachable", readyCondition.Reason)
}

// TestClusterConfigChecker_SuccessfulValidation tests that when validation succeeds,
// the Ready condition is set to True with proper reason.
func TestClusterConfigChecker_SuccessfulValidation(t *testing.T) {
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "valid-secret", Namespace: "default"}, Data: map[string][]byte{"value": []byte("valid-kubeconfig")}}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-success", Namespace: "default", Generation: 1},
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "valid-secret", Namespace: "default"}},
	}
	cl := newTestFakeClient(cc, sec)
	fakeRecorder := fakeEventRecorder{}
	// stub RestConfigFromKubeConfig to return valid config
	old := RestConfigFromKubeConfig
	RestConfigFromKubeConfig = func(b []byte) (*rest.Config, error) { return &rest.Config{}, nil }
	defer func() { RestConfigFromKubeConfig = old }()
	// stub CheckClusterReachable to return success
	oldCheck := CheckClusterReachable
	CheckClusterReachable = func(cfg *rest.Config) error { return nil }
	defer func() { CheckClusterReachable = oldCheck }()

	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	// Check Ready condition is True
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition, "Ready condition should be set after runOnce")
	require.Equal(t, metav1.ConditionTrue, readyCondition.Status, "Ready should be True on successful validation")
	require.Equal(t, "KubeconfigValidated", readyCondition.Reason)
	require.Equal(t, int64(1), readyCondition.ObservedGeneration)
}

// TestClusterConfigChecker_StatusUpdatePersisted verifies that status updates are actually
// persisted to the API server. This test would fail if Status().Update() wasn't used correctly.
func TestClusterConfigChecker_StatusUpdatePersisted(t *testing.T) {
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"}, Data: map[string][]byte{"value": []byte("kubeconfig")}}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-persist-test", Namespace: "default", Generation: 5},
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "test-secret", Namespace: "default"}},
		// Start with an old condition
		Status: telekomv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionFalse,
					Reason:             "SecretMissing",
					Message:            "old error",
					ObservedGeneration: 1,
					LastTransitionTime: metav1.Now(),
				},
			},
			ObservedGeneration: 1,
		},
	}
	cl := newTestFakeClient(cc, sec)
	fakeRecorder := fakeEventRecorder{}
	// stub for successful validation
	old := RestConfigFromKubeConfig
	RestConfigFromKubeConfig = func(b []byte) (*rest.Config, error) { return &rest.Config{}, nil }
	defer func() { RestConfigFromKubeConfig = old }()
	oldCheck := CheckClusterReachable
	CheckClusterReachable = func(cfg *rest.Config) error { return nil }
	defer func() { CheckClusterReachable = oldCheck }()

	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	checker.runOnce(context.Background(), checker.Log)

	// Read back from client - this simulates reading from the API server
	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))

	// Verify the status was actually updated (not just modified in memory)
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition, "Ready condition must be present")
	require.Equal(t, metav1.ConditionTrue, readyCondition.Status, "Status should be updated to True")
	require.Equal(t, "KubeconfigValidated", readyCondition.Reason, "Reason should be updated")
	require.Equal(t, int64(5), readyCondition.ObservedGeneration, "ObservedGeneration should match current generation")
	require.Equal(t, int64(5), got.Status.ObservedGeneration, "Status.ObservedGeneration should be updated")
}

// TestClusterConfigChecker_TransitionFromFailToSuccess verifies that the status correctly
// transitions from a failure state to success when the problem is fixed.
func TestClusterConfigChecker_TransitionFromFailToSuccess(t *testing.T) {
	// Start with a ClusterConfig in a failed state (missing secret)
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-transition", Namespace: "default", Generation: 2},
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "transition-secret", Namespace: "default"}},
		Status: telekomv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionFalse,
					Reason:             "SecretMissing",
					Message:            "Secret not found",
					ObservedGeneration: 1,
					LastTransitionTime: metav1.Now(),
				},
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	// First check - secret still missing
	checker.runOnce(context.Background(), checker.Log)
	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	require.Equal(t, metav1.ConditionFalse, getCondition(got, "Ready").Status)

	// Now add the secret
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "transition-secret", Namespace: "default"}, Data: map[string][]byte{"value": []byte("kubeconfig")}}
	require.NoError(t, cl.Create(context.Background(), sec))

	// Stub successful validation
	old := RestConfigFromKubeConfig
	RestConfigFromKubeConfig = func(b []byte) (*rest.Config, error) { return &rest.Config{}, nil }
	defer func() { RestConfigFromKubeConfig = old }()
	oldCheck := CheckClusterReachable
	CheckClusterReachable = func(cfg *rest.Config) error { return nil }
	defer func() { CheckClusterReachable = oldCheck }()

	// Second check - should now succeed
	checker.runOnce(context.Background(), checker.Log)
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionTrue, readyCondition.Status, "Ready should transition to True after secret is added")
	require.Equal(t, "KubeconfigValidated", readyCondition.Reason)
}

// helper: construct a client.ObjectKey for a ClusterConfig stored in the fake client
func clientKey(cc *telekomv1alpha1.ClusterConfig) client.ObjectKey {
	return client.ObjectKey{Namespace: cc.Namespace, Name: cc.Name}
}

// helper: get condition by type from a ClusterConfig
func getCondition(cc *telekomv1alpha1.ClusterConfig, condType string) *metav1.Condition {
	for i := range cc.Status.Conditions {
		if cc.Status.Conditions[i].Type == condType {
			return &cc.Status.Conditions[i]
		}
	}
	return nil
}

// TestClusterConfigChecker_NoKubeconfigSecretRef tests handling of ClusterConfig with no ref
func TestClusterConfigChecker_NoKubeconfigSecretRef(t *testing.T) {
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-no-ref", Namespace: "default"},
		Spec:       telekomv1alpha1.ClusterConfigSpec{
			// Empty kubeconfigSecretRef
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	checker.runOnce(context.Background(), checker.Log)
	// Should log warning but not update status (no error to report, just warning)
}

// TestClusterConfigChecker_LeaderElectionWait tests that checker waits for leadership signal
func TestClusterConfigChecker_LeaderElectionWait(t *testing.T) {
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-leader", Namespace: "default"},
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "sec", Namespace: "default"}},
	}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "sec", Namespace: "default"}, Data: map[string][]byte{"value": []byte("kubeconfig")}}
	cl := newTestFakeClient(cc, sec)
	fakeRecorder := fakeEventRecorder{}

	// Create a leadership signal channel
	leaderChan := make(chan struct{})
	checker := ClusterConfigChecker{
		Log:           zap.NewNop().Sugar(),
		Client:        cl,
		Recorder:      fakeRecorder,
		Interval:      time.Minute,
		LeaderElected: leaderChan,
	}

	// Stub successful validation
	old := RestConfigFromKubeConfig
	RestConfigFromKubeConfig = func(b []byte) (*rest.Config, error) { return &rest.Config{}, nil }
	defer func() { RestConfigFromKubeConfig = old }()
	oldCheck := CheckClusterReachable
	CheckClusterReachable = func(cfg *rest.Config) error { return nil }
	defer func() { CheckClusterReachable = oldCheck }()

	// Start checker in goroutine with short timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := make(chan struct{})
	go func() {
		close(started)
		checker.Start(ctx)
	}()
	<-started

	// Give a moment for the goroutine to start waiting
	time.Sleep(10 * time.Millisecond)

	// Signal leadership - checker should start
	close(leaderChan)

	// Wait for context to be cancelled
	<-ctx.Done()
}

// OIDC-specific tests

func TestClusterConfigChecker_OIDCAuthType_MissingOIDCConfig(t *testing.T) {
	// ClusterConfig with authType=OIDC but no oidcAuth configuration
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			// OIDCAuth not set
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))

	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "oidcAuth")
}

func TestClusterConfigChecker_OIDCAuthType_MissingClientSecret(t *testing.T) {
	// ClusterConfig with OIDC auth but missing client secret
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-cluster-2", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: "https://idp.example.com",
				ClientID:  "test-client",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "missing-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))

	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "secret")
}

func TestClusterConfigChecker_OIDCAuthType_MissingCASecret(t *testing.T) {
	// OIDC config with caSecretRef pointing to missing secret
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-client-secret", Namespace: "default"},
		Data:       map[string][]byte{"client-secret": []byte("test-secret")},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-cluster-3", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: "https://idp.example.com",
				ClientID:  "test-client",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "oidc-client-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
				CASecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "missing-ca-secret",
					Namespace: "default",
					Key:       "ca.crt",
				},
			},
		},
	}
	cl := newTestFakeClient(cc, clientSecret)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))

	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "CA secret")
}

// TestClusterConfigChecker_OIDCAuthType_TOFUAllowsEmptyCAKey verifies that when
// caSecretRef points to a secret that exists but doesn't have the CA key yet,
// the checker allows TOFU (Trust On First Use) to proceed and discover the CA.
func TestClusterConfigChecker_OIDCAuthType_TOFUAllowsEmptyCAKey(t *testing.T) {
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-client-secret", Namespace: "default"},
		Data:       map[string][]byte{"client-secret": []byte("test-secret")},
	}
	// CA secret exists but doesn't have ca.crt key - TOFU should populate it
	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca-secret-for-tofu", Namespace: "default"},
		Data:       map[string][]byte{}, // Empty - TOFU will populate this
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-cluster-tofu", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: "https://idp.example.com",
				ClientID:  "test-client",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "oidc-client-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
				CASecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "ca-secret-for-tofu",
					Namespace: "default",
					Key:       "ca.crt",
				},
			},
		},
	}
	cl := newTestFakeClient(cc, clientSecret, caSecret)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))

	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	// The validation should pass (no OIDCCASecretMissing error), but connection will fail
	// because we're using a fake OIDC issuer. The key point is it doesn't fail with "missing key"
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	// It should fail on OIDC discovery, not on CA secret validation
	require.Contains(t, readyCondition.Message, "OIDC")
	require.NotContains(t, readyCondition.Message, "missing key")
}

func TestClusterConfigChecker_OIDCAuthType_MissingRequiredFields(t *testing.T) {
	// OIDC config missing required fields (issuerURL, clientID, server)
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-client-secret", Namespace: "default"},
		Data:       map[string][]byte{"client-secret": []byte("test-secret")},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-cluster-4", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				// Missing IssuerURL
				ClientID: "test-client",
				Server:   "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "oidc-client-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
			},
		},
	}
	cl := newTestFakeClient(cc, clientSecret)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))

	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "Required value")
}

// TestDescribeFailure tests the DescribeFailure helper function (Merged Generic + OIDC)
func TestDescribeFailure(t *testing.T) {
	tests := []struct {
		name        string
		failureType string
		message     string
		expectedCat string
	}{
		// Generic Cases
		{"connection", "connection", "dial tcp timeout", "connection_failed"},
		{"parse", "parse", "invalid yaml", "kubeconfig_parse_error"},
		{"secret_missing", "secret_missing", "", "secret_not_found"},
		{"secret_key_missing", "secret_key_missing", "", "secret_key_missing"},
		{"not_configured", "not_configured", "", "not_configured"},
		{"unknown", "unknown", "something else", "validation_failed"},
		// OIDC Cases
		{"oidc_discovery", "oidc_discovery", "connection refused", "oidc_discovery_failed"},
		{"oidc_token", "oidc_token", "invalid client", "oidc_token_failed"},
		{"oidc_refresh", "oidc_refresh", "token revoked", "oidc_refresh_failed"},
		{"oidc_config", "oidc_config", "", "oidc_config_missing"},
		{"oidc_ca_missing", "oidc_ca_missing", "", "oidc_ca_secret_missing"},
		{"tofu", "tofu", "TLS handshake failed", "tofu_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			category, advice := DescribeFailure(tt.failureType, tt.message)
			require.Equal(t, tt.expectedCat, category)
			require.NotEmpty(t, advice)
		})
	}
}

// TestDetermineClusterConfigFailureType tests the determineClusterConfigFailureType function
func TestDetermineClusterConfigFailureType(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		expected string
	}{
		// OIDC cases
		{"oidc_discovery", "OIDC discovery failed: connection refused", "oidc_discovery"},
		{"oidc_token", "failed to get OIDC token: invalid client", "oidc_token"},
		{"oidc_refresh", "refresh token expired", "oidc_refresh"},
		{"oidc_config", "OIDC config missing", "oidc_config"},
		{"tofu_failed", "TOFU failed to fetch certificate", "tofu"},
		{"ca_secret_missing", "cluster CA secret missing", "oidc_ca_missing"},

		// Kubeconfig cases
		{"secret_missing", "secret missing or not found", "secret_missing"},
		{"secret_key_missing", "missing key 'value'", "secret_key_missing"},
		{"parse_failed", "kubeconfig parse failed", "parse"},
		{"connection", "cluster unreachable: dial timeout", "connection"},
		{"validation", "other validation error", "validation"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineClusterConfigFailureType(tt.message)
			require.Equal(t, tt.expected, result)
		})
	}
}

// TestNewStatusUpdateHelper tests the NewStatusUpdateHelper function
func TestNewStatusUpdateHelper(t *testing.T) {
	tests := []struct {
		name          string
		phase         string
		message       string
		eventType     string
		expectedPhase string
		expectedMsg   string
		expectedEvent string
	}{
		{
			name:          "ready status",
			phase:         "Ready",
			message:       "Cluster is ready",
			eventType:     "Normal",
			expectedPhase: "Ready",
			expectedMsg:   "Cluster is ready",
			expectedEvent: "Normal",
		},
		{
			name:          "failed status",
			phase:         "Failed",
			message:       "Cluster unreachable",
			eventType:     "Warning",
			expectedPhase: "Failed",
			expectedMsg:   "Cluster unreachable",
			expectedEvent: "Warning",
		},
		{
			name:          "empty values",
			phase:         "",
			message:       "",
			eventType:     "",
			expectedPhase: "",
			expectedMsg:   "",
			expectedEvent: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helper := NewStatusUpdateHelper(tt.phase, tt.message, tt.eventType)
			require.NotNil(t, helper)
			require.Equal(t, tt.expectedPhase, helper.phase)
			require.Equal(t, tt.expectedMsg, helper.message)
			require.Equal(t, tt.expectedEvent, helper.eventType)
		})
	}
}

// ====================================================================
// Tests for validateOIDCFromIdentityProvider function
// ====================================================================

// TestValidateOIDCFromIdentityProvider_MissingRequiredFields tests that
// validateOIDCFromIdentityProvider fails when name or server is missing
func TestValidateOIDCFromIdentityProvider_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		ref     *telekomv1alpha1.OIDCFromIdentityProviderConfig
		wantMsg string
	}{
		{
			name: "missing name",
			ref: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "",
				Server: "https://api.example.com:6443",
			},
			wantMsg: "Required value",
		},
		{
			name: "missing server",
			ref: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "my-idp",
				Server: "",
			},
			wantMsg: "Required value",
		},
		{
			name: "both missing",
			ref: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "",
				Server: "",
			},
			wantMsg: "Required value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := &telekomv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "oidc-from-idp-cluster", Namespace: "default"},
				Spec: telekomv1alpha1.ClusterConfigSpec{
					AuthType:                 telekomv1alpha1.ClusterAuthTypeOIDC,
					OIDCFromIdentityProvider: tt.ref,
				},
			}
			cl := newTestFakeClient(cc)
			fakeRecorder := fakeEventRecorder{}
			checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

			checker.runOnce(context.Background(), checker.Log)

			got := &telekomv1alpha1.ClusterConfig{}
			require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
			readyCondition := getCondition(got, "Ready")
			require.NotNil(t, readyCondition)
			require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
			require.Contains(t, readyCondition.Message, tt.wantMsg)
		})
	}
}

// TestValidateOIDCFromIdentityProvider_IdentityProviderNotFound tests that
// validateOIDCFromIdentityProvider fails when the referenced IdentityProvider doesn't exist
func TestValidateOIDCFromIdentityProvider_IdentityProviderNotFound(t *testing.T) {
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-from-idp-notfound", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "nonexistent-idp",
				Server: "https://api.example.com:6443",
			},
		},
	}
	cl := newTestFakeClient(cc) // No IdentityProvider created
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "not found")
}

// TestValidateOIDCFromIdentityProvider_IdentityProviderDisabled tests that
// validateOIDCFromIdentityProvider fails when the referenced IdentityProvider is disabled
func TestValidateOIDCFromIdentityProvider_IdentityProviderDisabled(t *testing.T) {
	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			Disabled: true, // IDP is disabled
			Keycloak: &telekomv1alpha1.KeycloakGroupSync{
				BaseURL: "https://keycloak.example.com", ClientID: "client",
				Realm: "test-realm",
				ClientSecretRef: telekomv1alpha1.SecretKeyReference{
					Name:      "keycloak-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
			},
		},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-from-disabled-idp", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "disabled-idp",
				Server: "https://api.example.com:6443",
			},
		},
	}
	cl := newTestFakeClient(cc, idp)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "disabled")
}

// TestValidateOIDCFromIdentityProvider_NoClientSecretRef tests that
// validateOIDCFromIdentityProvider fails when neither the OIDCFromIdentityProvider
// nor the IdentityProvider has a client secret configured
func TestValidateOIDCFromIdentityProvider_NoClientSecretRef(t *testing.T) {
	// IDP without Keycloak config (so no implicit client secret)
	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-no-keycloak"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			Disabled: false,
			// No Keycloak config
		},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-no-secret", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "idp-no-keycloak",
				Server: "https://api.example.com:6443",
				// No ClientSecretRef
			},
		},
	}
	cl := newTestFakeClient(cc, idp)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "clientSecretRef")
}

// TestValidateOIDCFromIdentityProvider_ClientSecretMissing tests that
// validateOIDCFromIdentityProvider fails when the client secret reference exists but secret is missing
func TestValidateOIDCFromIdentityProvider_ClientSecretMissing(t *testing.T) {
	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-with-keycloak"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			Disabled: false,
			Keycloak: &telekomv1alpha1.KeycloakGroupSync{
				BaseURL: "https://keycloak.example.com", ClientID: "client",
				Realm: "test-realm",
				ClientSecretRef: telekomv1alpha1.SecretKeyReference{
					Name:      "missing-keycloak-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
			},
		},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-secret-missing", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "idp-with-keycloak",
				Server: "https://api.example.com:6443",
			},
		},
	}
	cl := newTestFakeClient(cc, idp) // Secret not created
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "secret")
}

// TestValidateOIDCFromIdentityProvider_ClientSecretKeyMissing tests that
// validateOIDCFromIdentityProvider fails when the secret exists but doesn't have the required key
func TestValidateOIDCFromIdentityProvider_ClientSecretKeyMissing(t *testing.T) {
	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-key-missing"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			Disabled: false,
			Keycloak: &telekomv1alpha1.KeycloakGroupSync{
				BaseURL: "https://keycloak.example.com", ClientID: "client",
				Realm: "test-realm",
				ClientSecretRef: telekomv1alpha1.SecretKeyReference{
					Name:      "keycloak-secret-wrong-key",
					Namespace: "default",
					Key:       "client-secret",
				},
			},
		},
	}
	// Secret with wrong key
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "keycloak-secret-wrong-key", Namespace: "default"},
		Data:       map[string][]byte{"wrong-key": []byte("secret-value")},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-key-missing", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "idp-key-missing",
				Server: "https://api.example.com:6443",
			},
		},
	}
	cl := newTestFakeClient(cc, idp, secret)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "missing key")
}

// TestValidateOIDCFromIdentityProvider_CASecretMissing tests that
// validateOIDCFromIdentityProvider fails when caSecretRef points to a missing secret
func TestValidateOIDCFromIdentityProvider_CASecretMissing(t *testing.T) {
	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-ca-test"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			Disabled: false,
			Keycloak: &telekomv1alpha1.KeycloakGroupSync{
				BaseURL: "https://keycloak.example.com", ClientID: "client",
				Realm: "test-realm",
				ClientSecretRef: telekomv1alpha1.SecretKeyReference{
					Name:      "keycloak-client-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
			},
		},
	}
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "keycloak-client-secret", Namespace: "default"},
		Data:       map[string][]byte{"client-secret": []byte("secret-value")},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-ca-missing", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "idp-ca-test",
				Server: "https://api.example.com:6443",
				CASecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "missing-ca-secret",
					Namespace: "default",
					Key:       "ca.crt",
				},
			},
		},
	}
	cl := newTestFakeClient(cc, idp, clientSecret) // No CA secret
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "CA secret")
}

// TestValidateOIDCFromIdentityProvider_UsesExplicitClientSecret tests that
// when OIDCFromIdentityProvider has its own ClientSecretRef, it uses that instead of IDP's
func TestValidateOIDCFromIdentityProvider_UsesExplicitClientSecret(t *testing.T) {
	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-explicit-secret"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			Disabled: false,
			Keycloak: &telekomv1alpha1.KeycloakGroupSync{
				BaseURL: "https://keycloak.example.com", ClientID: "client",
				Realm: "test-realm",
				ClientSecretRef: telekomv1alpha1.SecretKeyReference{
					Name:      "idp-keycloak-secret", // This should NOT be used
					Namespace: "default",
					Key:       "client-secret",
				},
			},
		},
	}
	// Create the explicit secret (referenced by OIDCFromIdentityProvider)
	explicitSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "explicit-client-secret", Namespace: "default"},
		Data:       map[string][]byte{"my-key": []byte("explicit-secret-value")},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-explicit-secret", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "idp-explicit-secret",
				Server: "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "explicit-client-secret",
					Namespace: "default",
					Key:       "my-key",
				},
			},
		},
	}
	cl := newTestFakeClient(cc, idp, explicitSecret) // Only explicit secret, not IDP's secret
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	// Should pass secret validation but fail on OIDC discovery (which is expected)
	// The key test is that it doesn't fail looking for "idp-keycloak-secret"
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.NotContains(t, readyCondition.Message, "idp-keycloak-secret")
}

// TestValidateOIDCFromIdentityProvider_DefaultClientSecretKey tests that
// when no key is specified, "client-secret" is used as the default
func TestValidateOIDCFromIdentityProvider_DefaultClientSecretKey(t *testing.T) {
	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-default-key"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			Disabled: false,
			Keycloak: &telekomv1alpha1.KeycloakGroupSync{
				BaseURL: "https://keycloak.example.com", ClientID: "client",
				Realm: "test-realm",
				ClientSecretRef: telekomv1alpha1.SecretKeyReference{
					Name:      "keycloak-secret-default",
					Namespace: "default",
					// Key is empty - should default to "client-secret"
				},
			},
		},
	}
	// Secret with default key
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "keycloak-secret-default", Namespace: "default"},
		Data:       map[string][]byte{"client-secret": []byte("secret-value")},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-default-key", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "idp-default-key",
				Server: "https://api.example.com:6443",
			},
		},
	}
	cl := newTestFakeClient(cc, idp, secret)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	// Should pass secret key check (using default "client-secret") but fail on OIDC discovery
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.NotContains(t, readyCondition.Message, "missing key")
}

type fakeEventRecorder struct {
	Events chan string
}

func (f fakeEventRecorder) Eventf(_ runtime.Object, _ runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
	if f.Events == nil {
		return
	}
	message := note
	if len(args) > 0 {
		message = fmt.Sprintf(note, args...)
	}
	f.Events <- fmt.Sprintf("%s %s %s %s", eventtype, reason, action, message)
}
