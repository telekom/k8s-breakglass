package breakglass

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
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
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "missing", Namespace: "default"}},
	}
	cl := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc).Build()
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	// run once
	checker.runOnce(context.Background(), checker.Log)
	// read updated CC from client
	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	// Check Ready condition is False
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
}

func TestClusterConfigChecker_MissingKey(t *testing.T) {
	// secret exists but missing key 'value'
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "default"}, Data: map[string][]byte{"other": []byte("x")}}
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-b", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "s1", Namespace: "default"}}}
	cl := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc, sec).Build()
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	checker.runOnce(context.Background(), checker.Log)
	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))
	// Check Ready condition is False
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
}

func TestClusterConfigChecker_ParseFail(t *testing.T) {
	// secret contains key but invalid kubeconfig
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s2", Namespace: "default"}, Data: map[string][]byte{"value": []byte("not-a-kubeconfig")}}
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-c", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "s2", Namespace: "default"}}}
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
	// Check Ready condition is False
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
}

func TestClusterConfigChecker_Unreachable(t *testing.T) {
	// secret contains key and parse OK, but cluster unreachable
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s3", Namespace: "default"}, Data: map[string][]byte{"value": []byte("fake-kubeconfig")}}
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-d", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "s3", Namespace: "default"}}}
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
	// Check Ready condition is False
	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
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
	cl := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc).Build()
	fakeRecorder := record.NewFakeRecorder(10)
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
	cl := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc).Build()
	fakeRecorder := record.NewFakeRecorder(10)
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
	cl := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc, clientSecret).Build()
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))

	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "CA secret")
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
	cl := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc, clientSecret).Build()
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	checker.runOnce(context.Background(), checker.Log)

	got := &telekomv1alpha1.ClusterConfig{}
	require.NoError(t, cl.Get(context.Background(), clientKey(cc), got))

	readyCondition := getCondition(got, "Ready")
	require.NotNil(t, readyCondition)
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Contains(t, readyCondition.Message, "required fields")
}

// Test the determineClusterConfigFailureType function

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

func TestDescribeFailure_OIDCCases(t *testing.T) {
	tests := []struct {
		failureType    string
		message        string
		expectedCat    string
		expectedAdvice string
	}{
		{"oidc_discovery", "connection refused", "oidc_discovery_failed", "OIDC discovery failed"},
		{"oidc_token", "invalid client", "oidc_token_failed", "Failed to obtain OIDC token"},
		{"oidc_refresh", "token revoked", "oidc_refresh_failed", "Failed to refresh OIDC token"},
		{"oidc_config", "", "oidc_config_missing", "OIDC configuration is incomplete"},
		{"oidc_ca_missing", "", "oidc_ca_secret_missing", "CA secret doesn't exist"},
		{"tofu", "TLS handshake failed", "tofu_failed", "TOFU"},
	}

	for _, tt := range tests {
		t.Run(tt.failureType, func(t *testing.T) {
			cat, advice := DescribeFailure(tt.failureType, tt.message)
			require.Equal(t, tt.expectedCat, cat)
			require.Contains(t, advice, tt.expectedAdvice)
		})
	}
}
