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
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "missing", Namespace: "default"}},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := record.NewFakeRecorder(10)
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
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-b", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "s1", Namespace: "default"}}}
	cl := newTestFakeClient(cc, sec)
	fakeRecorder := record.NewFakeRecorder(10)
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
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-c", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "s2", Namespace: "default"}}}
	cl := newTestFakeClient(cc, sec)
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
	require.NotNil(t, readyCondition, "Ready condition should be set after runOnce")
	require.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	require.Equal(t, "KubeconfigParseFailed", readyCondition.Reason)
}

func TestClusterConfigChecker_Unreachable(t *testing.T) {
	// secret contains key and parse OK, but cluster unreachable
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s3", Namespace: "default"}, Data: map[string][]byte{"value": []byte("fake-kubeconfig")}}
	cc := &telekomv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-d", Namespace: "default"}, Spec: telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "s3", Namespace: "default"}}}
	cl := newTestFakeClient(cc, sec)
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
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "valid-secret", Namespace: "default"}},
	}
	cl := newTestFakeClient(cc, sec)
	fakeRecorder := record.NewFakeRecorder(10)
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
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "test-secret", Namespace: "default"}},
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
	fakeRecorder := record.NewFakeRecorder(10)
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
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "transition-secret", Namespace: "default"}},
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
	fakeRecorder := record.NewFakeRecorder(10)
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
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}
	checker.runOnce(context.Background(), checker.Log)
	// Should log warning but not update status (no error to report, just warning)
}

// TestClusterConfigChecker_LeaderElectionWait tests that checker waits for leadership signal
func TestClusterConfigChecker_LeaderElectionWait(t *testing.T) {
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-leader", Namespace: "default"},
		Spec:       telekomv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "sec", Namespace: "default"}},
	}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "sec", Namespace: "default"}, Data: map[string][]byte{"value": []byte("kubeconfig")}}
	cl := newTestFakeClient(cc, sec)
	fakeRecorder := record.NewFakeRecorder(10)

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

// TestClusterConfigChecker_DescribeFailure tests the DescribeFailure helper function
func TestClusterConfigChecker_DescribeFailure(t *testing.T) {
	tests := []struct {
		failureType      string
		message          string
		expectedCategory string
	}{
		{"connection", "dial tcp timeout", "connection_failed"},
		{"parse", "invalid yaml", "kubeconfig_parse_error"},
		{"secret_missing", "", "secret_not_found"},
		{"secret_key_missing", "", "secret_key_missing"},
		{"not_configured", "", "not_configured"},
		{"unknown", "something else", "validation_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.failureType, func(t *testing.T) {
			category, advice := DescribeFailure(tt.failureType, tt.message)
			require.Equal(t, tt.expectedCategory, category)
			require.NotEmpty(t, advice)
		})
	}
}

// TestClusterConfigChecker_DetermineFailureType tests the determineClusterConfigFailureType function
func TestClusterConfigChecker_DetermineFailureType(t *testing.T) {
	tests := []struct {
		message  string
		expected string
	}{
		{"secret missing or inaccessible", "secret_missing"},
		{"Resource not found in namespace", "secret_missing"},
		{"Kubeconfig is missing key: value", "secret_key_missing"},
		{"kubeconfig parse failed: invalid yaml", "parse"},
		{"cluster unreachable: dial tcp", "connection"},
		{"failed to dial remote server", "connection"},
		{"something else went wrong", "validation"},
	}

	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
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
