package webhook

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestFindNewEphemeralContainers(t *testing.T) {
	tests := []struct {
		name     string
		old      []corev1.EphemeralContainer
		new      []corev1.EphemeralContainer
		expected []corev1.EphemeralContainer
	}{
		{
			name:     "no containers",
			old:      nil,
			new:      nil,
			expected: []corev1.EphemeralContainer{},
		},
		{
			name: "empty old, one new",
			old:  nil,
			new: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
			},
			expected: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
			},
		},
		{
			name: "same containers, no new",
			old: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
			},
			new: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
			},
			expected: []corev1.EphemeralContainer{},
		},
		{
			name: "one new container added",
			old: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
			},
			new: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-2", Image: "alpine"}},
			},
			expected: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-2", Image: "alpine"}},
			},
		},
		{
			name: "multiple new containers",
			old:  []corev1.EphemeralContainer{},
			new: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-2", Image: "alpine"}},
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-3", Image: "ubuntu"}},
			},
			expected: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-2", Image: "alpine"}},
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-3", Image: "ubuntu"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findNewEphemeralContainers(tt.old, tt.new)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCapsToStrings(t *testing.T) {
	tests := []struct {
		name     string
		sc       *corev1.SecurityContext
		expected []string
	}{
		{
			name:     "nil security context",
			sc:       nil,
			expected: nil,
		},
		{
			name:     "nil capabilities",
			sc:       &corev1.SecurityContext{},
			expected: nil,
		},
		{
			name: "empty capabilities",
			sc: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{},
			},
			expected: []string{},
		},
		{
			name: "single capability",
			sc: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"NET_ADMIN"},
				},
			},
			expected: []string{"NET_ADMIN"},
		},
		{
			name: "multiple capabilities",
			sc: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"NET_ADMIN", "SYS_PTRACE", "SYS_ADMIN"},
				},
			},
			expected: []string{"NET_ADMIN", "SYS_PTRACE", "SYS_ADMIN"},
		},
		{
			name: "drop capabilities are ignored",
			sc: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add:  []corev1.Capability{"NET_ADMIN"},
					Drop: []corev1.Capability{"ALL"},
				},
			},
			expected: []string{"NET_ADMIN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := capsToStrings(tt.sc)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsRunAsNonRoot(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name     string
		sc       *corev1.SecurityContext
		expected bool
	}{
		{
			name:     "nil security context",
			sc:       nil,
			expected: false,
		},
		{
			name:     "nil RunAsNonRoot",
			sc:       &corev1.SecurityContext{},
			expected: false,
		},
		{
			name: "RunAsNonRoot true",
			sc: &corev1.SecurityContext{
				RunAsNonRoot: &trueVal,
			},
			expected: true,
		},
		{
			name: "RunAsNonRoot false",
			sc: &corev1.SecurityContext{
				RunAsNonRoot: &falseVal,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRunAsNonRoot(tt.sc)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// mockDebugHandler implements DebugSessionHandler for testing
type mockDebugHandler struct {
	session     *breakglassv1alpha1.DebugSession
	findErr     error
	validateErr error
}

func (m *mockDebugHandler) FindActiveSession(ctx context.Context, user, cluster string) (*breakglassv1alpha1.DebugSession, error) {
	return m.session, m.findErr
}

func (m *mockDebugHandler) ValidateEphemeralContainerRequest(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	namespace, podName, image string,
	capabilities []string,
	runAsNonRoot bool,
) error {
	return m.validateErr
}

// mockDecoder implements admission.Decoder for testing
type mockDecoder struct {
	pod       *corev1.Pod
	oldPod    *corev1.Pod
	decodeErr error
	oldErr    error
}

func (m *mockDecoder) Decode(req admission.Request, into runtime.Object) error {
	if m.decodeErr != nil {
		return m.decodeErr
	}
	if pod, ok := into.(*corev1.Pod); ok && m.pod != nil {
		*pod = *m.pod
	}
	return nil
}

func (m *mockDecoder) DecodeRaw(rawObj runtime.RawExtension, into runtime.Object) error {
	if m.oldErr != nil {
		return m.oldErr
	}
	if pod, ok := into.(*corev1.Pod); ok && m.oldPod != nil {
		*pod = *m.oldPod
	}
	return nil
}

func TestEphemeralContainerWebhook_Handle(t *testing.T) {
	logger := zap.NewNop().Sugar()

	validSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
		},
	}

	tests := []struct {
		name           string
		subResource    string
		username       string
		pod            *corev1.Pod
		oldPod         *corev1.Pod
		decodeErr      error
		oldDecodeErr   error
		session        *breakglassv1alpha1.DebugSession
		findErr        error
		validateErr    error
		expectAllowed  bool
		expectDenied   bool
		expectError    bool
		expectedReason string
	}{
		{
			name:          "non-ephemeral subresource allowed",
			subResource:   "status",
			expectAllowed: true,
		},
		{
			name:          "empty subresource allowed",
			subResource:   "",
			expectAllowed: true,
		},
		{
			name:        "decode error returns bad request",
			subResource: "ephemeralcontainers",
			decodeErr:   errors.New("decode failed"),
			expectError: true,
		},
		{
			name:        "find session error returns internal error",
			subResource: "ephemeralcontainers",
			username:    "testuser",
			pod:         &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"}},
			oldPod:      &corev1.Pod{},
			findErr:     errors.New("failed to list sessions"),
			expectError: true,
		},
		{
			name:           "no active session returns denied",
			subResource:    "ephemeralcontainers",
			username:       "testuser",
			pod:            &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"}},
			oldPod:         &corev1.Pod{},
			session:        nil,
			expectDenied:   true,
			expectedReason: "no active debug session found for user testuser",
		},
		{
			name:         "decode old object error returns bad request",
			subResource:  "ephemeralcontainers",
			username:     "testuser",
			pod:          &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"}},
			session:      validSession,
			oldDecodeErr: errors.New("old decode failed"),
			expectError:  true,
		},
		{
			name:        "no new containers allowed",
			subResource: "ephemeralcontainers",
			username:    "testuser",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
				Spec: corev1.PodSpec{
					EphemeralContainers: []corev1.EphemeralContainer{
						{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "existing", Image: "busybox"}},
					},
				},
			},
			oldPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					EphemeralContainers: []corev1.EphemeralContainer{
						{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "existing", Image: "busybox"}},
					},
				},
			},
			session:       validSession,
			expectAllowed: true,
		},
		{
			name:        "new container validated and allowed",
			subResource: "ephemeralcontainers",
			username:    "testuser",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
				Spec: corev1.PodSpec{
					EphemeralContainers: []corev1.EphemeralContainer{
						{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
					},
				},
			},
			oldPod:        &corev1.Pod{},
			session:       validSession,
			expectAllowed: true,
		},
		{
			name:        "validation error returns denied",
			subResource: "ephemeralcontainers",
			username:    "testuser",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "restricted"},
				Spec: corev1.PodSpec{
					EphemeralContainers: []corev1.EphemeralContainer{
						{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "malicious"}},
					},
				},
			},
			oldPod:         &corev1.Pod{},
			session:        validSession,
			validateErr:    errors.New("image not allowed"),
			expectDenied:   true,
			expectedReason: "ephemeral container denied: image not allowed",
		},
		{
			name:        "container with security context validated",
			subResource: "ephemeralcontainers",
			username:    "testuser",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
				Spec: corev1.PodSpec{
					EphemeralContainers: []corev1.EphemeralContainer{
						{
							EphemeralContainerCommon: corev1.EphemeralContainerCommon{
								Name:  "debug-1",
								Image: "busybox",
								SecurityContext: &corev1.SecurityContext{
									Capabilities: &corev1.Capabilities{
										Add: []corev1.Capability{"NET_ADMIN", "SYS_PTRACE"},
									},
								},
							},
						},
					},
				},
			},
			oldPod:        &corev1.Pod{},
			session:       validSession,
			expectAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			webhook := &EphemeralContainerWebhook{
				Decoder: &mockDecoder{
					pod:       tt.pod,
					oldPod:    tt.oldPod,
					decodeErr: tt.decodeErr,
					oldErr:    tt.oldDecodeErr,
				},
				DebugHandler: &mockDebugHandler{
					session:     tt.session,
					findErr:     tt.findErr,
					validateErr: tt.validateErr,
				},
				Log: logger,
			}

			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					SubResource: tt.subResource,
					UserInfo:    authenticationv1.UserInfo{Username: tt.username},
				},
			}

			resp := webhook.Handle(context.Background(), req)

			if tt.expectAllowed {
				require.True(t, resp.Allowed, "expected allowed=true, got result: %+v", resp.Result)
			}
			if tt.expectDenied {
				require.False(t, resp.Allowed, "expected denied")
				if tt.expectedReason != "" {
					// Check both Result.Reason and Result.Message
					reason := ""
					if resp.Result != nil {
						reason = string(resp.Result.Reason) + " " + resp.Result.Message
					}
					assert.Contains(t, reason, tt.expectedReason)
				}
			}
			if tt.expectError {
				require.False(t, resp.Allowed, "expected error")
				require.NotNil(t, resp.Result)
				require.True(t, resp.Result.Code >= 400, "expected error code")
			}
		})
	}
}

func TestNewEphemeralContainerWebhook(t *testing.T) {
	logger := zap.NewNop().Sugar()

	webhook := NewEphemeralContainerWebhook(nil, nil, logger, nil)

	require.NotNil(t, webhook)
	assert.Nil(t, webhook.Client)
	assert.Nil(t, webhook.Decoder)
	assert.Equal(t, logger, webhook.Log)
	assert.Nil(t, webhook.DebugHandler)
}
