// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func newServiceTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	return scheme
}

func TestNewService(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")
	assert.NotNil(t, svc)
	assert.False(t, svc.IsEnabled())
	assert.True(t, svc.IsConfigured(), "startup must fail closed until absence of enabled AuditConfigs is proven")
	assert.Equal(t, ConfigurationUnavailable, svc.ConfigurationState())
}

func TestService_ReloadStateTransitions(t *testing.T) {
	svc := NewService(fake.NewClientBuilder().WithScheme(newServiceTestScheme(t)).Build(), nil, zap.NewNop(), "test-namespace")
	valid := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "valid"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks:   []breakglassv1alpha1.AuditSinkConfig{{Name: "log", Type: breakglassv1alpha1.AuditSinkTypeLog}},
		},
	}

	require.NoError(t, svc.Reload(context.Background(), valid))
	assert.True(t, svc.IsEnabled())
	assert.True(t, svc.IsConfigured())
	assert.Equal(t, ConfigurationReady, svc.ConfigurationState())

	err := svc.ReloadMultipleWithAvailability(context.Background(), nil, true)
	require.Error(t, err)
	assert.False(t, svc.IsEnabled())
	assert.True(t, svc.IsConfigured())
	assert.Equal(t, ConfigurationUnavailable, svc.ConfigurationState())
	assert.ErrorContains(t, svc.EmitSync(context.Background(), &Event{Type: EventSessionTerminationIntent}), "disabled")

	require.NoError(t, svc.Reload(context.Background(), valid))
	assert.Equal(t, ConfigurationReady, svc.ConfigurationState())
	require.NoError(t, svc.Reload(context.Background(), nil))
	assert.False(t, svc.IsConfigured())
	assert.Equal(t, ConfigurationDisabled, svc.ConfigurationState())
}

func TestService_ReloadDisablesOnNilConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	err := svc.Reload(context.Background(), nil)
	assert.NoError(t, err)
	assert.False(t, svc.IsEnabled())
}

func TestService_ReloadDisablesOnDisabledConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: false,
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.False(t, svc.IsEnabled())
}

func TestService_ReloadWithLogSink(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "test-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
					Log: &breakglassv1alpha1.LogSinkSpec{
						Level:  "info",
						Format: "json",
					},
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Cleanup
	err = svc.Close()
	assert.NoError(t, err)
	assert.False(t, svc.IsEnabled())
}

func TestService_ReloadWithQueueConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Queue: &breakglassv1alpha1.AuditQueueConfig{
				Size:       5000,
				Workers:    3,
				DropOnFull: true,
			},
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "test-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Cleanup
	_ = svc.Close()
}

func TestService_ReloadWithSampling(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sampling: &breakglassv1alpha1.AuditSamplingConfig{
				Rate:                    "0.0",
				HighVolumeEventTypes:    []string{string(EventResourceGet), string(EventResourceList)},
				AlwaysCaptureEventTypes: []string{string(EventSessionRequested)},
			},
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "test-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())
	require.NotNil(t, svc.manager)
	assert.Equal(t, 0.0, svc.manager.config.SampleRate)
	assert.ElementsMatch(t,
		[]EventType{EventResourceGet, EventResourceList},
		svc.manager.config.HighVolumeEventTypes,
	)
	assert.ElementsMatch(t,
		[]EventType{EventSessionRequested},
		svc.manager.config.AlwaysCaptureEventTypes,
	)

	// Cleanup
	_ = svc.Close()
}

func TestService_ReloadMultipleUsesSharedEventTypeFilters(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")
	configs := []*breakglassv1alpha1.AuditConfig{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "config-a"},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled:   true,
				Filtering: &breakglassv1alpha1.AuditFilterConfig{IncludeEventTypes: []string{"session.*"}, ExcludeEventTypes: []string{"session.denied"}},
				Sinks:     []breakglassv1alpha1.AuditSinkConfig{{Name: "log-a", Type: breakglassv1alpha1.AuditSinkTypeLog}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "config-b"},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled:   true,
				Filtering: &breakglassv1alpha1.AuditFilterConfig{IncludeEventTypes: []string{"session.*"}, ExcludeEventTypes: []string{"session.denied"}},
				Sinks:     []breakglassv1alpha1.AuditSinkConfig{{Name: "log-b", Type: breakglassv1alpha1.AuditSinkTypeLog}},
			},
		},
	}

	err := svc.ReloadMultiple(context.Background(), configs)
	require.NoError(t, err)
	require.NotNil(t, svc.manager)
	assert.Equal(t, []string{"session.*"}, svc.manager.config.IncludeEventTypes)
	assert.Equal(t, []string{"session.denied"}, svc.manager.config.ExcludeEventTypes)
	_ = svc.Close()
}

func TestService_ReloadMultipleDisablesManagerEventFilterForDifferentConfigs(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")
	configs := []*breakglassv1alpha1.AuditConfig{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "config-a"},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled:   true,
				Filtering: &breakglassv1alpha1.AuditFilterConfig{IncludeEventTypes: []string{"session.*"}},
				Sinks:     []breakglassv1alpha1.AuditSinkConfig{{Name: "log-a", Type: breakglassv1alpha1.AuditSinkTypeLog}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "config-b"},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled:   true,
				Filtering: &breakglassv1alpha1.AuditFilterConfig{IncludeEventTypes: []string{"access.*"}},
				Sinks:     []breakglassv1alpha1.AuditSinkConfig{{Name: "log-b", Type: breakglassv1alpha1.AuditSinkTypeLog}},
			},
		},
	}

	err := svc.ReloadMultiple(context.Background(), configs)
	require.NoError(t, err)
	require.NotNil(t, svc.manager)
	assert.Empty(t, svc.manager.config.IncludeEventTypes)
	assert.Empty(t, svc.manager.config.ExcludeEventTypes)
	_ = svc.Close()
}

func TestService_EnabledConfigWithoutSinksIsUnavailable(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks:   []breakglassv1alpha1.AuditSinkConfig{}, // no sinks
		},
	}

	err := svc.Reload(context.Background(), config)
	require.Error(t, err)
	assert.False(t, svc.IsEnabled())
	assert.True(t, svc.IsConfigured())
	assert.Equal(t, ConfigurationUnavailable, svc.ConfigurationState())
}

func TestService_EmitWhenDisabled(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	// Service is disabled by default
	event := &Event{
		ID:        "test-1",
		Type:      EventSessionRequested,
		Timestamp: time.Now(),
		Actor:     Actor{User: "test@example.com"},
	}

	// Should not panic
	svc.Emit(context.Background(), event)

	// Required synchronous delivery must fail closed while auditing is disabled.
	err := svc.EmitSync(context.Background(), event)
	assert.Error(t, err)
}

func TestService_EmitWhenEnabled(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "test-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	require.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	event := &Event{
		ID:        "test-1",
		Type:      EventSessionRequested,
		Timestamp: time.Now(),
		Actor:     Actor{User: "test@example.com"},
	}

	// Should not panic
	svc.Emit(context.Background(), event)

	// A log write has no durable receipt and cannot satisfy required delivery.
	err = svc.EmitSync(context.Background(), event)
	assert.Error(t, err)

	// Cleanup
	_ = svc.Close()
}

func TestService_CloseWhenNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	// Close without Reload
	err := svc.Close()
	assert.NoError(t, err)
}

func TestService_ReloadMultipleTimes(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config1 := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config1"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{Name: "log1", Type: breakglassv1alpha1.AuditSinkTypeLog},
			},
		},
	}

	// First reload
	err := svc.Reload(context.Background(), config1)
	require.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	config2 := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config2"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{Name: "log2", Type: breakglassv1alpha1.AuditSinkTypeLog},
				{Name: "log3", Type: breakglassv1alpha1.AuditSinkTypeLog},
			},
		},
	}

	// Second reload should close old sinks and create new ones
	err = svc.Reload(context.Background(), config2)
	require.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Disable via nil
	err = svc.Reload(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, svc.IsEnabled())

	// Cleanup
	_ = svc.Close()
}

func TestService_BuildWebhookSink(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: breakglassv1alpha1.AuditSinkTypeWebhook,
					Webhook: &breakglassv1alpha1.WebhookSinkSpec{
						URL:            "https://example.com/audit",
						TimeoutSeconds: 10,
						Headers: map[string]string{
							"X-Custom-Header": "value",
						},
					},
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Cleanup
	_ = svc.Close()
}

func TestService_BuildWebhookSinkAuthSecretBearer(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	authSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-auth",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"token": []byte("secret-token"),
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(authSecret).Build()
	svc := NewService(client, nil, logger, "test-namespace")

	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := svc.buildWebhookSink(context.Background(), breakglassv1alpha1.AuditSinkConfig{
		Name: "webhook-sink",
		Type: breakglassv1alpha1.AuditSinkTypeWebhook,
		Webhook: &breakglassv1alpha1.WebhookSinkSpec{
			URL: server.URL,
			AuthSecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name:      "webhook-auth",
				Namespace: "test-namespace",
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, sink.Write(context.Background(), &Event{ID: "bearer", Type: EventSessionRequested}))
	assert.Equal(t, "Bearer secret-token", authHeader)
}

func TestService_BuildWebhookSinkAuthSecretBasic(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	authSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-auth",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"username": []byte("audit-user"),
			"password": []byte("audit-pass"),
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(authSecret).Build()
	svc := NewService(client, nil, logger, "test-namespace")

	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := svc.buildWebhookSink(context.Background(), breakglassv1alpha1.AuditSinkConfig{
		Name: "webhook-sink",
		Type: breakglassv1alpha1.AuditSinkTypeWebhook,
		Webhook: &breakglassv1alpha1.WebhookSinkSpec{
			URL: server.URL,
			AuthSecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name:      "webhook-auth",
				Namespace: "test-namespace",
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, sink.Write(context.Background(), &Event{ID: "basic", Type: EventSessionRequested}))
	assert.Equal(t, "Basic YXVkaXQtdXNlcjphdWRpdC1wYXNz", authHeader)
}

func TestService_BuildWebhookSinkAuthorizationHeaderPrecedence(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	authSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-auth",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"token": []byte("secret-token"),
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(authSecret).Build()
	svc := NewService(client, nil, logger, "test-namespace")

	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := svc.buildWebhookSink(context.Background(), breakglassv1alpha1.AuditSinkConfig{
		Name: "webhook-sink",
		Type: breakglassv1alpha1.AuditSinkTypeWebhook,
		Webhook: &breakglassv1alpha1.WebhookSinkSpec{
			URL: server.URL,
			Headers: map[string]string{
				"Authorization": "Bearer explicit-token",
			},
			AuthSecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name:      "webhook-auth",
				Namespace: "test-namespace",
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, sink.Write(context.Background(), &Event{ID: "precedence", Type: EventSessionRequested}))
	assert.Equal(t, "Bearer explicit-token", authHeader)
}

func TestService_BuildWebhookSinkTLSWithCASecret(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	var received bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-ca",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(caSecret).Build()
	svc := NewService(client, nil, logger, "test-namespace")

	sink, err := svc.buildWebhookSink(context.Background(), breakglassv1alpha1.AuditSinkConfig{
		Name: "webhook-sink",
		Type: breakglassv1alpha1.AuditSinkTypeWebhook,
		Webhook: &breakglassv1alpha1.WebhookSinkSpec{
			URL: server.URL,
			TLS: &breakglassv1alpha1.WebhookTLSSpec{
				CASecretRef: &breakglassv1alpha1.SecretKeySelector{
					Name:      "webhook-ca",
					Namespace: "test-namespace",
				},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, sink.Write(context.Background(), &Event{ID: "tls", Type: EventSessionRequested}))
	assert.True(t, received)
}

func TestService_BuildWebhookTLSConfigUsesCustomCAWhenSystemPoolFails(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-ca",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(caSecret).Build()
	svc := NewService(client, nil, logger, "test-namespace")

	oldSystemCertPool := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) {
		return nil, errors.New("system roots unavailable")
	}
	defer func() {
		systemCertPool = oldSystemCertPool
	}()

	cfg, err := svc.buildWebhookTLSConfig(context.Background(), &breakglassv1alpha1.WebhookTLSSpec{
		CASecretRef: &breakglassv1alpha1.SecretKeySelector{
			Name:      "webhook-ca",
			Namespace: "test-namespace",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, cfg.RootCAs)

	httpClient := server.Client()
	httpClient.Transport = &http.Transport{TLSClientConfig: cfg}
	resp, err := httpClient.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestService_BuildWebhookSinkMissingSecretErrors(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	svc := NewService(client, nil, logger, "test-namespace")

	_, err := svc.buildWebhookSink(context.Background(), breakglassv1alpha1.AuditSinkConfig{
		Name: "webhook-sink",
		Type: breakglassv1alpha1.AuditSinkTypeWebhook,
		Webhook: &breakglassv1alpha1.WebhookSinkSpec{
			URL: "https://example.com/audit",
			AuthSecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name:      "missing-auth",
				Namespace: "test-namespace",
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get webhook auth secret")

	_, err = svc.buildWebhookSink(context.Background(), breakglassv1alpha1.AuditSinkConfig{
		Name: "webhook-sink",
		Type: breakglassv1alpha1.AuditSinkTypeWebhook,
		Webhook: &breakglassv1alpha1.WebhookSinkSpec{
			URL: "https://example.com/audit",
			TLS: &breakglassv1alpha1.WebhookTLSSpec{
				CASecretRef: &breakglassv1alpha1.SecretKeySelector{
					Name:      "missing-ca",
					Namespace: "test-namespace",
				},
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load webhook CA certificate")
}

func TestService_BuildWebhookSinkRejectsNonControllerSecretNamespaces(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	svc := NewService(client, nil, logger, "test-namespace")

	t.Run("auth secret namespace", func(t *testing.T) {
		_, err := svc.buildWebhookSink(context.Background(), breakglassv1alpha1.AuditSinkConfig{
			Name: "webhook-sink",
			Type: breakglassv1alpha1.AuditSinkTypeWebhook,
			Webhook: &breakglassv1alpha1.WebhookSinkSpec{
				URL: "https://example.com/audit",
				AuthSecretRef: &breakglassv1alpha1.SecretKeySelector{
					Name:      "webhook-auth",
					Namespace: "other-namespace",
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `webhook auth secret "webhook-auth" namespace must be controller namespace "test-namespace", got "other-namespace"`)
	})

	t.Run("auth secret missing namespace", func(t *testing.T) {
		_, err := svc.buildWebhookSink(context.Background(), breakglassv1alpha1.AuditSinkConfig{
			Name: "webhook-sink",
			Type: breakglassv1alpha1.AuditSinkTypeWebhook,
			Webhook: &breakglassv1alpha1.WebhookSinkSpec{
				URL: "https://example.com/audit",
				AuthSecretRef: &breakglassv1alpha1.SecretKeySelector{
					Name: "webhook-auth",
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `webhook auth secret "webhook-auth" namespace must be controller namespace "test-namespace", got ""`)
	})

	t.Run("CA secret namespace", func(t *testing.T) {
		_, err := svc.buildWebhookSink(context.Background(), breakglassv1alpha1.AuditSinkConfig{
			Name: "webhook-sink",
			Type: breakglassv1alpha1.AuditSinkTypeWebhook,
			Webhook: &breakglassv1alpha1.WebhookSinkSpec{
				URL: "https://example.com/audit",
				TLS: &breakglassv1alpha1.WebhookTLSSpec{
					CASecretRef: &breakglassv1alpha1.SecretKeySelector{
						Name:      "webhook-ca",
						Namespace: "other-namespace",
					},
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `webhook CA secret "webhook-ca" namespace must be controller namespace "test-namespace", got "other-namespace"`)
	})

	t.Run("CA secret missing namespace", func(t *testing.T) {
		_, err := svc.buildWebhookSink(context.Background(), breakglassv1alpha1.AuditSinkConfig{
			Name: "webhook-sink",
			Type: breakglassv1alpha1.AuditSinkTypeWebhook,
			Webhook: &breakglassv1alpha1.WebhookSinkSpec{
				URL: "https://example.com/audit",
				TLS: &breakglassv1alpha1.WebhookTLSSpec{
					CASecretRef: &breakglassv1alpha1.SecretKeySelector{
						Name: "webhook-ca",
					},
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `webhook CA secret "webhook-ca" namespace must be controller namespace "test-namespace", got ""`)
	})
}

func TestService_BuildKubernetesSink(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "k8s-sink",
					Type: breakglassv1alpha1.AuditSinkTypeKubernetes,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Cleanup
	_ = svc.Close()
}

func TestService_ConfiguredSinkConstructionFailureDisablesRequiredAudit(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "invalid-sink",
					Type: "unknown-type",
				},
				{
					Name: "valid-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	require.Error(t, err)
	assert.False(t, svc.IsEnabled())
	assert.True(t, svc.IsConfigured())
	assert.Equal(t, ConfigurationUnavailable, svc.ConfigurationState())
	assert.Error(t, svc.EmitSync(context.Background(), &Event{Type: EventSessionTerminationIntent}))

	// Cleanup
	_ = svc.Close()
}

func TestService_MissingSinkSecretIsConfiguredButUnavailable(t *testing.T) {
	svc := NewService(fake.NewClientBuilder().WithScheme(newServiceTestScheme(t)).Build(), nil, zap.NewNop(), "test-namespace")
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-secret"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{{
				Name: "kafka",
				Type: breakglassv1alpha1.AuditSinkTypeKafka,
				Kafka: &breakglassv1alpha1.KafkaSinkSpec{
					Brokers: []string{"localhost:9092"},
					Topic:   "audit",
					TLS: &breakglassv1alpha1.KafkaTLSSpec{
						Enabled:     true,
						CASecretRef: &breakglassv1alpha1.SecretKeySelector{Name: "missing", Namespace: "test-namespace"},
					},
				},
			}},
		},
	}

	err := svc.Reload(context.Background(), config)
	require.Error(t, err)
	assert.ErrorContains(t, err, "missing")
	assert.False(t, svc.IsEnabled())
	assert.True(t, svc.IsConfigured())
	assert.Equal(t, ConfigurationUnavailable, svc.ConfigurationState())
}

func TestService_KafkaSinkMissingConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name:  "kafka-sink",
					Type:  breakglassv1alpha1.AuditSinkTypeKafka,
					Kafka: nil, // missing config
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	require.Error(t, err)
	assert.False(t, svc.IsEnabled())
	assert.True(t, svc.IsConfigured())
	assert.Equal(t, ConfigurationUnavailable, svc.ConfigurationState())
}

func TestService_BuildKafkaSinkRequiredAcks(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	tests := []struct {
		name        string
		requiredAck int
	}{
		{name: "all replicas", requiredAck: -1},
		{name: "no acks", requiredAck: 0},
		{name: "leader only", requiredAck: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, err := svc.buildKafkaSink(context.Background(), breakglassv1alpha1.AuditSinkConfig{
				Name: "kafka-sink",
				Type: breakglassv1alpha1.AuditSinkTypeKafka,
				Kafka: &breakglassv1alpha1.KafkaSinkSpec{
					Brokers:      []string{"localhost:9092"},
					Topic:        "audit-events",
					RequiredAcks: tt.requiredAck,
				},
			})
			require.NoError(t, err)
			defer func() { _ = sink.Close() }()

			kafkaSink, ok := sink.(*KafkaSink)
			require.True(t, ok)
			assert.Equal(t, tt.requiredAck, int(kafkaSink.writer.RequiredAcks))
		})
	}
}

func TestService_EmitSyncRejectsConfiguredAsyncKafka(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	svc := NewService(kubeClient, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "async-kafka"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{{
				Name: "async-kafka",
				Type: breakglassv1alpha1.AuditSinkTypeKafka,
				Kafka: &breakglassv1alpha1.KafkaSinkSpec{
					Brokers: []string{"localhost:9092"},
					Topic:   "audit-events",
					Async:   true,
				},
			}},
		},
	}

	require.NoError(t, svc.Reload(context.Background(), config))
	defer func() { require.NoError(t, svc.Close()) }()

	err := svc.EmitSync(context.Background(), &Event{Type: EventSessionExpired})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "async-kafka")
	assert.Contains(t, err.Error(), "uses asynchronous delivery")
	assert.Zero(t, svc.manager.Stats().ProcessedEvents)
}

func TestService_WebhookSinkMissingConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name:    "webhook-sink",
					Type:    breakglassv1alpha1.AuditSinkTypeWebhook,
					Webhook: nil, // missing config
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	require.Error(t, err)
	assert.False(t, svc.IsEnabled())
	assert.True(t, svc.IsConfigured())
	assert.Equal(t, ConfigurationUnavailable, svc.ConfigurationState())
}

func TestService_GetSecretKey(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"username": []byte("testuser"),
			"password": []byte("testpass"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	svc := NewService(client, nil, logger, "test-namespace")

	// Get existing key
	data, err := svc.getSecretKey(context.Background(), "test-secret", "test-namespace", "username")
	assert.NoError(t, err)
	assert.Equal(t, []byte("testuser"), data)

	// Get missing key
	_, err = svc.getSecretKey(context.Background(), "test-secret", "test-namespace", "missing-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Get from missing secret
	_, err = svc.getSecretKey(context.Background(), "missing-secret", "test-namespace", "username")
	assert.Error(t, err)
}

func TestDefaultQueuedSinkConfig(t *testing.T) {
	cfg := DefaultQueuedSinkConfig()

	assert.Equal(t, 10000, cfg.QueueSize)
	assert.Equal(t, 2, cfg.WorkerCount)
	assert.Equal(t, 5*time.Second, cfg.WriteTimeout)
	assert.True(t, cfg.DropOnFull)
	assert.Equal(t, 5, cfg.CircuitBreakerThreshold)
	assert.Equal(t, 30*time.Second, cfg.CircuitBreakerResetTime)
}

func TestService_GetSinkHealth_NoSinks(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	health := svc.GetSinkHealth()
	assert.Empty(t, health)
}

func TestService_GetSinkHealth_WithLogSink(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "test-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
					Log: &breakglassv1alpha1.LogSinkSpec{
						Level:  "info",
						Format: "json",
					},
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	require.NoError(t, err)

	health := svc.GetSinkHealth()
	// With isolated queuing, we should have one sink
	assert.NotEmpty(t, health)

	_ = svc.Close()
}

func TestService_GetQueuedSinkHealth_NoSinks(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	health := svc.GetQueuedSinkHealth()
	assert.Nil(t, health)
}

func TestService_GetQueuedSinkHealth_WithSink(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "test-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
					Log: &breakglassv1alpha1.LogSinkSpec{
						Level:  "info",
						Format: "json",
					},
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	require.NoError(t, err)

	health := svc.GetQueuedSinkHealth()
	assert.NotNil(t, health)
	assert.Len(t, health, 1)
	// The queued sink wraps the log sink and uses its name
	assert.NotEmpty(t, health[0].Name)

	_ = svc.Close()
}

func TestService_BuildKafkaTLSConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kafka-ca",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"ca.crt": []byte("test-ca-cert-data"),
		},
	}

	clientCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kafka-client-cert",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"tls.crt": []byte("test-client-cert"),
			"tls.key": []byte("test-client-key"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(caSecret, clientCertSecret).
		Build()

	svc := NewService(client, nil, logger, "test-namespace")
	ctx := context.Background()

	t.Run("with CA only", func(t *testing.T) {
		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			InsecureSkipVerify: false,
			CASecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-ca",
			},
		}

		cfg, err := svc.buildKafkaTLSConfig(ctx, tlsCfg)
		require.NoError(t, err)
		assert.True(t, cfg.Enabled)
		assert.False(t, cfg.InsecureSkipVerify)
		assert.Equal(t, []byte("test-ca-cert-data"), cfg.CACert)
	})

	t.Run("with client cert", func(t *testing.T) {
		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			ClientCertSecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-client-cert",
			},
		}

		cfg, err := svc.buildKafkaTLSConfig(ctx, tlsCfg)
		require.NoError(t, err)
		assert.Equal(t, []byte("test-client-cert"), cfg.ClientCert)
		assert.Equal(t, []byte("test-client-key"), cfg.ClientKey)
	})

	t.Run("with insecure skip verify", func(t *testing.T) {
		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			InsecureSkipVerify: true,
		}

		cfg, err := svc.buildKafkaTLSConfig(ctx, tlsCfg)
		require.NoError(t, err)
		assert.True(t, cfg.InsecureSkipVerify)
	})

	t.Run("CA secret not found", func(t *testing.T) {
		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			CASecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name: "missing-ca",
			},
		}

		_, err := svc.buildKafkaTLSConfig(ctx, tlsCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "CA certificate")
	})

	t.Run("client cert secret not found", func(t *testing.T) {
		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			ClientCertSecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name: "missing-client",
			},
		}

		_, err := svc.buildKafkaTLSConfig(ctx, tlsCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client certificate")
	})

	t.Run("client key missing", func(t *testing.T) {
		// Create secret without tls.key
		secretNoKey := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kafka-cert-no-key",
				Namespace: "test-namespace",
			},
			Data: map[string][]byte{
				"tls.crt": []byte("test-client-cert"),
			},
		}
		clientWithNoKey := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(secretNoKey).
			Build()
		svcNoKey := NewService(clientWithNoKey, nil, logger, "test-namespace")

		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			ClientCertSecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-cert-no-key",
			},
		}

		_, err := svcNoKey.buildKafkaTLSConfig(ctx, tlsCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client key")
	})
}

func TestService_BuildKafkaSASLConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)

	saslSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kafka-sasl",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"username": []byte("kafka-user"),
			"password": []byte("kafka-pass"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(saslSecret).
		Build()

	svc := NewService(client, nil, logger, "test-namespace")
	ctx := context.Background()

	t.Run("with PLAIN mechanism", func(t *testing.T) {
		saslCfg := &breakglassv1alpha1.KafkaSASLSpec{
			Mechanism: "PLAIN",
			CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-sasl",
			},
		}

		cfg, err := svc.buildKafkaSASLConfig(ctx, saslCfg)
		require.NoError(t, err)
		assert.Equal(t, "PLAIN", cfg.Mechanism)
		assert.Equal(t, "kafka-user", cfg.Username)
		assert.Equal(t, "kafka-pass", cfg.Password)
	})

	t.Run("with SCRAM-SHA-256", func(t *testing.T) {
		saslCfg := &breakglassv1alpha1.KafkaSASLSpec{
			Mechanism: "SCRAM-SHA-256",
			CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-sasl",
			},
		}

		cfg, err := svc.buildKafkaSASLConfig(ctx, saslCfg)
		require.NoError(t, err)
		assert.Equal(t, "SCRAM-SHA-256", cfg.Mechanism)
	})

	t.Run("secret not found", func(t *testing.T) {
		saslCfg := &breakglassv1alpha1.KafkaSASLSpec{
			Mechanism: "PLAIN",
			CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
				Name: "missing-secret",
			},
		}

		_, err := svc.buildKafkaSASLConfig(ctx, saslCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SASL username")
	})

	t.Run("password missing", func(t *testing.T) {
		secretNoPass := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kafka-sasl-no-pass",
				Namespace: "test-namespace",
			},
			Data: map[string][]byte{
				"username": []byte("kafka-user"),
			},
		}
		clientNoPass := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(secretNoPass).
			Build()
		svcNoPass := NewService(clientNoPass, nil, logger, "test-namespace")

		saslCfg := &breakglassv1alpha1.KafkaSASLSpec{
			Mechanism: "PLAIN",
			CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-sasl-no-pass",
			},
		}

		_, err := svcNoPass.buildKafkaSASLConfig(ctx, saslCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SASL password")
	})

	t.Run("explicit namespace", func(t *testing.T) {
		saslSecretOtherNS := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kafka-sasl-other",
				Namespace: "other-namespace",
			},
			Data: map[string][]byte{
				"username": []byte("other-user"),
				"password": []byte("other-pass"),
			},
		}
		clientOtherNS := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(saslSecretOtherNS).
			Build()
		svcOtherNS := NewService(clientOtherNS, nil, logger, "test-namespace")

		saslCfg := &breakglassv1alpha1.KafkaSASLSpec{
			Mechanism: "PLAIN",
			CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
				Name:      "kafka-sasl-other",
				Namespace: "other-namespace",
			},
		}

		cfg, err := svcOtherNS.buildKafkaSASLConfig(ctx, saslCfg)
		require.NoError(t, err)
		assert.Equal(t, "other-user", cfg.Username)
	})
}

func TestService_GetStats_NoManager(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	// No manager initialized
	stats := svc.GetStats()
	assert.Nil(t, stats)
}

func TestService_GetStats_WithManager(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	// Reload with a valid config to initialize the manager
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-stats-config",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "log-sink",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	require.NoError(t, err)

	// Manager should now be initialized
	stats := svc.GetStats()
	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.ProcessedEvents, int64(0))
	assert.GreaterOrEqual(t, stats.DroppedEvents, int64(0))

	_ = svc.Close()
}

func TestService_Manager_NilBeforeReload(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")
	assert.Nil(t, svc.Manager())
}

func TestService_Manager_NonNilAfterSuccessfulReload(t *testing.T) {
	logger := zap.NewNop()
	scheme := newServiceTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, nil, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-manager-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "log-sink",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	require.NoError(t, err)
	assert.NotNil(t, svc.Manager())

	_ = svc.Close()
}
