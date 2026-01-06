// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package mail

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestNewService(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, "Test Branding", logger.Sugar())
	assert.NotNil(t, svc)
	assert.False(t, svc.IsEnabled())
}

func TestService_StartWithoutMailProvider(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, "Test Branding", logger.Sugar())

	// Start should fail gracefully if no MailProvider exists
	err := svc.Start(context.Background())
	assert.Error(t, err)
	assert.False(t, svc.IsEnabled())
}

func TestService_StartWithDefaultMailProvider(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	mailProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-provider",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			DisplayName: "Test Mail Provider",
			Default:     true,
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "localhost",
				Port: 1025,
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "test@example.com",
				Name:    "Test Sender",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(mailProvider).
		Build()

	svc := NewService(client, "Test Branding", logger.Sugar())

	err := svc.Start(context.Background())
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Cleanup
	_ = svc.Stop(context.Background())
}

func TestService_EnqueueWhenDisabled(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, "Test Branding", logger.Sugar())

	// Enqueue should silently succeed when disabled
	err := svc.Enqueue("session-1", []string{"test@example.com"}, "Subject", "Body")
	assert.NoError(t, err)
}

func TestService_Reload(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	mailProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-provider",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			DisplayName: "Test Mail Provider",
			Default:     true,
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "localhost",
				Port: 1025,
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "test@example.com",
				Name:    "Test Sender",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(mailProvider).
		Build()

	svc := NewService(client, "Test Branding", logger.Sugar())

	// Initially disabled
	assert.False(t, svc.IsEnabled())

	// Reload should enable
	err := svc.Reload(context.Background())
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Get the underlying queue (for test verification)
	queue := svc.GetQueue()
	assert.NotNil(t, queue)

	// Cleanup
	_ = svc.Stop(context.Background())
	assert.False(t, svc.IsEnabled())
}

func TestService_StopWhenNotStarted(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, "Test Branding", logger.Sugar())

	// Stop should not error when not started
	err := svc.Stop(context.Background())
	assert.NoError(t, err)
}

// TestService_HotReloadAfterNoProviderAtStartup tests the full hot-reload scenario:
// 1. Start service when no MailProvider exists
// 2. Create a MailProvider dynamically
// 3. Call Reload to pick up the new provider
// 4. Verify mail service becomes enabled
func TestService_HotReloadAfterNoProviderAtStartup(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	// Start with empty cluster (no MailProvider)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, "Test Branding", logger.Sugar())

	// Start should fail gracefully - no provider exists
	err := svc.Start(context.Background())
	assert.Error(t, err, "Start should fail when no MailProvider exists")
	assert.False(t, svc.IsEnabled(), "Service should be disabled after failed start")

	// Simulate creating a MailProvider dynamically
	mailProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dynamic-provider",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			DisplayName: "Dynamic Mail Provider",
			Default:     true,
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "mail.example.com",
				Port: 587,
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "noreply@example.com",
				Name:    "Breakglass Notifications",
			},
		},
	}
	err = client.Create(context.Background(), mailProvider)
	assert.NoError(t, err, "Should be able to create MailProvider")

	// Simulate what MailProviderReconciler.OnMailProviderChange does
	err = svc.Reload(context.Background())
	assert.NoError(t, err, "Reload should succeed after provider is created")
	assert.True(t, svc.IsEnabled(), "Service should be enabled after reload")

	// Verify we can now enqueue emails
	queue := svc.GetQueue()
	assert.NotNil(t, queue, "Queue should exist after reload")

	// Cleanup
	err = svc.Stop(context.Background())
	assert.NoError(t, err)
	assert.False(t, svc.IsEnabled(), "Service should be disabled after stop")
}
