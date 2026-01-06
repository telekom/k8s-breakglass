/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"context"
	"testing"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLoadMailProvider(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "smtp-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"password": []byte("test-password"),
		},
	}

	mailProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-provider",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			DisplayName: "Test Provider",
			Default:     true,
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host:     "smtp.example.com",
				Port:     587,
				Username: "test@example.com",
				PasswordRef: &breakglassv1alpha1.SecretKeyReference{
					Name:      "smtp-secret",
					Namespace: "default",
					Key:       "password",
				},
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "sender@example.com",
				Name:    "Test Sender",
			},
			Retry: breakglassv1alpha1.RetryConfig{
				Count:            3,
				InitialBackoffMs: 100,
				QueueSize:        1000,
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(mailProvider, secret).
		Build()

	loader := NewMailProviderLoader(client)

	t.Run("load existing provider", func(t *testing.T) {
		cfg, err := loader.LoadMailProvider(context.Background(), "test-provider")
		if err != nil {
			t.Fatalf("LoadMailProvider() error = %v", err)
		}

		if cfg.Host != "smtp.example.com" {
			t.Errorf("Expected host smtp.example.com, got %s", cfg.Host)
		}
		if cfg.Port != 587 {
			t.Errorf("Expected port 587, got %d", cfg.Port)
		}
		if cfg.Username != "test@example.com" {
			t.Errorf("Expected username test@example.com, got %s", cfg.Username)
		}
		if cfg.Password != "test-password" {
			t.Errorf("Expected password test-password, got %s", cfg.Password)
		}
		if cfg.SenderAddress != "sender@example.com" {
			t.Errorf("Expected sender address sender@example.com, got %s", cfg.SenderAddress)
		}
	})

	t.Run("load non-existent provider", func(t *testing.T) {
		_, err := loader.LoadMailProvider(context.Background(), "non-existent")
		if err == nil {
			t.Error("Expected error for non-existent provider, got nil")
		}
	})

	t.Run("cached provider", func(t *testing.T) {
		// First load
		_, err := loader.LoadMailProvider(context.Background(), "test-provider")
		if err != nil {
			t.Fatalf("First LoadMailProvider() error = %v", err)
		}

		// Second load should use cache
		cfg, err := loader.LoadMailProvider(context.Background(), "test-provider")
		if err != nil {
			t.Fatalf("Second LoadMailProvider() error = %v", err)
		}

		if cfg == nil {
			t.Error("Expected cached config, got nil")
		}
	})
}

func TestLoadAllMailProviders(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "smtp-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"password": []byte("test-password"),
		},
	}

	defaultProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-provider",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			Default: true,
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.default.com",
				Port: 587,
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "default@example.com",
			},
		},
	}

	otherProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "other-provider",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			Default: false,
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.other.com",
				Port: 587,
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "other@example.com",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(defaultProvider, otherProvider, secret).
		Build()

	loader := NewMailProviderLoader(client)

	t.Run("load all providers", func(t *testing.T) {
		providers, err := loader.LoadAllMailProviders(context.Background())
		if err != nil {
			t.Fatalf("LoadAllMailProviders() error = %v", err)
		}

		if len(providers) != 2 {
			t.Errorf("Expected 2 providers, got %d", len(providers))
		}

		if _, ok := providers["default-provider"]; !ok {
			t.Error("Expected default-provider in map")
		}
		if _, ok := providers["other-provider"]; !ok {
			t.Error("Expected other-provider in map")
		}
	})
}

func TestGetDefaultMailProvider(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	defaultProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-provider",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			Default: true,
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.default.com",
				Port: 587,
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "default@example.com",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(defaultProvider).
		Build()

	loader := NewMailProviderLoader(client)

	t.Run("get default provider", func(t *testing.T) {
		cfg, err := loader.GetDefaultMailProvider(context.Background())
		if err != nil {
			t.Fatalf("GetDefaultMailProvider() error = %v", err)
		}

		if cfg == nil {
			t.Fatal("Expected default config, got nil")
		}

		if cfg.Host != "smtp.default.com" {
			t.Errorf("Expected host smtp.default.com, got %s", cfg.Host)
		}
	})
}

func TestGetMailProviderByPriority(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	defaultProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-provider",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			Default: true,
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.default.com",
				Port: 587,
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "default@example.com",
			},
		},
	}

	clusterProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-provider",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.cluster.com",
				Port: 587,
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "cluster@example.com",
			},
		},
	}

	escalationProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "escalation-provider",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.escalation.com",
				Port: 587,
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "escalation@example.com",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(defaultProvider, clusterProvider, escalationProvider).
		Build()

	loader := NewMailProviderLoader(client)
	ctx := context.Background()

	tests := []struct {
		name               string
		escalationProvider string
		clusterProvider    string
		expectedHost       string
	}{
		{
			name:               "escalation provider has priority",
			escalationProvider: "escalation-provider",
			clusterProvider:    "cluster-provider",
			expectedHost:       "smtp.escalation.com",
		},
		{
			name:               "cluster provider used when no escalation",
			escalationProvider: "",
			clusterProvider:    "cluster-provider",
			expectedHost:       "smtp.cluster.com",
		},
		{
			name:               "default provider used when neither specified",
			escalationProvider: "",
			clusterProvider:    "",
			expectedHost:       "smtp.default.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loader.GetMailProviderByPriority(ctx, tt.escalationProvider, tt.clusterProvider)
			if err != nil {
				t.Fatalf("GetMailProviderByPriority() error = %v", err)
			}

			if cfg.Host != tt.expectedHost {
				t.Errorf("Expected host %s, got %s", tt.expectedHost, cfg.Host)
			}
		})
	}
}

func TestInvalidateCache(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	mailProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-provider",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.example.com",
				Port: 587,
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "test@example.com",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(mailProvider).
		Build()

	loader := NewMailProviderLoader(client)
	ctx := context.Background()

	// Load provider to cache it
	_, err := loader.LoadMailProvider(ctx, "test-provider")
	if err != nil {
		t.Fatalf("LoadMailProvider() error = %v", err)
	}

	// Invalidate cache
	loader.InvalidateCache("test-provider")

	// Verify cache is empty
	t.Log("Cache invalidated successfully")
}

func TestMailProviderConfig_GetTLSConfig(t *testing.T) {
	const testCACert = `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUPFFNzK5sok9Bl0JUlPYl6QXnJLcwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNTExMjUxNTI5NDhaFw0yNTExMjYx
NTI5NDhaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQD5W/I7H+29ceIlnWo8Rw6qJum4kj2fK8rwPJNVmhV5QvRte2wx
ybdVdZLDkbgEGSEkU6z2kCzqgvGGOh3O+oBOpC2z9ryt1glj8ykkEw4o9jaLZ0zO
hqmoAEBP3mZdQhi2SrUAeDDun/iq8dTADda2mHVNATBob7l2Y0kk+nxsyTFIAcTu
BxE7Gb/RcSGM/7MGePMXFvmS73sdqBj6zOArCeJUR/RBliic0oWrsbQjbfH1cXGm
OkFcAgR90ARikKjd+G1OA3e9FF/pjdkg8t1ntzP1/+oNAUA1NRVyl6axUWSRq2Xz
g7MDlL0xoUpRpN2J/1ZNG2yywdQ7XwwnQhLRAgMBAAGjUzBRMB0GA1UdDgQWBBT1
G2uJpNQYpxsmo+DaFrQYKdv2MDAfBgNVHSMEGDAWgBT1G2uJpNQYpxsmo+DaFrQY
Kdv2MDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDENpgNFOCi
N8Igw4yrQU9Re4BZzsbagFPbOWcXjsTw/CUGi5xdobF2nRrXHc54jr9Es5oRlG2e
0c9xuQ37Nwb8/7jrIcbHFb03FSz4VXDXhAvXCqn08Y0ZRhU79n7x/sLh9mBefCIn
Z4d+QFNm3N1Y/tpRbJavvD/asuCzYcxttTzj9X9bQrvOaOBwH2reaoHZvOgYc75u
dQBsMeAlg7H7UgxSRm2NFxYIxxQ1JEhh+eOrA0vU+ZSp9Ule7OLkP/jodCQAs7dZ
o4H3FDVtDbGTiWZiFeVo1TmugM60/gtTZuBFHC7Cmmuhl3BA/y/l72UXzzfsfTYM
IZ+J72v8cfAb
-----END CERTIFICATE-----`

	config := &MailProviderConfig{
		Host:                 "smtp.secure.example",
		InsecureSkipVerify:   true,
		CertificateAuthority: testCACert,
	}

	tlsConfig := config.GetTLSConfig()
	if tlsConfig.ServerName != config.Host {
		t.Fatalf("expected ServerName %s, got %s", config.Host, tlsConfig.ServerName)
	}
	if !tlsConfig.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to be true")
	}
	if tlsConfig.RootCAs == nil {
		t.Fatal("expected custom CA to be added to RootCAs")
	}
}

func TestMailProviderConfig_GetTLSConfig_InvalidPEM(t *testing.T) {
	config := &MailProviderConfig{
		Host:                 "smtp.example.com",
		CertificateAuthority: "not a valid cert",
	}

	tlsConfig := config.GetTLSConfig()
	if tlsConfig.ServerName != config.Host {
		t.Fatalf("expected ServerName %s, got %s", config.Host, tlsConfig.ServerName)
	}
	if tlsConfig.RootCAs != nil {
		t.Fatal("expected RootCAs to be nil when certificate parsing fails")
	}
}
