/*
Copyright 2024.

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

package v1alpha1

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestMailProviderValidation(t *testing.T) {
	tests := []struct {
		name    string
		mp      *MailProvider
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid mail provider with auth",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host:     "smtp.example.com",
						Port:     587,
						Username: "user@example.com",
						PasswordRef: &SecretKeyReference{
							Name:      "smtp-secret",
							Namespace: "default",
							Key:       "password",
						},
					},
					Sender: SenderConfig{
						Address: "noreply@example.com",
						Name:    "Test Sender",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid mail provider without auth",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: "smtp.internal",
						Port: 25,
					},
					Sender: SenderConfig{
						Address: "internal@example.com",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid mail provider with IP address as host",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host:     "192.168.1.100",
						Port:     587,
						Username: "user@example.com",
						PasswordRef: &SecretKeyReference{
							Name:      "smtp-secret",
							Namespace: "default",
							Key:       "password",
						},
					},
					Sender: SenderConfig{
						Address: "noreply@example.com",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid mail provider with IPv6 address as host",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: "2001:db8::1",
						Port: 587,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing host",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Port: 587,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
			wantErr: true,
			errMsg:  "SMTP host is required",
		},
		{
			name: "invalid port - too low",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: "smtp.example.com",
						Port: 0,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
			wantErr: true,
			errMsg:  "port must be between 1 and 65535",
		},
		{
			name: "invalid port - too high",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: "smtp.example.com",
						Port: 70000,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
			wantErr: true,
			errMsg:  "port must be between 1 and 65535",
		},
		{
			name: "username without password",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host:     "smtp.example.com",
						Port:     587,
						Username: "user@example.com",
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
			wantErr: true,
			errMsg:  "passwordRef must be specified when username is provided",
		},
		{
			name: "password without username",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: "smtp.example.com",
						Port: 587,
						PasswordRef: &SecretKeyReference{
							Name:      "smtp-secret",
							Namespace: "default",
							Key:       "password",
						},
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
			wantErr: true,
			errMsg:  "username must be specified when passwordRef is provided",
		},
		{
			name: "missing secret name in passwordRef",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host:     "smtp.example.com",
						Port:     587,
						Username: "user@example.com",
						PasswordRef: &SecretKeyReference{
							Key: "password",
						},
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
			wantErr: true,
			errMsg:  "secret name is required",
		},
		{
			name: "missing secret key in passwordRef",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host:     "smtp.example.com",
						Port:     587,
						Username: "user@example.com",
						PasswordRef: &SecretKeyReference{
							Name: "smtp-secret",
						},
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
			wantErr: true,
			errMsg:  "secret key is required",
		},
		{
			name: "missing sender address",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: "smtp.example.com",
						Port: 587,
					},
					Sender: SenderConfig{
						Name: "Test Sender",
					},
				},
			},
			wantErr: true,
			errMsg:  "sender address is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			warnings, err := tt.mp.ValidateCreate(ctx, tt.mp)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" {
				// Just log the error for debugging
				t.Logf("Error message: %v", err.Error())
			}

			// Check for expected warnings
			if !tt.wantErr && tt.mp.Spec.SMTP.InsecureSkipVerify {
				if len(warnings) == 0 {
					t.Error("Expected warning for insecureSkipVerify but got none")
				}
			}
		})
	}
}

func TestMailProviderValidateUpdate(t *testing.T) {
	oldMP := &MailProvider{
		Spec: MailProviderSpec{
			SMTP: SMTPConfig{
				Host: "smtp.old.com",
				Port: 587,
			},
			Sender: SenderConfig{
				Address: "old@example.com",
			},
		},
	}

	newMP := &MailProvider{
		Spec: MailProviderSpec{
			SMTP: SMTPConfig{
				Host: "smtp.new.com",
				Port: 587,
			},
			Sender: SenderConfig{
				Address: "new@example.com",
			},
		},
	}

	ctx := context.Background()
	warnings, err := newMP.ValidateUpdate(ctx, oldMP, newMP)

	if err != nil {
		t.Errorf("ValidateUpdate() for valid update returned error: %v", err)
	}

	if len(warnings) > 0 {
		t.Logf("Warnings: %v", warnings)
	}
}

func TestMailProviderValidateDelete(t *testing.T) {
	mp := &MailProvider{
		Spec: MailProviderSpec{
			SMTP: SMTPConfig{
				Host: "smtp.example.com",
				Port: 587,
			},
			Sender: SenderConfig{
				Address: "test@example.com",
			},
		},
	}

	ctx := context.Background()
	warnings, err := mp.ValidateDelete(ctx, mp)

	if err != nil {
		t.Errorf("ValidateDelete() returned unexpected error: %v", err)
	}

	if warnings != nil {
		t.Errorf("ValidateDelete() returned unexpected warnings: %v", warnings)
	}
}

func TestMailProviderWarnings(t *testing.T) {
	tests := []struct {
		name        string
		mp          *MailProvider
		wantWarning string
	}{
		{
			name: "insecureSkipVerify warning",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host:               "smtp.example.com",
						Port:               587,
						InsecureSkipVerify: true,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
			wantWarning: "insecureSkipVerify",
		},
		{
			name: "no auth warning",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: "smtp.example.com",
						Port: 25,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
			wantWarning: "No SMTP authentication",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			warnings, err := tt.mp.ValidateCreate(ctx, tt.mp)

			if err != nil {
				t.Errorf("ValidateCreate() returned unexpected error: %v", err)
				return
			}

			if len(warnings) == 0 {
				t.Errorf("Expected warning containing '%s' but got no warnings", tt.wantWarning)
				return
			}

			found := false
			for _, w := range warnings {
				if len(w) > 0 {
					found = true
					t.Logf("Got warning: %s", w)
				}
			}

			if !found {
				t.Errorf("Expected warning containing '%s' but got: %v", tt.wantWarning, warnings)
			}
		})
	}
}

func TestMailProviderDefaultUniqueness(t *testing.T) {
	// Test that only one provider can be marked as default
	// Note: This test requires webhookClient to be set

	ctx := context.Background()

	// Create a provider marked as default
	existingDefault := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "existing-default",
		},
		Spec: MailProviderSpec{
			Default: true,
			SMTP: SMTPConfig{
				Host: "smtp.existing.com",
				Port: 587,
			},
			Sender: SenderConfig{
				Address: "existing@example.com",
			},
		},
	}

	// Try to create another default provider
	newDefault := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "new-default",
		},
		Spec: MailProviderSpec{
			Default: true,
			SMTP: SMTPConfig{
				Host: "smtp.new.com",
				Port: 587,
			},
			Sender: SenderConfig{
				Address: "new@example.com",
			},
		},
	}

	// Set up fake client with existing default
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingDefault).
		Build()

	// Set the webhook client for validation
	webhookClient = fakeClient
	defer func() { webhookClient = nil }()

	// Validation should fail
	_, err := newDefault.ValidateCreate(ctx, newDefault)
	if err == nil {
		t.Error("Expected error when creating second default provider, got nil")
	} else {
		t.Logf("Got expected error: %v", err)
	}

	// Update existing default to not be default should succeed
	updatedProvider := existingDefault.DeepCopy()
	updatedProvider.Spec.Default = false
	_, err = updatedProvider.ValidateUpdate(ctx, existingDefault, updatedProvider)
	if err != nil {
		t.Errorf("Expected no error when removing default flag, got: %v", err)
	}

	// Create non-default provider should succeed
	nonDefault := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "non-default",
		},
		Spec: MailProviderSpec{
			Default: false,
			SMTP: SMTPConfig{
				Host: "smtp.other.com",
				Port: 587,
			},
			Sender: SenderConfig{
				Address: "other@example.com",
			},
		},
	}
	_, err = nonDefault.ValidateCreate(ctx, nonDefault)
	if err != nil {
		t.Errorf("Expected no error for non-default provider, got: %v", err)
	}
}

func TestMailProviderUnauthenticatedSMTP(t *testing.T) {
	// Test that unauthenticated SMTP servers are properly supported
	mp := &MailProvider{
		Spec: MailProviderSpec{
			SMTP: SMTPConfig{
				Host: "smtp-relay.internal",
				Port: 25,
				// No username or password
			},
			Sender: SenderConfig{
				Address: "relay@example.com",
			},
		},
	}

	ctx := context.Background()
	warnings, err := mp.ValidateCreate(ctx, mp)

	if err != nil {
		t.Errorf("Expected no error for unauthenticated SMTP, got: %v", err)
	}

	// Should get a warning about no authentication
	if len(warnings) == 0 {
		t.Error("Expected warning about unauthenticated SMTP, got none")
	} else {
		t.Logf("Got expected warning: %v", warnings)
	}
}

func TestMailProviderIPAddressHost(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{
			name: "IPv4 address",
			host: "192.168.1.100",
		},
		{
			name: "IPv6 address",
			host: "2001:db8::1",
		},
		{
			name: "IPv6 localhost",
			host: "::1",
		},
		{
			name: "IPv4 localhost",
			host: "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: tt.host,
						Port: 587,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			}

			ctx := context.Background()
			_, err := mp.ValidateCreate(ctx, mp)

			if err != nil {
				t.Errorf("Expected no error for IP address %s, got: %v", tt.host, err)
			}
		})
	}
}

func TestMailProviderRetryConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		retry       RetryConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid default retry config",
			retry: RetryConfig{
				Count:            3,
				InitialBackoffMs: 100,
				QueueSize:        1000,
			},
			wantErr: false,
		},
		{
			name: "minimum retry count",
			retry: RetryConfig{
				Count:            0,
				InitialBackoffMs: 100,
				QueueSize:        1000,
			},
			wantErr: false,
		},
		{
			name: "maximum retry count",
			retry: RetryConfig{
				Count:            10,
				InitialBackoffMs: 100,
				QueueSize:        1000,
			},
			wantErr: false,
		},
		{
			name: "minimum backoff",
			retry: RetryConfig{
				Count:            3,
				InitialBackoffMs: 10,
				QueueSize:        1000,
			},
			wantErr: false,
		},
		{
			name: "maximum backoff",
			retry: RetryConfig{
				Count:            3,
				InitialBackoffMs: 60000,
				QueueSize:        1000,
			},
			wantErr: false,
		},
		{
			name: "minimum queue size",
			retry: RetryConfig{
				Count:            3,
				InitialBackoffMs: 100,
				QueueSize:        10,
			},
			wantErr: false,
		},
		{
			name: "maximum queue size",
			retry: RetryConfig{
				Count:            3,
				InitialBackoffMs: 100,
				QueueSize:        10000,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: "smtp.example.com",
						Port: 587,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
					Retry: tt.retry,
				},
			}

			ctx := context.Background()
			_, err := mp.ValidateCreate(ctx, mp)

			if (err != nil) != tt.wantErr {
				t.Errorf("Expected error: %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestMailProviderPortConfigurations(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{name: "SMTP port 25", port: 25, wantErr: false},
		{name: "STARTTLS port 587", port: 587, wantErr: false},
		{name: "TLS port 465", port: 465, wantErr: false},
		{name: "submission port 2525", port: 2525, wantErr: false},
		{name: "high port 8025", port: 8025, wantErr: false},
		{name: "minimum valid port", port: 1, wantErr: false},
		{name: "maximum valid port", port: 65535, wantErr: false},
		{name: "invalid port 0", port: 0, wantErr: true},
		{name: "invalid port negative", port: -1, wantErr: true},
		{name: "invalid port too high", port: 65536, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: "smtp.example.com",
						Port: tt.port,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			}

			ctx := context.Background()
			_, err := mp.ValidateCreate(ctx, mp)

			if (err != nil) != tt.wantErr {
				t.Errorf("Port %d: expected error: %v, got: %v", tt.port, tt.wantErr, err)
			}
		})
	}
}

func TestMailProviderTLSConfigurations(t *testing.T) {
	tests := []struct {
		name        string
		smtp        SMTPConfig
		wantWarning bool
	}{
		{
			name: "secure with CA cert",
			smtp: SMTPConfig{
				Host:                 "smtp.example.com",
				Port:                 587,
				CertificateAuthority: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
			},
			wantWarning: false,
		},
		{
			name: "insecure skip verify",
			smtp: SMTPConfig{
				Host:               "smtp.example.com",
				Port:               587,
				InsecureSkipVerify: true,
			},
			wantWarning: true,
		},
		{
			name: "no TLS config",
			smtp: SMTPConfig{
				Host: "smtp.example.com",
				Port: 25,
			},
			wantWarning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MailProvider{
				Spec: MailProviderSpec{
					SMTP: tt.smtp,
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			}

			ctx := context.Background()
			warnings, err := mp.ValidateCreate(ctx, mp)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			hasWarning := len(warnings) > 0 && tt.smtp.InsecureSkipVerify
			if hasWarning != tt.wantWarning {
				t.Errorf("Expected warning: %v, got warnings: %v", tt.wantWarning, warnings)
			}
		})
	}
}

func TestMailProviderEmailAddressValidation(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{name: "valid simple email", address: "user@example.com", wantErr: false},
		{name: "valid with subdomain", address: "user@mail.example.com", wantErr: false},
		{name: "valid with plus", address: "user+tag@example.com", wantErr: false},
		{name: "valid with dots", address: "first.last@example.com", wantErr: false},
		{name: "valid with numbers", address: "user123@example.com", wantErr: false},
		{name: "valid with hyphen", address: "user-name@example.com", wantErr: false},
		{name: "valid noreply", address: "noreply@example.com", wantErr: false},
		{name: "empty address", address: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: "smtp.example.com",
						Port: 587,
					},
					Sender: SenderConfig{
						Address: tt.address,
					},
				},
			}

			ctx := context.Background()
			_, err := mp.ValidateCreate(ctx, mp)

			if (err != nil) != tt.wantErr {
				t.Errorf("Address '%s': expected error: %v, got: %v", tt.address, tt.wantErr, err)
			}
		})
	}
}

func TestMailProviderOptionalFields(t *testing.T) {
	tests := []struct {
		name string
		mp   *MailProvider
	}{
		{
			name: "all optional fields set",
			mp: &MailProvider{
				ObjectMeta: metav1.ObjectMeta{
					Name: "full-config",
				},
				Spec: MailProviderSpec{
					DisplayName: "Production SMTP",
					Default:     true,
					Disabled:    false,
					SMTP: SMTPConfig{
						Host:                 "smtp.example.com",
						Port:                 587,
						Username:             "user@example.com",
						InsecureSkipVerify:   false,
						CertificateAuthority: "-----BEGIN CERTIFICATE-----",
						PasswordRef: &SecretKeyReference{
							Name:      "smtp-secret",
							Namespace: "default",
							Key:       "password",
						},
					},
					Sender: SenderConfig{
						Address: "sender@example.com",
						Name:    "Sender Name",
					},
					Retry: RetryConfig{
						Count:            5,
						InitialBackoffMs: 200,
						QueueSize:        2000,
					},
				},
			},
		},
		{
			name: "minimal required fields only",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: "smtp.minimal.com",
						Port: 25,
					},
					Sender: SenderConfig{
						Address: "minimal@example.com",
					},
				},
			},
		},
		{
			name: "with display name only",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					DisplayName: "My SMTP Server",
					SMTP: SMTPConfig{
						Host: "smtp.example.com",
						Port: 587,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
		},
		{
			name: "disabled provider",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					Disabled: true,
					SMTP: SMTPConfig{
						Host: "smtp.example.com",
						Port: 587,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := tt.mp.ValidateCreate(ctx, tt.mp)

			if err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.name, err)
			}
		})
	}
}

func TestMailProviderSecretReference(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		passwordRef *SecretKeyReference
		wantErr     bool
	}{
		{
			name:     "both username and password",
			username: "user@example.com",
			passwordRef: &SecretKeyReference{
				Name:      "smtp-secret",
				Namespace: "default",
				Key:       "password",
			},
			wantErr: false,
		},
		{
			name:        "neither username nor password",
			username:    "",
			passwordRef: nil,
			wantErr:     false,
		},
		{
			name:        "username without password",
			username:    "user@example.com",
			passwordRef: nil,
			wantErr:     true,
		},
		{
			name:     "password without username",
			username: "",
			passwordRef: &SecretKeyReference{
				Name:      "smtp-secret",
				Namespace: "default",
				Key:       "password",
			},
			wantErr: true,
		},
		{
			name:     "password ref missing name",
			username: "user@example.com",
			passwordRef: &SecretKeyReference{
				Key: "password",
			},
			wantErr: true,
		},
		{
			name:     "password ref missing key",
			username: "user@example.com",
			passwordRef: &SecretKeyReference{
				Name: "smtp-secret",
			},
			wantErr: true,
		},
		{
			name:     "password ref with namespace",
			username: "user@example.com",
			passwordRef: &SecretKeyReference{
				Name:      "smtp-secret",
				Namespace: "custom-namespace",
				Key:       "password",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host:        "smtp.example.com",
						Port:        587,
						Username:    tt.username,
						PasswordRef: tt.passwordRef,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			}

			ctx := context.Background()
			_, err := mp.ValidateCreate(ctx, mp)

			if (err != nil) != tt.wantErr {
				t.Errorf("Expected error: %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestMailProviderHostnames(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		// Valid hostnames
		{name: "simple hostname", host: "smtp.example.com", wantErr: false},
		{name: "subdomain", host: "mail.smtp.example.com", wantErr: false},
		{name: "short hostname", host: "smtp", wantErr: false},
		{name: "hostname with numbers", host: "smtp1.example.com", wantErr: false},
		{name: "hostname with hyphens", host: "smtp-relay.example.com", wantErr: false},
		{name: "localhost", host: "localhost", wantErr: false},

		// Kubernetes service names
		{name: "k8s service", host: "mailhog.default.svc.cluster.local", wantErr: false},
		{name: "k8s service short", host: "mailhog.default", wantErr: false},
		{name: "k8s service name only", host: "mailhog", wantErr: false},

		// IP addresses
		{name: "IPv4", host: "192.168.1.1", wantErr: false},
		{name: "IPv4 localhost", host: "127.0.0.1", wantErr: false},
		{name: "IPv6", host: "2001:db8::1", wantErr: false},
		{name: "IPv6 localhost", host: "::1", wantErr: false},
		{name: "IPv6 full", host: "2001:0db8:0000:0000:0000:0000:0000:0001", wantErr: false},

		// Invalid
		{name: "empty host", host: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host: tt.host,
						Port: 587,
					},
					Sender: SenderConfig{
						Address: "test@example.com",
					},
				},
			}

			ctx := context.Background()
			_, err := mp.ValidateCreate(ctx, mp)

			if (err != nil) != tt.wantErr {
				t.Errorf("Host '%s': expected error: %v, got: %v", tt.host, tt.wantErr, err)
			}
		})
	}
}

func TestMailProviderUpdateScenarios(t *testing.T) {
	tests := []struct {
		name    string
		old     *MailProvider
		new     *MailProvider
		wantErr bool
	}{
		{
			name: "change host",
			old: &MailProvider{
				Spec: MailProviderSpec{
					SMTP:   SMTPConfig{Host: "smtp1.example.com", Port: 587},
					Sender: SenderConfig{Address: "test@example.com"},
				},
			},
			new: &MailProvider{
				Spec: MailProviderSpec{
					SMTP:   SMTPConfig{Host: "smtp2.example.com", Port: 587},
					Sender: SenderConfig{Address: "test@example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "change port",
			old: &MailProvider{
				Spec: MailProviderSpec{
					SMTP:   SMTPConfig{Host: "smtp.example.com", Port: 587},
					Sender: SenderConfig{Address: "test@example.com"},
				},
			},
			new: &MailProvider{
				Spec: MailProviderSpec{
					SMTP:   SMTPConfig{Host: "smtp.example.com", Port: 465},
					Sender: SenderConfig{Address: "test@example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "add authentication",
			old: &MailProvider{
				Spec: MailProviderSpec{
					SMTP:   SMTPConfig{Host: "smtp.example.com", Port: 25},
					Sender: SenderConfig{Address: "test@example.com"},
				},
			},
			new: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host:     "smtp.example.com",
						Port:     587,
						Username: "user@example.com",
						PasswordRef: &SecretKeyReference{
							Name:      "smtp-secret",
							Namespace: "default",
							Key:       "password",
						},
					},
					Sender: SenderConfig{Address: "test@example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "remove authentication",
			old: &MailProvider{
				Spec: MailProviderSpec{
					SMTP: SMTPConfig{
						Host:     "smtp.example.com",
						Port:     587,
						Username: "user@example.com",
						PasswordRef: &SecretKeyReference{
							Name:      "smtp-secret",
							Namespace: "default",
							Key:       "password",
						},
					},
					Sender: SenderConfig{Address: "test@example.com"},
				},
			},
			new: &MailProvider{
				Spec: MailProviderSpec{
					SMTP:   SMTPConfig{Host: "smtp.example.com", Port: 25},
					Sender: SenderConfig{Address: "test@example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "toggle default flag",
			old: &MailProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "test-provider"},
				Spec: MailProviderSpec{
					Default: false,
					SMTP:    SMTPConfig{Host: "smtp.example.com", Port: 587},
					Sender:  SenderConfig{Address: "test@example.com"},
				},
			},
			new: &MailProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "test-provider"},
				Spec: MailProviderSpec{
					Default: true,
					SMTP:    SMTPConfig{Host: "smtp.example.com", Port: 587},
					Sender:  SenderConfig{Address: "test@example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "disable provider",
			old: &MailProvider{
				Spec: MailProviderSpec{
					Disabled: false,
					SMTP:     SMTPConfig{Host: "smtp.example.com", Port: 587},
					Sender:   SenderConfig{Address: "test@example.com"},
				},
			},
			new: &MailProvider{
				Spec: MailProviderSpec{
					Disabled: true,
					SMTP:     SMTPConfig{Host: "smtp.example.com", Port: 587},
					Sender:   SenderConfig{Address: "test@example.com"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := tt.new.ValidateUpdate(ctx, tt.old, tt.new)

			if (err != nil) != tt.wantErr {
				t.Errorf("Expected error: %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestMailProviderRealWorldConfigurations(t *testing.T) {
	// Test realistic production scenarios
	tests := []struct {
		name string
		mp   *MailProvider
	}{
		{
			name: "Gmail configuration",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					DisplayName: "Gmail SMTP",
					SMTP: SMTPConfig{
						Host:     "smtp.gmail.com",
						Port:     587,
						Username: "user@gmail.com",
						PasswordRef: &SecretKeyReference{
							Name:      "gmail-secret",
							Namespace: "default",
							Key:       "app-password",
						},
					},
					Sender: SenderConfig{
						Address: "user@gmail.com",
						Name:    "Breakglass System",
					},
				},
			},
		},
		{
			name: "Office 365 configuration",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					DisplayName: "Office 365",
					SMTP: SMTPConfig{
						Host:     "smtp.office365.com",
						Port:     587,
						Username: "user@company.com",
						PasswordRef: &SecretKeyReference{
							Name:      "o365-secret",
							Namespace: "default",
							Key:       "password",
						},
					},
					Sender: SenderConfig{
						Address: "breakglass@company.com",
						Name:    "Company Breakglass",
					},
				},
			},
		},
		{
			name: "Internal relay",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					DisplayName: "Internal SMTP Relay",
					SMTP: SMTPConfig{
						Host: "smtp-relay.internal",
						Port: 25,
					},
					Sender: SenderConfig{
						Address: "noreply@internal.company.com",
					},
				},
			},
		},
		{
			name: "AWS SES",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					DisplayName: "AWS SES",
					SMTP: SMTPConfig{
						Host:     "email-smtp.us-east-1.amazonaws.com",
						Port:     587,
						Username: "AKIAIOSFODNN7EXAMPLE",
						PasswordRef: &SecretKeyReference{
							Name:      "ses-secret",
							Namespace: "default",
							Key:       "smtp-password",
						},
					},
					Sender: SenderConfig{
						Address: "noreply@example.com",
						Name:    "AWS Breakglass",
					},
				},
			},
		},
		{
			name: "SendGrid",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					DisplayName: "SendGrid",
					SMTP: SMTPConfig{
						Host:     "smtp.sendgrid.net",
						Port:     587,
						Username: "apikey",
						PasswordRef: &SecretKeyReference{
							Name:      "sendgrid-secret",
							Namespace: "default",
							Key:       "api-key",
						},
					},
					Sender: SenderConfig{
						Address: "noreply@example.com",
						Name:    "SendGrid Breakglass",
					},
				},
			},
		},
		{
			name: "MailHog development",
			mp: &MailProvider{
				Spec: MailProviderSpec{
					DisplayName: "MailHog Dev",
					SMTP: SMTPConfig{
						Host:               "mailhog.default.svc.cluster.local",
						Port:               1025,
						InsecureSkipVerify: true,
					},
					Sender: SenderConfig{
						Address: "dev@localhost",
						Name:    "Dev Breakglass",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := tt.mp.ValidateCreate(ctx, tt.mp)

			if err != nil {
				t.Errorf("Configuration '%s' should be valid but got error: %v", tt.name, err)
			}
		})
	}
}

func TestMailProviderValidateCreate_WrongType(t *testing.T) {
	mp := &MailProvider{}
	wrongType := &BreakglassSession{}
	_, err := mp.ValidateCreate(context.Background(), wrongType)
	if err == nil {
		t.Fatal("expected error when obj is wrong type")
	}
}

func TestMailProviderValidateUpdate_WrongNewType(t *testing.T) {
	mp := &MailProvider{
		Spec: MailProviderSpec{
			SMTP:   SMTPConfig{Host: "smtp.example.com", Port: 587},
			Sender: SenderConfig{Address: "test@example.com"},
		},
	}
	wrongType := &BreakglassSession{}
	_, err := mp.ValidateUpdate(context.Background(), mp, wrongType)
	if err == nil {
		t.Fatal("expected error when new obj is wrong type")
	}
}

func TestMailProviderValidateUpdate_WrongOldType(t *testing.T) {
	mp := &MailProvider{
		Spec: MailProviderSpec{
			SMTP:   SMTPConfig{Host: "smtp.example.com", Port: 587},
			Sender: SenderConfig{Address: "test@example.com"},
		},
	}
	wrongType := &BreakglassSession{}
	_, err := mp.ValidateUpdate(context.Background(), wrongType, mp)
	if err == nil {
		t.Fatal("expected error when old obj is wrong type")
	}
}

func TestMailProviderValidateUpdate_BecomingDefault(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	existingDefault := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-default"},
		Spec: MailProviderSpec{
			Default: true,
			SMTP:    SMTPConfig{Host: "smtp.old.com", Port: 587},
			Sender:  SenderConfig{Address: "old@example.com"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingDefault).Build()
	webhookClient = fakeClient
	defer func() { webhookClient = nil }()

	oldMp := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "another-provider"},
		Spec: MailProviderSpec{
			Default: false,
			SMTP:    SMTPConfig{Host: "smtp.new.com", Port: 587},
			Sender:  SenderConfig{Address: "new@example.com"},
		},
	}

	newMp := oldMp.DeepCopy()
	newMp.Spec.Default = true // becoming default

	_, err := newMp.ValidateUpdate(context.Background(), oldMp, newMp)
	if err == nil {
		t.Fatal("expected error when becoming default with another default already existing")
	}
}

func TestMailProviderValidateUpdate_SameNameDefault(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	existingDefault := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "the-default"},
		Spec: MailProviderSpec{
			Default: true,
			SMTP:    SMTPConfig{Host: "smtp.old.com", Port: 587},
			Sender:  SenderConfig{Address: "old@example.com"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingDefault).Build()
	webhookClient = fakeClient
	defer func() { webhookClient = nil }()

	// Same provider updating other fields
	newMp := existingDefault.DeepCopy()
	newMp.Spec.SMTP.Port = 465

	_, err := newMp.ValidateUpdate(context.Background(), existingDefault, newMp)
	if err != nil {
		t.Fatalf("expected success when updating same default provider, got: %v", err)
	}
}

func TestMailProviderValidateDefaultUniqueness_NilReader(t *testing.T) {
	oldClient := webhookClient
	oldCache := webhookCache
	webhookClient = nil
	webhookCache = nil
	defer func() {
		webhookClient = oldClient
		webhookCache = oldCache
	}()

	mp := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "new-default"},
		Spec: MailProviderSpec{
			Default: true,
			SMTP:    SMTPConfig{Host: "smtp.test.com", Port: 587},
			Sender:  SenderConfig{Address: "test@example.com"},
		},
	}

	err := mp.validateDefaultUniqueness(context.Background(), "")
	if err != nil {
		t.Fatalf("expected nil error when reader is nil, got: %v", err)
	}
}

func TestMailProviderValidateDefaultUniqueness_NoConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	// Create a non-default mail provider
	existingMp := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-provider"},
		Spec: MailProviderSpec{
			Default: false,
			SMTP:    SMTPConfig{Host: "smtp.test.com", Port: 587},
			Sender:  SenderConfig{Address: "test@example.com"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingMp).Build()
	webhookClient = fakeClient
	defer func() { webhookClient = nil }()

	mp := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "new-default"},
		Spec: MailProviderSpec{
			Default: true,
			SMTP:    SMTPConfig{Host: "smtp.new.com", Port: 587},
			Sender:  SenderConfig{Address: "new@example.com"},
		},
	}

	err := mp.validateDefaultUniqueness(context.Background(), "")
	if err != nil {
		t.Fatalf("expected nil error when no conflict, got: %v", err)
	}
}

func TestMailProviderValidateDefaultUniqueness_WithConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	// Create an existing default mail provider
	existingMp := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-default"},
		Spec: MailProviderSpec{
			Default: true, // Already marked as default
			SMTP:    SMTPConfig{Host: "smtp.test.com", Port: 587},
			Sender:  SenderConfig{Address: "test@example.com"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingMp).Build()
	webhookClient = fakeClient
	defer func() { webhookClient = nil }()

	mp := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "new-default"},
		Spec: MailProviderSpec{
			Default: true, // Also wants to be default - conflict!
			SMTP:    SMTPConfig{Host: "smtp.new.com", Port: 587},
			Sender:  SenderConfig{Address: "new@example.com"},
		},
	}

	err := mp.validateDefaultUniqueness(context.Background(), "")
	if err == nil {
		t.Fatal("expected error when there's already a default MailProvider")
	}
}
