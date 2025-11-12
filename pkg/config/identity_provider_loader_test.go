package config

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func TestIdentityProviderLoader_LoadIdentityProvider(t *testing.T) {
	tests := []struct {
		name      string
		idps      []breakglassv1alpha1.IdentityProvider
		secrets   []corev1.Secret
		wantError bool
		check     func(*IdentityProviderConfig) bool
	}{
		{
			name: "primary OIDC provider",
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "primary-oidc",
					},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Primary: true,
						OIDC: breakglassv1alpha1.OIDCConfig{
							Authority: "https://auth.example.com",
							ClientID:  "test-client",
						},
					},
				},
			},
			wantError: false,
			check: func(cfg *IdentityProviderConfig) bool {
				return cfg.Type == "OIDC" &&
					cfg.Authority == "https://auth.example.com" &&
					cfg.ClientID == "test-client" &&
					cfg.Keycloak == nil
			},
		},
		{
			name: "OIDC with Keycloak group sync",
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "oidc-keycloak",
					},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Primary: true,
						OIDC: breakglassv1alpha1.OIDCConfig{
							Authority: "https://auth.example.com",
							ClientID:  "test-client",
						},
						GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
						Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
							BaseURL:  "https://keycloak.example.com",
							Realm:    "master",
							ClientID: "keycloak-admin",
							CacheTTL: "10m",
							ClientSecretRef: breakglassv1alpha1.SecretKeyReference{
								Name: "keycloak-secret",
								Key:  "clientSecret",
							},
						},
					},
				},
			},
			secrets: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "keycloak-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"clientSecret": []byte("super-secret"),
					},
				},
			},
			wantError: false,
			check: func(cfg *IdentityProviderConfig) bool {
				return cfg.Type == "OIDC" &&
					cfg.Authority == "https://auth.example.com" &&
					cfg.Keycloak != nil &&
					cfg.Keycloak.BaseURL == "https://keycloak.example.com" &&
					cfg.Keycloak.ClientSecret == "super-secret"
			},
		},
		{
			name: "disabled provider skipped",
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "disabled-provider",
					},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Primary:  true,
						Disabled: true,
						OIDC: breakglassv1alpha1.OIDCConfig{
							Authority: "https://disabled.example.com",
							ClientID:  "disabled",
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "fallback-provider",
					},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Primary: false,
						OIDC: breakglassv1alpha1.OIDCConfig{
							Authority: "https://fallback.example.com",
							ClientID:  "fallback",
						},
					},
				},
			},
			wantError: false,
			check: func(cfg *IdentityProviderConfig) bool {
				// Should load fallback-provider since disabled-provider is disabled
				return cfg.Authority == "https://fallback.example.com"
			},
		},
		{
			name:      "no providers error",
			idps:      []breakglassv1alpha1.IdentityProvider{},
			wantError: true,
		},
		{
			name: "all providers disabled error",
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "disabled1",
					},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Disabled: true,
						OIDC: breakglassv1alpha1.OIDCConfig{
							Authority: "https://auth.example.com",
							ClientID:  "test",
						},
					},
				},
			},
			wantError: true,
		},
		{
			name: "secret not found error",
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "broken-keycloak",
					},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Primary: true,
						OIDC: breakglassv1alpha1.OIDCConfig{
							Authority: "https://auth.example.com",
							ClientID:  "test",
						},
						GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
						Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
							BaseURL:  "https://keycloak.example.com",
							Realm:    "master",
							ClientID: "admin",
							ClientSecretRef: breakglassv1alpha1.SecretKeyReference{
								Name: "missing-secret",
								Key:  "clientSecret",
							},
						},
					},
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build fake client with resources
			builder := fake.NewClientBuilder().WithScheme(Scheme)

			// Add objects
			for _, idp := range tt.idps {
				idpCopy := idp
				builder = builder.WithObjects(&idpCopy)
			}
			for _, secret := range tt.secrets {
				secretCopy := secret
				builder = builder.WithObjects(&secretCopy)
			}

			fakeClient := builder.Build()

			loader := NewIdentityProviderLoader(fakeClient)
			cfg, err := loader.LoadIdentityProvider(context.Background())

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("expected config, got nil")
			}

			if !tt.check(cfg) {
				t.Errorf("check failed for config: %+v", cfg)
			}
		})
	}
}

func TestIdentityProviderLoader_LoadIdentityProviderByName(t *testing.T) {
	tests := []struct {
		name      string
		idps      []breakglassv1alpha1.IdentityProvider
		loadName  string
		wantError bool
		check     func(*IdentityProviderConfig) bool
	}{
		{
			name: "load specific provider",
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "specific-provider",
					},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						OIDC: breakglassv1alpha1.OIDCConfig{
							Authority: "https://specific.example.com",
							ClientID:  "specific",
						},
					},
				},
			},
			loadName:  "specific-provider",
			wantError: false,
			check: func(cfg *IdentityProviderConfig) bool {
				return cfg.Authority == "https://specific.example.com" &&
					cfg.ClientID == "specific"
			},
		},
		{
			name:      "provider not found",
			idps:      []breakglassv1alpha1.IdentityProvider{},
			loadName:  "nonexistent",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(Scheme)

			for _, idp := range tt.idps {
				idpCopy := idp
				builder = builder.WithObjects(&idpCopy)
			}

			fakeClient := builder.Build()
			loader := NewIdentityProviderLoader(fakeClient)

			cfg, err := loader.LoadIdentityProviderByName(context.Background(), tt.loadName)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !tt.check(cfg) {
				t.Errorf("check failed for config: %+v", cfg)
			}
		})
	}
}

// TestIdentityProviderLoader_ValidateIdentityProviderExists tests startup validation
func TestIdentityProviderLoader_ValidateIdentityProviderExists(t *testing.T) {
	tests := []struct {
		name      string
		idps      []breakglassv1alpha1.IdentityProvider
		wantError bool
		errMsg    string
	}{
		{
			name: "valid - primary provider exists",
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "primary"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Primary: true,
						OIDC: breakglassv1alpha1.OIDCConfig{
							Authority: "https://auth.example.com",
							ClientID:  "test",
						},
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid - fallback provider exists and enabled",
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "fallback"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						OIDC: breakglassv1alpha1.OIDCConfig{
							Authority: "https://auth.example.com",
							ClientID:  "test",
						},
					},
				},
			},
			wantError: false,
		},
		{
			name:      "error - no providers",
			idps:      []breakglassv1alpha1.IdentityProvider{},
			wantError: true,
			errMsg:    "no IdentityProvider resources found; IdentityProvider is MANDATORY",
		},
		{
			name: "error - all providers disabled",
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "disabled1"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Disabled: true,
						OIDC: breakglassv1alpha1.OIDCConfig{
							Authority: "https://auth.example.com",
							ClientID:  "test",
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "disabled2"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Disabled: true,
						OIDC: breakglassv1alpha1.OIDCConfig{
							Authority: "https://auth2.example.com",
							ClientID:  "test2",
						},
					},
				},
			},
			wantError: true,
			errMsg:    "all IdentityProvider resources are disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(Scheme)
			for _, idp := range tt.idps {
				idpCopy := idp
				builder = builder.WithObjects(&idpCopy)
			}

			fakeClient := builder.Build()
			loader := NewIdentityProviderLoader(fakeClient)

			err := loader.ValidateIdentityProviderExists(context.Background())

			if tt.wantError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("error message doesn't match.\nExpected substring: %s\nGot: %s", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestIdentityProviderLoader_CrossNamespaceSecrets tests loading secrets from different namespaces
func TestIdentityProviderLoader_CrossNamespaceSecrets(t *testing.T) {
	tests := []struct {
		name       string
		secretNs   string
		wantError  bool
		wantSecret string
	}{
		{
			name:       "secret in same namespace (default)",
			secretNs:   "default",
			wantError:  false,
			wantSecret: "default-secret-value",
		},
		{
			name:       "secret in different namespace (cross-namespace)",
			secretNs:   "secrets-namespace",
			wantError:  false,
			wantSecret: "cross-namespace-secret",
		},
		{
			name:      "secret not found in specified namespace",
			secretNs:  "nonexistent-namespace",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create secrets in different namespaces
			secrets := []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kc-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"secret": []byte("default-secret-value"),
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kc-secret",
						Namespace: "secrets-namespace",
					},
					Data: map[string][]byte{
						"secret": []byte("cross-namespace-secret"),
					},
				},
			}

			builder := fake.NewClientBuilder().WithScheme(Scheme)

			// Add IdentityProvider with cross-namespace secret reference
			idp := breakglassv1alpha1.IdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "test-idp"},
				Spec: breakglassv1alpha1.IdentityProviderSpec{
					Primary: true,
					OIDC: breakglassv1alpha1.OIDCConfig{
						Authority: "https://auth.example.com",
						ClientID:  "test",
					},
					GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
					Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
						BaseURL:  "https://keycloak.example.com",
						Realm:    "master",
						ClientID: "admin",
						ClientSecretRef: breakglassv1alpha1.SecretKeyReference{
							Name:      "kc-secret",
							Namespace: tt.secretNs,
							Key:       "secret",
						},
					},
				},
			}
			builder = builder.WithObjects(&idp)

			// Add secrets
			for i := range secrets {
				builder = builder.WithObjects(&secrets[i])
			}

			fakeClient := builder.Build()
			loader := NewIdentityProviderLoader(fakeClient)

			cfg, err := loader.LoadIdentityProvider(context.Background())

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("expected config, got nil")
			}

			if cfg.Keycloak == nil {
				t.Fatal("expected Keycloak config to be set")
			}

			if cfg.Keycloak.ClientSecret != tt.wantSecret {
				t.Errorf("secret mismatch.\nExpected: %s\nGot: %s", tt.wantSecret, cfg.Keycloak.ClientSecret)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
