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

package breakglass

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
)

// ============================================================================
// Tests for validateOIDCAuth - edge cases
// ============================================================================

func TestValidateOIDCAuth_NeitherOIDCConfigured(t *testing.T) {
	// Test when authType is OIDC but neither oidcAuth nor oidcFromIdentityProvider is configured
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-missing-config", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType:                 telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth:                 nil,
			OIDCFromIdentityProvider: nil,
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateOIDCAuth(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "neither oidcAuth nor oidcFromIdentityProvider")
}

func TestValidateOIDCAuth_DirectOIDCMissingFields(t *testing.T) {
	tests := []struct {
		name        string
		issuerURL   string
		clientID    string
		server      string
		expectedErr string
	}{
		{
			name:        "missing issuerURL",
			issuerURL:   "",
			clientID:    "client-id",
			server:      "https://api.example.com:6443",
			expectedErr: "issuerURL",
		},
		{
			name:        "missing clientID",
			issuerURL:   "https://idp.example.com",
			clientID:    "",
			server:      "https://api.example.com:6443",
			expectedErr: "clientID",
		},
		{
			name:        "missing server",
			issuerURL:   "https://idp.example.com",
			clientID:    "client-id",
			server:      "",
			expectedErr: "server",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cc := &telekomv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "oidc-" + tc.name, Namespace: "default"},
				Spec: telekomv1alpha1.ClusterConfigSpec{
					AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
					OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
						IssuerURL: tc.issuerURL,
						ClientID:  tc.clientID,
						Server:    tc.server,
					},
				},
			}
			cl := newTestFakeClient(cc)
			fakeRecorder := record.NewFakeRecorder(10)
			checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

			ctx := context.Background()
			_, err := checker.validateDirectOIDCAuth(ctx, cc, checker.Log)

			require.Error(t, err)
			require.Contains(t, err.Error(), "missing required fields")
		})
	}
}

func TestValidateOIDCAuth_DirectOIDCMissingClientSecretRef(t *testing.T) {
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-no-secret-ref", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL:       "https://idp.example.com",
				ClientID:        "client-id",
				Server:          "https://api.example.com:6443",
				ClientSecretRef: nil, // No secret ref
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateDirectOIDCAuth(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "clientSecretRef")
}

func TestValidateOIDCAuth_DirectOIDCClientSecretMissing(t *testing.T) {
	// Secret referenced doesn't exist
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-secret-missing", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: "https://idp.example.com",
				ClientID:  "client-id",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "non-existent-secret",
					Namespace: "default",
				},
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateDirectOIDCAuth(ctx, cc, checker.Log)

	require.Error(t, err)
}

func TestValidateOIDCAuth_DirectOIDCClientSecretMissingKey(t *testing.T) {
	// Secret exists but key is missing
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-secret", Namespace: "default"},
		Data:       map[string][]byte{"wrong-key": []byte("secret-value")},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-secret-no-key", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: "https://idp.example.com",
				ClientID:  "client-id",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "oidc-secret",
					Namespace: "default",
					Key:       "client-secret", // This key doesn't exist
				},
			},
		},
	}
	cl := newTestFakeClient(cc, clientSecret)
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateDirectOIDCAuth(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "missing key")
}

func TestValidateOIDCAuth_DirectOIDCCASecretMissing(t *testing.T) {
	// Client secret exists but CA secret is missing
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-client-secret", Namespace: "default"},
		Data:       map[string][]byte{"client-secret": []byte("secret-value")},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-ca-missing", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: "https://idp.example.com",
				ClientID:  "client-id",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "oidc-client-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
				CASecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "non-existent-ca-secret",
					Namespace: "default",
				},
			},
		},
	}
	cl := newTestFakeClient(cc, clientSecret)
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateDirectOIDCAuth(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "non-existent-ca-secret")
}

// ============================================================================
// Tests for validateOIDCFromIdentityProvider - edge cases
// ============================================================================

func TestValidateOIDCFromIdentityProvider_MissingName(t *testing.T) {
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-idp-no-name", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "", // Missing
				Server: "https://api.example.com:6443",
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateOIDCFromIdentityProvider(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "missing required fields")
}

func TestValidateOIDCFromIdentityProvider_MissingServer(t *testing.T) {
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-idp-no-server", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "my-idp",
				Server: "", // Missing
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateOIDCFromIdentityProvider(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "missing required fields")
}

func TestValidateOIDCFromIdentityProvider_IDPNotFound(t *testing.T) {
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-idp-not-found", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "non-existent-idp",
				Server: "https://api.example.com:6443",
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateOIDCFromIdentityProvider(ctx, cc, checker.Log)

	require.Error(t, err)
}

func TestValidateOIDCFromIdentityProvider_IDPDisabled(t *testing.T) {
	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			Disabled: true, // IDP is disabled
		},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-idp-disabled", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "disabled-idp",
				Server: "https://api.example.com:6443",
			},
		},
	}
	cl := newTestFakeClient(cc, idp)
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateOIDCFromIdentityProvider(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "disabled")
}

func TestValidateOIDCFromIDP_NoClientSecretRef_PlainProvider(t *testing.T) {
	// IDP without Keycloak config and no explicit clientSecretRef
	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "plain-idp"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			Disabled: false,
			Keycloak: nil, // No Keycloak config
		},
	}
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-idp-no-secret", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:            "plain-idp",
				Server:          "https://api.example.com:6443",
				ClientSecretRef: nil, // No explicit secret ref
			},
		},
	}
	cl := newTestFakeClient(cc, idp)
	fakeRecorder := record.NewFakeRecorder(10)
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateOIDCFromIdentityProvider(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "clientSecretRef")
}

// ============================================================================
// Tests for GetClusterConfigByName - additional edge cases
// ============================================================================

func TestGetClusterConfigInNamespace(t *testing.T) {
	ctx := context.Background()

	t.Run("found in specific namespace", func(t *testing.T) {
		cc := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "prod"},
		}
		cli := newTestFakeClient(cc)
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigInNamespace(ctx, "prod", "my-cluster")
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, "my-cluster", got.Name)
		require.Equal(t, "prod", got.Namespace)
	})

	t.Run("not found in wrong namespace", func(t *testing.T) {
		cc := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "prod"},
		}
		cli := newTestFakeClient(cc)
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigInNamespace(ctx, "dev", "my-cluster")
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("not found at all", func(t *testing.T) {
		cli := newTestFakeClient()
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigInNamespace(ctx, "any", "non-existent")
		require.Error(t, err)
		require.Nil(t, got)
	})
}

func TestGetClusterConfigByName_EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("special characters in name", func(t *testing.T) {
		cc := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-with-dash", Namespace: "default"},
		}
		cli := newTestFakeClient(cc)
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigByName(ctx, "cluster-with-dash")
		require.NoError(t, err)
		require.NotNil(t, got)
	})

	t.Run("empty name returns error", func(t *testing.T) {
		cc := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "some-cluster", Namespace: "default"},
		}
		cli := newTestFakeClient(cc)
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigByName(ctx, "")
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("multiple namespaces same name returns error", func(t *testing.T) {
		cc1 := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "shared-name", Namespace: "ns1"},
		}
		cc2 := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "shared-name", Namespace: "ns2"},
		}
		cli := newTestFakeClient(cc1, cc2)
		mgr := NewClusterConfigManager(cli)

		got, err := mgr.GetClusterConfigByName(ctx, "shared-name")
		require.Error(t, err)
		require.Nil(t, got)
		require.Contains(t, err.Error(), "not unique")
	})
}
