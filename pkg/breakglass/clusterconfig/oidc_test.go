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

package clusterconfig

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// Tests for validateOIDCAuth - edge cases
// ============================================================================

func TestValidateOIDCAuth_NeitherOIDCConfigured(t *testing.T) {
	// Test when authType is OIDC but neither oidcAuth nor oidcFromIdentityProvider is configured
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-missing-config", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			AuthType:                 breakglassv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth:                 nil,
			OIDCFromIdentityProvider: nil,
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := fakeEventRecorder{}
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
			cc := &breakglassv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "oidc-" + tc.name, Namespace: "default"},
				Spec: breakglassv1alpha1.ClusterConfigSpec{
					AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
					OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
						IssuerURL: tc.issuerURL,
						ClientID:  tc.clientID,
						Server:    tc.server,
					},
				},
			}
			cl := newTestFakeClient(cc)
			fakeRecorder := fakeEventRecorder{}
			checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

			ctx := context.Background()
			_, err := checker.validateDirectOIDCAuth(ctx, cc, checker.Log)

			require.Error(t, err)
			require.Contains(t, err.Error(), "missing required fields")
		})
	}
}

func TestValidateOIDCAuth_DirectOIDCMissingClientSecretRef(t *testing.T) {
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-no-secret-ref", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
				IssuerURL:       "https://idp.example.com",
				ClientID:        "client-id",
				Server:          "https://api.example.com:6443",
				ClientSecretRef: nil, // No secret ref
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateDirectOIDCAuth(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "clientSecretRef")
}

func TestValidateOIDCAuth_DirectOIDCClientSecretMissing(t *testing.T) {
	// Secret referenced doesn't exist
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-secret-missing", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
				IssuerURL: "https://idp.example.com",
				ClientID:  "client-id",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &breakglassv1alpha1.SecretKeyReference{
					Name:      "non-existent-secret",
					Namespace: "default",
				},
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := fakeEventRecorder{}
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
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-secret-no-key", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
				IssuerURL: "https://idp.example.com",
				ClientID:  "client-id",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &breakglassv1alpha1.SecretKeyReference{
					Name:      "oidc-secret",
					Namespace: "default",
					Key:       "client-secret", // This key doesn't exist
				},
			},
		},
	}
	cl := newTestFakeClient(cc, clientSecret)
	fakeRecorder := fakeEventRecorder{}
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
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-ca-missing", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
				IssuerURL: "https://idp.example.com",
				ClientID:  "client-id",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &breakglassv1alpha1.SecretKeyReference{
					Name:      "oidc-client-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
				CASecretRef: &breakglassv1alpha1.SecretKeyReference{
					Name:      "non-existent-ca-secret",
					Namespace: "default",
				},
			},
		},
	}
	cl := newTestFakeClient(cc, clientSecret)
	fakeRecorder := fakeEventRecorder{}
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
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-idp-no-name", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "", // Missing
				Server: "https://api.example.com:6443",
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateOIDCFromIdentityProvider(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "missing required fields")
}

func TestValidateOIDCFromIdentityProvider_MissingServer(t *testing.T) {
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-idp-no-server", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "my-idp",
				Server: "", // Missing
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateOIDCFromIdentityProvider(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "missing required fields")
}

func TestValidateOIDCFromIdentityProvider_IDPNotFound(t *testing.T) {
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-idp-not-found", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "non-existent-idp",
				Server: "https://api.example.com:6443",
			},
		},
	}
	cl := newTestFakeClient(cc)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateOIDCFromIdentityProvider(ctx, cc, checker.Log)

	require.Error(t, err)
}

func TestValidateOIDCFromIdentityProvider_IDPDisabled(t *testing.T) {
	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			Disabled: true, // IDP is disabled
		},
	}
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-idp-disabled", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "disabled-idp",
				Server: "https://api.example.com:6443",
			},
		},
	}
	cl := newTestFakeClient(cc, idp)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateOIDCFromIdentityProvider(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "disabled")
}

func TestValidateOIDCFromIDP_NoClientSecretRef_PlainProvider(t *testing.T) {
	// IDP without Keycloak config and no explicit clientSecretRef
	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "plain-idp"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			Disabled: false,
			Keycloak: nil, // No Keycloak config
		},
	}
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-idp-no-secret", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{
				Name:            "plain-idp",
				Server:          "https://api.example.com:6443",
				ClientSecretRef: nil, // No explicit secret ref
			},
		},
	}
	cl := newTestFakeClient(cc, idp)
	fakeRecorder := fakeEventRecorder{}
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: cl, Recorder: fakeRecorder, Interval: time.Minute}

	ctx := context.Background()
	_, err := checker.validateOIDCFromIdentityProvider(ctx, cc, checker.Log)

	require.Error(t, err)
	require.Contains(t, err.Error(), "clientSecretRef")
}
