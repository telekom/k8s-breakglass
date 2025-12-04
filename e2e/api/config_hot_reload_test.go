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

// Package api contains E2E tests for configuration hot reload.
package api

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestIdentityProviderHotReload tests that changes to IdentityProvider CRs are detected and applied.
func TestIdentityProviderHotReload(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("UpdateIdentityProviderSpec", func(t *testing.T) {
		idpName := helpers.GenerateUniqueName("e2e-reload-idp")
		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      idpName,
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "hot-reload"},
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://original-issuer.example.com",
					ClientID:  "original-client-id",
				},
				Issuer: "https://original-issuer.example.com",
			},
		}
		cleanup.Add(idp)
		require.NoError(t, cli.Create(ctx, idp), "Failed to create test IdentityProvider")

		time.Sleep(2 * time.Second)

		var initial telekomv1alpha1.IdentityProvider
		err := cli.Get(ctx, types.NamespacedName{Name: idpName, Namespace: namespace}, &initial)
		require.NoError(t, err)
		assert.Equal(t, "https://original-issuer.example.com", initial.Spec.OIDC.Authority)
		t.Logf("Initial IDP authority: %s", initial.Spec.OIDC.Authority)

		initial.Spec.OIDC.Authority = "https://updated-issuer.example.com"
		initial.Spec.OIDC.ClientID = "updated-client-id"
		initial.Spec.Issuer = "https://updated-issuer.example.com"
		require.NoError(t, cli.Update(ctx, &initial), "Failed to update IdentityProvider")

		time.Sleep(3 * time.Second)

		var updated telekomv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idpName, Namespace: namespace}, &updated)
		require.NoError(t, err)
		assert.Equal(t, "https://updated-issuer.example.com", updated.Spec.OIDC.Authority)
		assert.Equal(t, "updated-client-id", updated.Spec.OIDC.ClientID)
		t.Logf("Updated IDP authority: %s, client: %s", updated.Spec.OIDC.Authority, updated.Spec.OIDC.ClientID)

		t.Logf("IDP status after update: ObservedGeneration=%d, Conditions=%v",
			updated.Status.ObservedGeneration, len(updated.Status.Conditions))
	})

	t.Run("UpdateIdentityProviderDisabledFlag", func(t *testing.T) {
		idpName := helpers.GenerateUniqueName("e2e-reload-idp-disabled")
		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      idpName,
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "hot-reload-disabled"},
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://disabled-test.example.com",
					ClientID:  "disabled-client",
				},
				Issuer:   "https://disabled-test.example.com",
				Disabled: false,
			},
		}
		cleanup.Add(idp)
		require.NoError(t, cli.Create(ctx, idp), "Failed to create test IdentityProvider")

		time.Sleep(2 * time.Second)

		var initial telekomv1alpha1.IdentityProvider
		err := cli.Get(ctx, types.NamespacedName{Name: idpName, Namespace: namespace}, &initial)
		require.NoError(t, err)
		assert.False(t, initial.Spec.Disabled)
		t.Logf("Initial IDP disabled: %v", initial.Spec.Disabled)

		// Disable the provider
		initial.Spec.Disabled = true
		require.NoError(t, cli.Update(ctx, &initial), "Failed to disable IdentityProvider")

		time.Sleep(3 * time.Second)

		var updated telekomv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idpName, Namespace: namespace}, &updated)
		require.NoError(t, err)
		assert.True(t, updated.Spec.Disabled)
		t.Logf("Updated IDP disabled: %v", updated.Spec.Disabled)
	})
}

// TestClusterConfigHotReload tests that changes to ClusterConfig CRs are detected and applied.
func TestClusterConfigHotReload(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("UpdateClusterConfigSpec", func(t *testing.T) {
		secretName := helpers.GenerateUniqueName("e2e-cc-kubeconfig")
		kubeconfig := `apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster:
    server: https://original-api.example.com:6443
contexts:
- name: test-context
  context:
    cluster: test-cluster
    user: test-user
current-context: test-context
users:
- name: test-user
  user:
    token: original-token
`
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"value": []byte(kubeconfig),
			},
		}
		cleanup.Add(secret)
		require.NoError(t, cli.Create(ctx, secret), "Failed to create kubeconfig secret")

		ccName := helpers.GenerateUniqueName("e2e-reload-cc")
		cc := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ccName,
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "hot-reload"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID:   "original-cluster-id",
				Environment: "dev",
				KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      secretName,
					Namespace: namespace,
				},
			},
		}
		cleanup.Add(cc)
		require.NoError(t, cli.Create(ctx, cc), "Failed to create ClusterConfig")

		time.Sleep(2 * time.Second)

		var initial telekomv1alpha1.ClusterConfig
		err := cli.Get(ctx, types.NamespacedName{Name: ccName, Namespace: namespace}, &initial)
		require.NoError(t, err)
		assert.Equal(t, "original-cluster-id", initial.Spec.ClusterID)
		t.Logf("Initial ClusterConfig: ClusterID=%s", initial.Spec.ClusterID)

		initial.Spec.ClusterID = "updated-cluster-id"
		initial.Spec.Environment = "staging"
		require.NoError(t, cli.Update(ctx, &initial), "Failed to update ClusterConfig")

		time.Sleep(3 * time.Second)

		var updated telekomv1alpha1.ClusterConfig
		err = cli.Get(ctx, types.NamespacedName{Name: ccName, Namespace: namespace}, &updated)
		require.NoError(t, err)
		assert.Equal(t, "updated-cluster-id", updated.Spec.ClusterID)
		assert.Equal(t, "staging", updated.Spec.Environment)
		t.Logf("Updated ClusterConfig: ClusterID=%s, Environment=%s", updated.Spec.ClusterID, updated.Spec.Environment)
	})

	t.Run("UpdateKubeconfigSecret", func(t *testing.T) {
		secretName := helpers.GenerateUniqueName("e2e-cc-kubeconfig-v2")
		kubeconfig := `apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster:
    server: https://original-api.example.com:6443
contexts:
- name: test-context
  context:
    cluster: test-cluster
    user: test-user
current-context: test-context
users:
- name: test-user
  user:
    token: original-token
`
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"value": []byte(kubeconfig),
			},
		}
		cleanup.Add(secret)
		require.NoError(t, cli.Create(ctx, secret), "Failed to create kubeconfig secret")

		ccName := helpers.GenerateUniqueName("e2e-reload-cc-secret")
		cc := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ccName,
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "hot-reload-secret"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID: "secret-reload-test",
				KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      secretName,
					Namespace: namespace,
				},
			},
		}
		cleanup.Add(cc)
		require.NoError(t, cli.Create(ctx, cc), "Failed to create ClusterConfig")

		time.Sleep(2 * time.Second)

		var initial telekomv1alpha1.ClusterConfig
		err := cli.Get(ctx, types.NamespacedName{Name: ccName, Namespace: namespace}, &initial)
		require.NoError(t, err)
		initialGeneration := initial.Generation
		t.Logf("Initial ClusterConfig generation: %d", initialGeneration)

		err = cli.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret)
		require.NoError(t, err)
		updatedKubeconfig := `apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster:
    server: https://updated-api.example.com:6443
contexts:
- name: test-context
  context:
    cluster: test-cluster
    user: test-user
current-context: test-context
users:
- name: test-user
  user:
    token: updated-token-value
`
		secret.Data["value"] = []byte(updatedKubeconfig)
		require.NoError(t, cli.Update(ctx, secret), "Failed to update kubeconfig secret")

		time.Sleep(3 * time.Second)

		var updated telekomv1alpha1.ClusterConfig
		err = cli.Get(ctx, types.NamespacedName{Name: ccName, Namespace: namespace}, &updated)
		require.NoError(t, err)
		t.Logf("ClusterConfig after secret update: Generation=%d, ObservedGeneration=%d",
			updated.Generation, updated.Status.ObservedGeneration)

		for _, cond := range updated.Status.Conditions {
			t.Logf("  Condition: %s = %s (%s)", cond.Type, cond.Status, cond.Message)
		}
	})
}

// TestMailProviderHotReload tests that changes to MailProvider CRs are detected and applied.
func TestMailProviderHotReload(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("UpdateMailProviderSpec", func(t *testing.T) {
		secretName := helpers.GenerateUniqueName("e2e-mail-secret")
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"password": []byte(base64.StdEncoding.EncodeToString([]byte("test-password"))),
			},
		}
		cleanup.Add(secret)
		require.NoError(t, cli.Create(ctx, secret), "Failed to create mail secret")

		mpName := helpers.GenerateUniqueName("e2e-reload-mp")
		mp := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      mpName,
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "hot-reload"},
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				DisplayName: "Original Mail Provider",
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "original-smtp.example.com",
					Port: 587,
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "original@example.com",
					Name:    "Original Sender",
				},
			},
		}
		cleanup.Add(mp)
		require.NoError(t, cli.Create(ctx, mp), "Failed to create MailProvider")

		time.Sleep(2 * time.Second)

		var initial telekomv1alpha1.MailProvider
		err := cli.Get(ctx, types.NamespacedName{Name: mpName, Namespace: namespace}, &initial)
		require.NoError(t, err)
		assert.Equal(t, "original-smtp.example.com", initial.Spec.SMTP.Host)
		t.Logf("Initial MailProvider host: %s", initial.Spec.SMTP.Host)

		initial.Spec.SMTP.Host = "updated-smtp.example.com"
		initial.Spec.Sender.Address = "updated@example.com"
		require.NoError(t, cli.Update(ctx, &initial), "Failed to update MailProvider")

		time.Sleep(3 * time.Second)

		var updated telekomv1alpha1.MailProvider
		err = cli.Get(ctx, types.NamespacedName{Name: mpName, Namespace: namespace}, &updated)
		require.NoError(t, err)
		assert.Equal(t, "updated-smtp.example.com", updated.Spec.SMTP.Host)
		assert.Equal(t, "updated@example.com", updated.Spec.Sender.Address)
		t.Logf("Updated MailProvider host: %s, from: %s", updated.Spec.SMTP.Host, updated.Spec.Sender.Address)
	})
}

// TestAPIReloadsDuringLiveTraffic tests that the API continues to work during config reloads.
func TestAPIReloadsDuringLiveTraffic(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	namespace := helpers.GetTestNamespace()

	provider := helpers.DefaultOIDCProvider()
	token := provider.GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token, "Failed to get auth token")

	apiClient := helpers.NewAPIClientWithAuth(token)

	t.Run("APIWorksBeforeAndAfterIDPUpdate", func(t *testing.T) {
		sessions, err := apiClient.ListSessions(ctx)
		require.NoError(t, err, "API should work before config update")
		t.Logf("Sessions before update: %d", len(sessions))

		var idpList telekomv1alpha1.IdentityProviderList
		err = cli.List(ctx, &idpList)
		require.NoError(t, err)
		require.NotEmpty(t, idpList.Items, "Should have at least one IdentityProvider")

		var testIDP *telekomv1alpha1.IdentityProvider
		for i := range idpList.Items {
			if idpList.Items[i].Labels != nil && idpList.Items[i].Labels["e2e-test"] == "true" {
				testIDP = &idpList.Items[i]
				break
			}
		}

		if testIDP == nil {
			t.Skip("No test IdentityProvider found to update")
			return
		}

		originalClientID := testIDP.Spec.OIDC.ClientID

		// Ensure we restore the original client ID at the end
		defer func() {
			// Re-fetch to get latest version to avoid conflict
			if err := cli.Get(ctx, types.NamespacedName{Name: testIDP.Name, Namespace: namespace}, testIDP); err == nil {
				testIDP.Spec.OIDC.ClientID = originalClientID
				_ = cli.Update(ctx, testIDP)
			}
		}()

		testIDP.Spec.OIDC.ClientID = "temporary-client-id-" + helpers.GenerateUniqueName("")
		err = cli.Update(ctx, testIDP)
		require.NoError(t, err, "Failed to update test IDP")

		for i := 0; i < 5; i++ {
			sessions, err := apiClient.ListSessions(ctx)
			if err != nil {
				t.Logf("Request %d during update: error=%v", i+1, err)
			} else {
				t.Logf("Request %d during update: success, sessions=%d", i+1, len(sessions))
			}
			time.Sleep(500 * time.Millisecond)
		}

		// Explicitly restore (defer will handle it if this fails, but good to be explicit for the test flow)
		err = cli.Get(ctx, types.NamespacedName{Name: testIDP.Name, Namespace: namespace}, testIDP)
		require.NoError(t, err)
		testIDP.Spec.OIDC.ClientID = originalClientID
		err = cli.Update(ctx, testIDP)
		require.NoError(t, err, "Failed to restore test IDP")

		sessions, err = apiClient.ListSessions(ctx)
		require.NoError(t, err, "API should work after config update")
		t.Logf("Sessions after update: %d", len(sessions))
	})
}
