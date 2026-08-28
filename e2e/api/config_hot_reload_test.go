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

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestIdentityProviderHotReload tests that changes to IdentityProvider CRs are detected and applied.
func TestIdentityProviderHotReload(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("UpdateIdentityProviderSpec", func(t *testing.T) {
		idpName := helpers.GenerateUniqueName("e2e-reload-idp")
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      idpName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("hot-reload"),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority:        "https://original-issuer.example.com",
					ClientID:         "original-client-id",
					ExpectedAudience: "original-client-id",
				},
				Issuer: "https://original-issuer.example.com",
			},
		}
		cleanup.Add(idp)
		require.NoError(t, cli.Create(ctx, idp), "Failed to create test IdentityProvider")

		time.Sleep(helpers.CachePropagationDelay)

		var initial breakglassv1alpha1.IdentityProvider
		err := cli.Get(ctx, types.NamespacedName{Name: idpName, Namespace: namespace}, &initial)
		require.NoError(t, err)
		assert.Equal(t, "https://original-issuer.example.com", initial.Spec.OIDC.Authority)
		t.Logf("Initial IDP authority: %s", initial.Spec.OIDC.Authority)

		// Use retry to handle conflicts with the IdentityProviderReconciler
		err = helpers.UpdateWithRetry(ctx, cli, &initial, func(idp *breakglassv1alpha1.IdentityProvider) error {
			idp.Spec.OIDC.Authority = "https://updated-issuer.example.com"
			idp.Spec.OIDC.ClientID = "updated-client-id"
			idp.Spec.OIDC.ExpectedAudience = "updated-client-id"
			idp.Spec.Issuer = "https://updated-issuer.example.com"
			return nil
		})
		require.NoError(t, err, "Failed to update IdentityProvider")

		time.Sleep(helpers.CachePropagationDelay)

		var updated breakglassv1alpha1.IdentityProvider
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
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      idpName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("hot-reload-disabled"),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority:        "https://disabled-test.example.com",
					ClientID:         "disabled-client",
					ExpectedAudience: "disabled-client",
				},
				Issuer:   "https://disabled-test.example.com",
				Disabled: false,
			},
		}
		cleanup.Add(idp)
		require.NoError(t, cli.Create(ctx, idp), "Failed to create test IdentityProvider")

		time.Sleep(helpers.CachePropagationDelay)

		var initial breakglassv1alpha1.IdentityProvider
		err := cli.Get(ctx, types.NamespacedName{Name: idpName, Namespace: namespace}, &initial)
		require.NoError(t, err)
		assert.False(t, initial.Spec.Disabled)
		t.Logf("Initial IDP disabled: %v", initial.Spec.Disabled)

		// Disable the provider using retry to handle conflicts with reconciler
		err = helpers.UpdateWithRetry(ctx, cli, &initial, func(idp *breakglassv1alpha1.IdentityProvider) error {
			idp.Spec.Disabled = true
			return nil
		})
		require.NoError(t, err, "Failed to disable IdentityProvider")

		time.Sleep(helpers.CachePropagationDelay)

		var updated breakglassv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idpName, Namespace: namespace}, &updated)
		require.NoError(t, err)
		assert.True(t, updated.Spec.Disabled)
		t.Logf("Updated IDP disabled: %v", updated.Spec.Disabled)
	})
}

// TestClusterConfigHotReload tests that changes to ClusterConfig CRs are detected and applied.
func TestClusterConfigHotReload(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
				Labels:    helpers.E2ETestLabels(),
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"value": []byte(kubeconfig),
			},
		}
		cleanup.Add(secret)
		require.NoError(t, cli.Create(ctx, secret), "Failed to create kubeconfig secret")

		ccName := helpers.GenerateUniqueName("e2e-reload-cc")
		cc := helpers.NewClusterConfigBuilder(ccName, namespace).
			WithClusterID("original-cluster-id").
			WithEnvironment("dev").
			WithLabels(helpers.E2ELabelsWithFeature("hot-reload")).
			WithKubeconfigSecret(secretName, "").
			Build()
		cleanup.Add(cc)
		require.NoError(t, cli.Create(ctx, cc), "Failed to create ClusterConfig")

		time.Sleep(helpers.CachePropagationDelay)

		var initial breakglassv1alpha1.ClusterConfig
		err := cli.Get(ctx, types.NamespacedName{Name: ccName, Namespace: namespace}, &initial)
		require.NoError(t, err)
		assert.Equal(t, "original-cluster-id", initial.Spec.ClusterID)
		t.Logf("Initial ClusterConfig: ClusterID=%s", initial.Spec.ClusterID)

		// Use retry to handle conflicts with the ClusterConfigReconciler
		err = helpers.UpdateWithRetry(ctx, cli, &initial, func(cc *breakglassv1alpha1.ClusterConfig) error {
			cc.Spec.ClusterID = "updated-cluster-id"
			cc.Spec.Environment = "staging"
			return nil
		})
		require.NoError(t, err, "Failed to update ClusterConfig")

		time.Sleep(helpers.CachePropagationDelay)

		var updated breakglassv1alpha1.ClusterConfig
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
				Labels:    helpers.E2ETestLabels(),
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"value": []byte(kubeconfig),
			},
		}
		cleanup.Add(secret)
		require.NoError(t, cli.Create(ctx, secret), "Failed to create kubeconfig secret")

		ccName := helpers.GenerateUniqueName("e2e-reload-cc-secret")
		cc := helpers.NewClusterConfigBuilder(ccName, namespace).
			WithClusterID("secret-reload-test").
			WithLabels(helpers.E2ELabelsWithFeature("hot-reload-secret")).
			WithKubeconfigSecret(secretName, "").
			Build()
		cleanup.Add(cc)
		require.NoError(t, cli.Create(ctx, cc), "Failed to create ClusterConfig")

		time.Sleep(helpers.CachePropagationDelay)

		var initial breakglassv1alpha1.ClusterConfig
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

		time.Sleep(helpers.CachePropagationDelay)

		var updated breakglassv1alpha1.ClusterConfig
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
				Labels:    helpers.E2ETestLabels(),
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"password": []byte(base64.StdEncoding.EncodeToString([]byte("test-password"))),
			},
		}
		cleanup.Add(secret)
		require.NoError(t, cli.Create(ctx, secret), "Failed to create mail secret")

		mpName := helpers.GenerateUniqueName("e2e-reload-mp")
		mp := &breakglassv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      mpName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("hot-reload"),
			},
			Spec: breakglassv1alpha1.MailProviderSpec{
				DisplayName: "Original Mail Provider",
				SMTP: breakglassv1alpha1.SMTPConfig{
					Host: "original-smtp.example.com",
					Port: 587,
				},
				Sender: breakglassv1alpha1.SenderConfig{
					Address: "original@example.com",
					Name:    "Original Sender",
				},
			},
		}
		cleanup.Add(mp)
		require.NoError(t, cli.Create(ctx, mp), "Failed to create MailProvider")

		time.Sleep(helpers.CachePropagationDelay)

		var initial breakglassv1alpha1.MailProvider
		err := cli.Get(ctx, types.NamespacedName{Name: mpName, Namespace: namespace}, &initial)
		require.NoError(t, err)
		assert.Equal(t, "original-smtp.example.com", initial.Spec.SMTP.Host)
		t.Logf("Initial MailProvider host: %s", initial.Spec.SMTP.Host)

		// Use retry to handle conflicts with the MailProviderReconciler
		err = helpers.UpdateWithRetry(ctx, cli, &initial, func(mp *breakglassv1alpha1.MailProvider) error {
			mp.Spec.SMTP.Host = "updated-smtp.example.com"
			mp.Spec.Sender.Address = "updated@example.com"
			return nil
		})
		require.NoError(t, err, "Failed to update MailProvider")

		time.Sleep(helpers.CachePropagationDelay)

		var updated breakglassv1alpha1.MailProvider
		err = cli.Get(ctx, types.NamespacedName{Name: mpName, Namespace: namespace}, &updated)
		require.NoError(t, err)
		assert.Equal(t, "updated-smtp.example.com", updated.Spec.SMTP.Host)
		assert.Equal(t, "updated@example.com", updated.Spec.Sender.Address)
		t.Logf("Updated MailProvider host: %s, from: %s", updated.Spec.SMTP.Host, updated.Spec.Sender.Address)
	})
}

// TestAPIReloadsDuringLiveTraffic tests that the API continues to work during config reloads.
func TestAPIReloadsDuringLiveTraffic(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)

	provider := helpers.DefaultOIDCProvider()
	token := provider.GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token, "Failed to get auth token")

	apiClient := helpers.NewAPIClientWithAuth(token)

	t.Run("APIWorksBeforeAndAfterIDPUpdate", func(t *testing.T) {
		sessions, err := apiClient.ListSessions(ctx)
		require.NoError(t, err, "API should work before config update")
		t.Logf("Sessions before update: %d", len(sessions))

		var idpList breakglassv1alpha1.IdentityProviderList
		err = cli.List(ctx, &idpList)
		require.NoError(t, err)
		require.NotEmpty(t, idpList.Items, "Should have at least one IdentityProvider")

		var testIDP *breakglassv1alpha1.IdentityProvider
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

		originalDisplayName := testIDP.Spec.DisplayName

		// Updating clientID or expectedAudience changes the authentication contract
		// for the token that drives this test. That cannot prove hot reload under
		// live traffic: it deliberately makes the in-flight token invalid and then
		// leaks 401s into the rest of this serial E2E package. DisplayName is still
		// part of the provider spec, so it causes the real provider reconciler and
		// its runtime reload path to run without changing the token contract.
		// Always restore it, including if an assertion below fails, so this test
		// cannot contaminate subsequent authenticated tests.
		restored := false
		t.Cleanup(func() {
			if restored {
				return
			}

			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
			defer cleanupCancel()
			restoreIDP := &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: testIDP.Name}}
			if err := helpers.UpdateWithRetry(cleanupCtx, cli, restoreIDP, func(idp *breakglassv1alpha1.IdentityProvider) error {
				idp.Spec.DisplayName = originalDisplayName
				return nil
			}); err != nil {
				t.Errorf("failed to restore IdentityProvider display name: %v", err)
			}
		})

		err = helpers.UpdateWithRetry(ctx, cli, testIDP, func(idp *breakglassv1alpha1.IdentityProvider) error {
			idp.Spec.DisplayName = "E2E reload " + helpers.GenerateUniqueName("")
			return nil
		})
		require.NoError(t, err, "Failed to update test IDP")

		var updatedIDP breakglassv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: testIDP.Name}, &updatedIDP)
		require.NoError(t, err, "Failed to read updated test IDP")
		targetGeneration := updatedIDP.Generation

		for i := 0; i < 5; i++ {
			sessions, err := apiClient.ListSessions(ctx)
			require.NoErrorf(t, err, "request %d during IdentityProvider reload must retain valid authentication", i+1)
			t.Logf("Request %d during update: success, sessions=%d", i+1, len(sessions))
			time.Sleep(500 * time.Millisecond)
		}

		err = helpers.WaitForCondition(ctx, func() (bool, error) {
			var reloaded breakglassv1alpha1.IdentityProvider
			if err := cli.Get(ctx, types.NamespacedName{Name: testIDP.Name}, &reloaded); err != nil {
				// The API cache/server can transiently reject a read while the
				// controller is reconciling. Treat that as not-ready and let the
				// bounded poll retry; WaitForCondition still observes ctx
				// cancellation and terminates the poll promptly.
				return false, nil
			}
			if reloaded.Status.ObservedGeneration < targetGeneration {
				return false, nil
			}
			for _, condition := range reloaded.Status.Conditions {
				if condition.Type == string(breakglassv1alpha1.IdentityProviderConditionReady) &&
					condition.Status == metav1.ConditionTrue &&
					condition.ObservedGeneration >= targetGeneration {
					return true, nil
				}
			}
			return false, nil
		}, helpers.WaitForStateTimeout, 200*time.Millisecond)
		require.NoError(t, err, "IdentityProvider update was not reconciled after live API traffic")

		// Explicitly restore so the succeeding request verifies the post-reload
		// state as well. t.Cleanup remains the fail-safe for an earlier failure.
		err = helpers.UpdateWithRetry(ctx, cli, testIDP, func(idp *breakglassv1alpha1.IdentityProvider) error {
			idp.Spec.DisplayName = originalDisplayName
			return nil
		})
		require.NoError(t, err, "Failed to restore test IDP")
		restored = true

		sessions, err = apiClient.ListSessions(ctx)
		require.NoError(t, err, "API should work after config update")
		t.Logf("Sessions after update: %d", len(sessions))
	})
}
