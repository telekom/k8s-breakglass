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

package helpers

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

var (
	k8sClient     client.Client
	k8sConfig     *rest.Config
	clientOnce    sync.Once
	clientInitErr error
)

func init() {
	// Initialize controller-runtime logger to suppress "log.SetLogger(...) was never called" warning
	log.SetLogger(zap.New(zap.UseDevMode(true)))
	_ = telekomv1alpha1.AddToScheme(scheme.Scheme)
}

// GetKubeconfig returns the path to the kubeconfig file
func GetKubeconfig() string {
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		return kubeconfig
	}
	return os.Getenv("HOME") + "/.kube/config"
}

// GetClient returns a singleton Kubernetes client for E2E tests
func GetClient(t *testing.T) client.Client {
	clientOnce.Do(func() {
		kubeconfig := GetKubeconfig()
		k8sConfig, clientInitErr = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if clientInitErr != nil {
			return
		}

		k8sClient, clientInitErr = client.New(k8sConfig, client.Options{Scheme: scheme.Scheme})
	})

	require.NoError(t, clientInitErr, "Failed to create Kubernetes client")
	return k8sClient
}

// GetConfig returns the Kubernetes REST config
func GetConfig(t *testing.T) *rest.Config {
	_ = GetClient(t) // Ensure client is initialized
	return k8sConfig
}

// MustGetClient returns a client, failing the test if it cannot be created
func MustGetClient(t *testing.T) client.Client {
	cli := GetClient(t)
	require.NotNil(t, cli, "Kubernetes client is nil")
	return cli
}

// CreateAndCleanup creates a resource and registers cleanup
func CreateAndCleanup[T client.Object](t *testing.T, ctx context.Context, cli client.Client, obj T) T {
	// Try to delete first in case it exists from a previous run
	_ = cli.Delete(ctx, obj)

	err := cli.Create(ctx, obj)
	require.NoError(t, err, "Failed to create resource")

	t.Cleanup(func() {
		_ = cli.Delete(context.Background(), obj)
	})

	return obj
}

// GetNamespacedName returns a namespaced name for testing
func GetNamespacedName(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return fmt.Sprintf("%s/%s", namespace, name)
}

// LogClusterConfigStatus logs the status of all ClusterConfigs for debugging
// This is useful to diagnose issues like missing secret keys
func LogClusterConfigStatus(t *testing.T, ctx context.Context, cli client.Client) {
	t.Helper()
	t.Log("=== ClusterConfig Debug Information ===")

	var list telekomv1alpha1.ClusterConfigList
	if err := cli.List(ctx, &list); err != nil {
		t.Logf("ERROR: Failed to list ClusterConfigs: %v", err)
		return
	}

	if len(list.Items) == 0 {
		t.Log("WARNING: No ClusterConfigs found!")
		return
	}

	for _, cc := range list.Items {
		t.Logf("ClusterConfig: %s/%s", cc.Namespace, cc.Name)
		t.Logf("  Tenant: %s, ClusterID: %s", cc.Spec.Tenant, cc.Spec.ClusterID)
		t.Logf("  KubeconfigSecretRef: name=%s, namespace=%s, key=%s",
			cc.Spec.KubeconfigSecretRef.Name,
			cc.Spec.KubeconfigSecretRef.Namespace,
			cc.Spec.KubeconfigSecretRef.Key)

		// Log conditions
		if len(cc.Status.Conditions) > 0 {
			for _, cond := range cc.Status.Conditions {
				t.Logf("  Condition[%s]: status=%s, reason=%s, message=%s",
					cond.Type, cond.Status, cond.Reason, cond.Message)
			}
		} else {
			t.Log("  Conditions: (none)")
		}
	}
	t.Log("========================================")
}

// LogSessionStatus logs the status of a specific session for debugging
func LogSessionStatus(t *testing.T, ctx context.Context, cli client.Client, name, namespace string) {
	t.Helper()
	var session telekomv1alpha1.BreakglassSession
	key := client.ObjectKey{Name: name, Namespace: namespace}
	if err := cli.Get(ctx, key, &session); err != nil {
		t.Logf("ERROR: Failed to get session %s/%s: %v", namespace, name, err)
		return
	}

	t.Logf("Session %s/%s:", namespace, name)
	t.Logf("  User: %s, GrantedGroup: %s, Cluster: %s", session.Spec.User, session.Spec.GrantedGroup, session.Spec.Cluster)
	t.Logf("  State: %s, Approver: %s", session.Status.State, session.Status.Approver)
	t.Logf("  Approvers: %v", session.Status.Approvers)
	if !session.Status.ExpiresAt.IsZero() {
		t.Logf("  ExpiresAt: %s", session.Status.ExpiresAt.Format("2006-01-02T15:04:05Z"))
	}
}

// VerifyClusterConfigSecret verifies that a ClusterConfig's secret is properly configured
// Returns an error if the secret is missing or doesn't have the expected key
func VerifyClusterConfigSecret(t *testing.T, ctx context.Context, cli client.Client, clusterName string) error {
	t.Helper()

	// Find the ClusterConfig
	var ccList telekomv1alpha1.ClusterConfigList
	if err := cli.List(ctx, &ccList); err != nil {
		return fmt.Errorf("failed to list ClusterConfigs: %w", err)
	}

	var cc *telekomv1alpha1.ClusterConfig
	for _, item := range ccList.Items {
		if item.Name == clusterName || item.Spec.Tenant == clusterName {
			cc = &item
			break
		}
	}
	if cc == nil {
		return fmt.Errorf("ClusterConfig not found for cluster: %s", clusterName)
	}

	// Check the secret
	secretRef := cc.Spec.KubeconfigSecretRef
	key := client.ObjectKey{Name: secretRef.Name, Namespace: secretRef.Namespace}

	var secret corev1.Secret
	if err := cli.Get(ctx, key, &secret); err != nil {
		return fmt.Errorf("secret %s/%s not found: %w", secretRef.Namespace, secretRef.Name, err)
	}

	// Determine expected key
	expectedKey := secretRef.Key
	if expectedKey == "" {
		expectedKey = "value" // Default key
	}

	if _, ok := secret.Data[expectedKey]; !ok {
		availableKeys := make([]string, 0, len(secret.Data))
		for k := range secret.Data {
			availableKeys = append(availableKeys, k)
		}
		return fmt.Errorf("secret %s/%s missing key '%s' (available keys: %v)",
			secretRef.Namespace, secretRef.Name, expectedKey, availableKeys)
	}

	t.Logf("ClusterConfig %s: secret %s/%s has key '%s' ✓",
		clusterName, secretRef.Namespace, secretRef.Name, expectedKey)
	return nil
}
