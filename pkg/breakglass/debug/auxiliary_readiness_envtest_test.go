// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestPlatformAuxiliaryReadinessEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	environment := &envtest.Environment{}
	cfg, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	apiClient, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, apiClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "auxiliary-platform"}}))
	object := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "auxiliary", Namespace: "auxiliary-platform"}}
	require.NoError(t, apiClient.Create(ctx, object))
	originalUID := object.UID
	require.NotEmpty(t, originalUID)
	logger := zap.NewNop().Sugar()
	manager := NewAuxiliaryResourceManager(logger, apiClient)
	check := func(uid string) readinessResult {
		return manager.checkSingleResourceReadiness(ctx, logger, apiClient, "v1", "ConfigMap", object.Name, object.Namespace, uid)
	}
	ready := check(string(originalUID))
	require.True(t, ready.ready)
	require.Equal(t, "Current", ready.readinessStatus)
	require.True(t, check("").failed, "legacy resources without a recorded UID cannot be considered ready")
	require.NoError(t, apiClient.Delete(ctx, object))
	require.Eventually(t, func() bool {
		return apierrors.IsNotFound(apiClient.Get(ctx, client.ObjectKeyFromObject(object), &corev1.ConfigMap{}))
	}, 5*time.Second, 20*time.Millisecond)
	missing := check(string(originalUID))
	require.False(t, missing.ready)
	require.False(t, missing.failed)
	require.Equal(t, "NotFound", missing.readinessStatus)
	replacement := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: object.Name, Namespace: object.Namespace}}
	require.NoError(t, apiClient.Create(ctx, replacement))
	require.NotEqual(t, originalUID, replacement.UID)
	replaced := check(string(originalUID))
	require.False(t, replaced.ready)
	require.True(t, replaced.failed)
	require.Equal(t, "resource was replaced", replaced.message)
	require.True(t, check(string(replacement.UID)).ready)
}
