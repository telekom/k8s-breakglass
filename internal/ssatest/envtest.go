// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package ssatest provides real API-server fixtures for SSA characterization tests.
package ssatest

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Start installs the repository CRDs and returns an uncached API-server client.
func Start(t *testing.T) client.Client {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	_, source, _, ok := runtime.Caller(0)
	require.True(t, ok)
	environment := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join(filepath.Dir(source), "..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	scheme := k8sruntime.NewScheme()
	for _, add := range []func(*k8sruntime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, batchv1.AddToScheme, breakglassv1alpha1.AddToScheme,
	} {
		require.NoError(t, add(scheme))
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	return c
}

// Session creates a valid regular session. Status must be seeded separately.
func Session(t *testing.T, c client.Client, name string) *breakglassv1alpha1.BreakglassSession {
	t.Helper()
	obj := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "spoke", User: "user@example.com", GrantedGroup: "admins",
		},
	}
	require.NoError(t, c.Create(t.Context(), obj))
	return obj
}

// DebugSession creates a valid debug session with an unexpired active status.
func DebugSession(t *testing.T, c client.Client, name string) *breakglassv1alpha1.DebugSession {
	t.Helper()
	obj := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "spoke", TemplateRef: "template", RequestedBy: "user@example.com",
		},
	}
	require.NoError(t, c.Create(t.Context(), obj))
	expiry := metav1.NewTime(time.Now().Add(time.Hour).UTC().Truncate(time.Second))
	obj.Status = breakglassv1alpha1.DebugSessionStatus{
		State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry,
	}
	require.NoError(t, c.Status().Update(t.Context(), obj))
	return obj
}

// Escalation creates a valid escalation with no validation/group-sync status.
func Escalation(t *testing.T, c client.Client, name string) *breakglassv1alpha1.BreakglassEscalation {
	t.Helper()
	obj := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed:        breakglassv1alpha1.BreakglassEscalationAllowed{Clusters: []string{"spoke"}, Groups: []string{"users"}},
			Approvers:      breakglassv1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
			EscalatedGroup: "admins",
		},
	}
	require.NoError(t, c.Create(t.Context(), obj))
	return obj
}

// CountingClient records actual write attempts while delegating to a real server.
// Hooks deliberately race a second writer between the helper's read and write.
type CountingClient struct {
	client.Client
	Applies           atomic.Int64
	Patches           atomic.Int64
	StatusPatches     atomic.Int64
	BeforePatch       func(context.Context, client.Object)
	BeforeApply       func(context.Context)
	BeforeStatusPatch func(context.Context, client.Object)
}

func (c *CountingClient) Apply(ctx context.Context, obj k8sruntime.ApplyConfiguration, opts ...client.ApplyOption) error {
	c.Applies.Add(1)
	if c.BeforeApply != nil {
		c.BeforeApply(ctx)
	}
	return c.Client.Apply(ctx, obj, opts...)
}

func (c *CountingClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	c.Patches.Add(1)
	if c.BeforePatch != nil {
		c.BeforePatch(ctx, obj)
	}

	return c.Client.Patch(ctx, obj, patch, opts...)
}

func (c *CountingClient) Status() client.SubResourceWriter {
	return &statusWriter{SubResourceWriter: c.Client.Status(), counter: c}
}

func (c *CountingClient) SubResource(name string) client.SubResourceClient {
	return &subResourceClient{SubResourceClient: c.Client.SubResource(name), counter: c, name: name}
}

type statusWriter struct {
	client.SubResourceWriter
	counter *CountingClient
}

func (w *statusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	w.counter.StatusPatches.Add(1)
	if w.counter.BeforeStatusPatch != nil {
		w.counter.BeforeStatusPatch(ctx, obj)
	}
	return w.SubResourceWriter.Patch(ctx, obj, patch, opts...)
}

type subResourceClient struct {
	client.SubResourceClient
	counter *CountingClient
	name    string
}

func (c *subResourceClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	if c.name == "status" {
		c.counter.StatusPatches.Add(1)
		if c.counter.BeforeStatusPatch != nil {
			c.counter.BeforeStatusPatch(ctx, obj)
		}
	}
	return c.SubResourceClient.Patch(ctx, obj, patch, opts...)
}

func (c *subResourceClient) Apply(ctx context.Context, obj k8sruntime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	c.counter.Applies.Add(1)
	return c.SubResourceClient.Apply(ctx, obj, opts...)
}
