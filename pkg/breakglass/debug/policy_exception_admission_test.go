// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package debug

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func webhookDenial() error {
	return apierrors.NewForbidden(schema.GroupResource{Group: "batch", Resource: "jobs"}, "trace",
		errors.New(`admission webhook "vpol.validate.kyverno.svc-fail" denied the request: Policy disallow-host-namespaces failed`))
}

func shortPolicyExceptionWindow(t *testing.T, window time.Duration) {
	t.Helper()
	oldWindow, oldInterval := policyExceptionAdmissionWindow, policyExceptionAdmissionInterval
	policyExceptionAdmissionWindow, policyExceptionAdmissionInterval = window, time.Millisecond
	t.Cleanup(func() { policyExceptionAdmissionWindow, policyExceptionAdmissionInterval = oldWindow, oldInterval })
}

func TestCreatedKyvernoPolicyException(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses []breakglassv1alpha1.AuxiliaryResourceStatus
		want     bool
	}{
		{name: "none"},
		{name: "configmap", statuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Kind: "ConfigMap", APIVersion: "v1", Created: true}}},
		{name: "policies v1", statuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Kind: "PolicyException", APIVersion: "policies.kyverno.io/v1", Created: true}}, want: true},
		{name: "kyverno v2", statuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Kind: "PolicyException", APIVersion: "kyverno.io/v2", Created: true}}, want: true},
		{name: "not created", statuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Kind: "PolicyException", APIVersion: "kyverno.io/v2"}}},
		{name: "foreign group", statuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Kind: "PolicyException", APIVersion: "example.com/v1", Created: true}}},
		{name: "other kyverno group", statuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Kind: "PolicyException", APIVersion: "reports.kyverno.io/v1", Created: true}}},
		{name: "suffix lookalike", statuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Kind: "PolicyException", APIVersion: "custom.kyverno.io/v1", Created: true}}},
		{name: "additional document", statuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Kind: "ConfigMap", APIVersion: "v1", Created: true, AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{{Kind: "PolicyException", APIVersion: "policies.kyverno.io/v1"}}}}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, createdKyvernoPolicyException(tc.statuses))
		})
	}
}

func TestCreateAfterPolicyExceptionRetriesWebhookDenial(t *testing.T) {
	shortPolicyExceptionWindow(t, time.Second)
	calls, fences := 0, 0
	err := createAfterPolicyException(context.Background(), func() error {
		calls++
		if calls < 3 {
			return webhookDenial()
		}
		return nil
	}, func() error { fences++; return nil })
	require.NoError(t, err)
	require.Equal(t, 3, calls)
	require.Equal(t, 2, fences)
}

func TestCreateAfterPolicyExceptionStopsOnOtherErrors(t *testing.T) {
	shortPolicyExceptionWindow(t, time.Second)
	for name, want := range map[string]error{
		"forbidden rbac": apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "x", errors.New("user cannot create")),
		"invalid":        apierrors.NewBadRequest("invalid"),
		"plain":          errors.New("connection reset"),
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			err := createAfterPolicyException(context.Background(), func() error { calls++; return want }, func() error { return nil })
			require.ErrorIs(t, err, want)
			require.Equal(t, 1, calls)
		})
	}
}

func TestCreateAfterPolicyExceptionBoundedWindow(t *testing.T) {
	shortPolicyExceptionWindow(t, 20*time.Millisecond)
	calls := 0
	err := createAfterPolicyException(context.Background(), func() error { calls++; return webhookDenial() }, func() error { return nil })
	require.True(t, isAdmissionWebhookDenial(err))
	require.Greater(t, calls, 1)
}

func TestCreateAfterPolicyExceptionHonoursContextAndFence(t *testing.T) {
	shortPolicyExceptionWindow(t, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := createAfterPolicyException(ctx, webhookDenial, func() error { return nil })
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, isAdmissionWebhookDenial(err))

	fenceErr := errors.New("session no longer owns workload")
	calls := 0
	err = createAfterPolicyException(context.Background(), func() error { calls++; return webhookDenial() }, func() error { return fenceErr })
	require.ErrorIs(t, err, fenceErr)
	require.Equal(t, 1, calls)
}

func TestWrappedWebhookDenialIsRetryable(t *testing.T) {
	require.True(t, isAdmissionWebhookDenial(fmt.Errorf("create tracked resource: %w", webhookDenial())))
	require.False(t, isAdmissionWebhookDenial(errors.New(`admission webhook "x" denied the request`)))
}

func createAfterPolicyException(ctx context.Context, create, fence func() error) error {
	return createUntilAdmitted(ctx, time.Now().Add(policyExceptionAdmissionWindow), create, fence)
}

func TestPolicyExceptionAdmissionDeadline(t *testing.T) {
	shortPolicyExceptionWindow(t, time.Minute)
	at := func(d time.Duration) *string { s := time.Now().Add(d).UTC().Format(time.RFC3339); return &s }
	exception := func(createdAt *string, deleted bool) breakglassv1alpha1.AuxiliaryResourceStatus {
		return breakglassv1alpha1.AuxiliaryResourceStatus{Kind: "PolicyException", APIVersion: "policies.kyverno.io/v1", Created: true, CreatedAt: createdAt, Deleted: deleted}
	}
	_, ok := policyExceptionAdmissionDeadline(nil)
	require.False(t, ok)
	_, ok = policyExceptionAdmissionDeadline([]breakglassv1alpha1.AuxiliaryResourceStatus{exception(at(-2*time.Minute), false)})
	require.False(t, ok, "window closed")
	_, ok = policyExceptionAdmissionDeadline([]breakglassv1alpha1.AuxiliaryResourceStatus{exception(at(0), true)})
	require.False(t, ok, "deleted exception")
	_, ok = policyExceptionAdmissionDeadline([]breakglassv1alpha1.AuxiliaryResourceStatus{{Kind: "ConfigMap", APIVersion: "v1", Created: true, CreatedAt: at(0)}})
	require.False(t, ok, "not an exception")
	deadline, ok := policyExceptionAdmissionDeadline([]breakglassv1alpha1.AuxiliaryResourceStatus{exception(at(-2*time.Minute), false), exception(at(-10*time.Second), false)})
	require.True(t, ok)
	require.WithinDuration(t, time.Now().Add(50*time.Second), deadline, 2*time.Second)
}

func TestMergeAuxiliaryStatusesKeepsFirstCreatedAt(t *testing.T) {
	first, later := "2026-01-01T00:00:00Z", "2026-01-01T00:05:00Z"
	status := func(createdAt string, deleted bool) breakglassv1alpha1.AuxiliaryResourceStatus {
		return breakglassv1alpha1.AuxiliaryResourceStatus{Name: "exception", ResourceName: "debug-node-uid", Kind: "PolicyException", APIVersion: "policies.kyverno.io/v1", Created: true, CreatedAt: &createdAt, Deleted: deleted}
	}
	merged := mergeAuxiliaryStatuses([]breakglassv1alpha1.AuxiliaryResourceStatus{status(first, false)}, []breakglassv1alpha1.AuxiliaryResourceStatus{status(later, false)})
	require.Equal(t, first, *merged[0].CreatedAt, "a redeploy must not extend the admission window")
	merged = mergeAuxiliaryStatuses([]breakglassv1alpha1.AuxiliaryResourceStatus{status(first, true)}, []breakglassv1alpha1.AuxiliaryResourceStatus{status(later, false)})
	require.Equal(t, later, *merged[0].CreatedAt, "a recreated resource starts a new window")
}
