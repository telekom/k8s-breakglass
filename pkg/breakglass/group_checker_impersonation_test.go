// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"

	"k8s.io/client-go/rest"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/impersonation"
)

// restConfigStub is a non-nil rest.Config pointing at an unroutable address. Tests
// use it to prove that argument validation happens before any network call: if it
// did not, these tests would hang rather than fail fast.
var restConfigStub = rest.Config{Host: "https://127.0.0.1:1"}

func TestSelfSubjectAccessReviewSpec(t *testing.T) {
	t.Run("resource attributes", func(t *testing.T) {
		sar := authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   "default",
					Verb:        "get",
					Group:       "apps",
					Resource:    "deployments",
					Subresource: "status",
					Name:        "my-app",
				},
			},
		}

		spec, err := selfSubjectAccessReviewSpec(sar)
		require.NoError(t, err)
		require.NotNil(t, spec.ResourceAttributes)
		assert.Nil(t, spec.NonResourceAttributes)

		ra := spec.ResourceAttributes
		assert.Equal(t, "default", ra.Namespace)
		assert.Equal(t, "get", ra.Verb)
		assert.Equal(t, "apps", ra.Group)
		assert.Equal(t, "deployments", ra.Resource)
		assert.Equal(t, "status", ra.Subresource)
		assert.Equal(t, "my-app", ra.Name)
	})

	t.Run("non-resource attributes", func(t *testing.T) {
		sar := authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				NonResourceAttributes: &authorizationv1.NonResourceAttributes{
					Path: "/healthz", Verb: "get",
				},
			},
		}

		spec, err := selfSubjectAccessReviewSpec(sar)
		require.NoError(t, err)
		require.NotNil(t, spec.NonResourceAttributes)
		assert.Nil(t, spec.ResourceAttributes)
		assert.Equal(t, "/healthz", spec.NonResourceAttributes.Path)
	})

	t.Run("neither is an error", func(t *testing.T) {
		_, err := selfSubjectAccessReviewSpec(authorizationv1.SubjectAccessReview{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resourceAttributes or nonResourceAttributes")
	})
}

// TestResolveProbeCapability_HonoursExplicitClusterConfig covers the per-spoke
// override path, which is how an operator pins a spoke that autodetection cannot
// read correctly.
func TestResolveProbeCapability_HonoursExplicitClusterConfig(t *testing.T) {
	tests := []struct {
		name        string
		support     breakglassv1alpha1.ConstrainedImpersonationSupport
		wantSupport impersonation.Support
		wantVia     string
	}{
		{"enabled", breakglassv1alpha1.ConstrainedImpersonationEnabled, impersonation.SupportYes, "configured"},
		{"disabled", breakglassv1alpha1.ConstrainedImpersonationDisabled, impersonation.SupportNo, "configured"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &breakglassv1alpha1.ConstrainedImpersonationConfig{Support: tc.support}

			got := resolveProbeCapability("some-spoke", cfg)

			assert.Equal(t, tc.wantSupport, got.Support)
			assert.Equal(t, tc.wantVia, got.DetectedVia)
		})
	}
}

// TestResolveProbeCapability_AutoUsesProbeCache asserts Auto defers to runtime
// detection rather than a version compare.
func TestResolveProbeCapability_AutoUsesProbeCache(t *testing.T) {
	cluster := "auto-spoke-" + t.Name()
	t.Cleanup(func() { probeCapabilities.Forget(cluster) })

	// Nothing detected yet: unknown, which means "attempt constrained".
	got := resolveProbeCapability(cluster, &breakglassv1alpha1.ConstrainedImpersonationConfig{
		Support: breakglassv1alpha1.ConstrainedImpersonationAuto,
	})
	assert.Equal(t, impersonation.SupportUnknown, got.Support)
	assert.True(t, got.UsesConstrained(),
		"an undetected spoke must attempt the constrained path so the fallback decides")

	// After a denial the cache reports unsupported, so subsequent requests go
	// straight to legacy without paying for a guaranteed-denied attempt.
	probeCapabilities.RecordProbe(cluster, impersonation.ModeUserInfo, false, "v1.31.0")

	got = resolveProbeCapability(cluster, &breakglassv1alpha1.ConstrainedImpersonationConfig{
		Support: breakglassv1alpha1.ConstrainedImpersonationAuto,
	})
	assert.Equal(t, impersonation.SupportNo, got.Support)
	assert.False(t, got.UsesConstrained())
}

// TestResolveProbeCapability_NilConfigDefaultsToAuto is a compatibility test: a
// ClusterConfig with no constrainedImpersonation block must autodetect.
func TestResolveProbeCapability_NilConfigDefaultsToAuto(t *testing.T) {
	cluster := "nil-cfg-spoke-" + t.Name()
	t.Cleanup(func() { probeCapabilities.Forget(cluster) })

	got := resolveProbeCapability(cluster, nil)

	assert.Equal(t, impersonation.SupportUnknown, got.Support)
	assert.True(t, got.UsesConstrained())
}

// TestResolveProbeCapability_PerSpokeIsolation is the hub-and-spoke requirement:
// two spokes at different Kubernetes versions must both work in one controller.
func TestResolveProbeCapability_PerSpokeIsolation(t *testing.T) {
	modern := "modern-" + t.Name()
	legacy := "legacy-" + t.Name()
	t.Cleanup(func() {
		probeCapabilities.Forget(modern)
		probeCapabilities.Forget(legacy)
	})

	probeCapabilities.RecordProbe(modern, impersonation.ModeUserInfo, true, "v1.36.1")
	probeCapabilities.RecordProbe(legacy, impersonation.ModeUserInfo, false, "v1.31.0")

	auto := &breakglassv1alpha1.ConstrainedImpersonationConfig{
		Support: breakglassv1alpha1.ConstrainedImpersonationAuto,
	}

	gotModern := resolveProbeCapability(modern, auto)
	gotLegacy := resolveProbeCapability(legacy, auto)

	assert.Equal(t, impersonation.SupportYes, gotModern.Support)
	assert.True(t, gotModern.UsesConstrained())

	assert.Equal(t, impersonation.SupportNo, gotLegacy.Support)
	assert.False(t, gotLegacy.UsesConstrained(),
		"the legacy spoke inherited the modern spoke's capability")
}

// TestProbeModeFor covers the probe-mode selection, including the correction of a
// mode that cannot carry groups.
func TestProbeModeFor(t *testing.T) {
	tests := []struct {
		name string
		cfg  *breakglassv1alpha1.ConstrainedImpersonationConfig
		want impersonation.Mode
	}{
		{"nil defaults to user-info", nil, impersonation.ModeUserInfo},
		{"empty defaults to user-info", &breakglassv1alpha1.ConstrainedImpersonationConfig{}, impersonation.ModeUserInfo},
		{
			"explicit user-info",
			&breakglassv1alpha1.ConstrainedImpersonationConfig{ProbeMode: breakglassv1alpha1.ImpersonationModeUserInfo},
			impersonation.ModeUserInfo,
		},
		{
			"explicit legacy is honoured",
			&breakglassv1alpha1.ConstrainedImpersonationConfig{ProbeMode: breakglassv1alpha1.ImpersonationModeLegacy},
			impersonation.ModeLegacy,
		},
		// The probe impersonates groups, and user-info is the only mode that can carry
		// them, so anything else is corrected rather than producing a broken probe.
		{
			"serviceaccount is corrected to user-info",
			&breakglassv1alpha1.ConstrainedImpersonationConfig{ProbeMode: breakglassv1alpha1.ImpersonationModeServiceAccount},
			impersonation.ModeUserInfo,
		},
		{
			"arbitrary-node is corrected to user-info",
			&breakglassv1alpha1.ConstrainedImpersonationConfig{ProbeMode: breakglassv1alpha1.ImpersonationModeArbitraryNode},
			impersonation.ModeUserInfo,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := probeModeFor(tc.cfg); got != tc.want {
				t.Errorf("probeModeFor() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClusterConstrainedImpersonation(t *testing.T) {
	assert.Nil(t, clusterConstrainedImpersonation(nil))
	assert.Nil(t, clusterConstrainedImpersonation(&breakglassv1alpha1.ClusterConfig{}))

	cfg := &breakglassv1alpha1.ConstrainedImpersonationConfig{
		Support: breakglassv1alpha1.ConstrainedImpersonationEnabled,
	}
	cc := &breakglassv1alpha1.ClusterConfig{
		Spec: breakglassv1alpha1.ClusterConfigSpec{ConstrainedImpersonation: cfg},
	}
	assert.Same(t, cfg, clusterConstrainedImpersonation(cc))
}

// TestCanGroupsDoConstrained_NilRestConfig asserts the pre-existing error contract
// is unchanged, since callers key off this exact message.
func TestCanGroupsDoConstrained_NilRestConfig(t *testing.T) {
	_, err := CanGroupsDoConstrained(
		context.Background(), nil, []string{"admins"},
		authorizationv1.SubjectAccessReview{}, "spoke", nil)

	require.Error(t, err)
	assert.Equal(t, "rest config is nil", err.Error(),
		"the error message changed; performRBACCheck matches on it verbatim")
}

// TestCanGroupsDoConstrained_InvalidSARIsRejectedBeforeAnyNetworkCall asserts a
// malformed SAR fails fast rather than producing a misleading capability verdict.
func TestCanGroupsDoConstrained_InvalidSARIsRejectedBeforeAnyNetworkCall(t *testing.T) {
	// A non-nil but unusable rest.Config: if the SAR check did not come first, this
	// would attempt a connection.
	_, err := CanGroupsDoConstrained(
		context.Background(),
		&restConfigStub, []string{"admins"},
		authorizationv1.SubjectAccessReview{}, // neither resource nor non-resource attrs
		"spoke", nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "resourceAttributes or nonResourceAttributes")
}

// TestCanGroupsDo_DelegatesWithNilClusterConfig asserts the legacy entry point
// keeps its signature and error contract.
func TestCanGroupsDo_DelegatesWithNilClusterConfig(t *testing.T) {
	_, err := CanGroupsDo(
		context.Background(), nil, []string{"admins"},
		authorizationv1.SubjectAccessReview{}, "spoke")

	require.Error(t, err)
	assert.Equal(t, "rest config is nil", err.Error())
}

// TestAuthCheckerUsernameUnchanged pins the synthetic probe identity. The
// constrained RBAC in config/rbac/impersonate_constrained_role.yaml names it in
// resourceNames, so changing it here silently breaks the constrained probe on every
// spoke.
func TestAuthCheckerUsernameUnchanged(t *testing.T) {
	assert.Equal(t, "system:auth-checker", AuthCheckerUsername,
		"config/rbac/impersonate_constrained_role.yaml pins this value in resourceNames")
}

// TestProbeCapabilityCacheIsShared asserts the accessor exposes the same cache the
// probe writes to, which is what lets the debug reconciler reuse the verdict.
func TestProbeCapabilityCacheIsShared(t *testing.T) {
	require.NotNil(t, ProbeCapabilityCache())
	assert.Same(t, probeCapabilities, ProbeCapabilityCache())

	cluster := "shared-" + t.Name()
	t.Cleanup(func() { probeCapabilities.Forget(cluster) })

	ProbeCapabilityCache().RecordProbe(cluster, impersonation.ModeUserInfo, true, "v1.36.0")
	assert.Equal(t, impersonation.SupportYes, probeCapabilities.Get(cluster).Support)
}

// TestIsConstrainedImpersonationDenial_TransientErrorsDoNotPinLegacy documents the
// rule at the call site: only an impersonation refusal may downgrade a spoke.
func TestIsConstrainedImpersonationDenial_TransientErrorsDoNotPinLegacy(t *testing.T) {
	transient := []error{
		errors.New("dial tcp 10.0.0.1:6443: connect: connection refused"),
		errors.New("context deadline exceeded"),
		errors.New("an error on the server (\"Internal Server Error\") has prevented the request from succeeding"),
	}

	for _, err := range transient {
		assert.False(t, impersonation.IsConstrainedImpersonationDenial(err),
			"a transient failure (%v) would pin the spoke to legacy mode", err)
	}

	denial := errors.New(`selfsubjectaccessreviews.authorization.k8s.io is forbidden: ` +
		`User "system:serviceaccount:breakglass:manager" cannot impersonate resource ` +
		`"users" in API group "authentication.k8s.io"`)
	assert.True(t, impersonation.IsConstrainedImpersonationDenial(denial))
}
