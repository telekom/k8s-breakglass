// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package impersonation_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/impersonation"
)

// api/v1alpha1/impersonation_validation.go duplicates the constrained-impersonation
// constants so that the API package keeps no dependency on pkg/, and its comment
// names THIS FILE as the thing that asserts the two copies agree. That test did not
// exist, so the duplication was unguarded: a divergence between the admission-time
// validation in api/v1alpha1 and the runtime enforcement in pkg/impersonation would
// compile, lint and pass the whole suite.
//
// The consequence is not cosmetic. If, say, the api/v1alpha1 copy of
// "system:masters" or the system:node:/system:serviceaccount: prefixes drifted from
// pkg/impersonation's, admission would accept a configuration that the runtime then
// treats as a different mode — exactly the silent legacy-downgrade this feature
// exists to prevent.
//
// This file makes the divergence a build failure. It lives in package
// impersonation_test so it may import api/v1alpha1 without creating an import
// cycle.

// TestAPIPackageConstantsMatch asserts the duplicated string constants agree.
func TestAPIPackageConstantsMatch(t *testing.T) {
	assert.Equal(t, impersonation.GroupSystemMasters,
		breakglassv1alpha1.ExportedImpGroupSystemMasters,
		"the system:masters guardrail string differs between api/v1alpha1 and pkg/impersonation")

	assert.Equal(t, impersonation.UsernameNodePrefix,
		breakglassv1alpha1.ExportedImpUsernameNodePrefix,
		"the node username prefix differs; mode inference would diverge between admission and runtime")

	assert.Equal(t, impersonation.UsernameServiceAccountPrefix,
		breakglassv1alpha1.ExportedImpUsernameSAPrefix,
		"the ServiceAccount username prefix differs; mode inference would diverge")

	assert.Equal(t, impersonation.ManyAuthorizationChecksInLoop,
		breakglassv1alpha1.ExportedImpManyChecksInLoop,
		"the apiserver wildcard-collapse threshold differs between the two packages")
}

// TestAPIPackageModesMatch asserts the CRD enum and the runtime Mode set are the
// same, so no mode can be accepted at admission but unknown at runtime (or vice
// versa, which would make a legal configuration unusable).
func TestAPIPackageModesMatch(t *testing.T) {
	apiModes := []breakglassv1alpha1.ImpersonationMode{
		breakglassv1alpha1.ImpersonationModeUserInfo,
		breakglassv1alpha1.ImpersonationModeServiceAccount,
		breakglassv1alpha1.ImpersonationModeArbitraryNode,
		breakglassv1alpha1.ImpersonationModeAssociatedNode,
		breakglassv1alpha1.ImpersonationModeLegacy,
	}

	for _, m := range apiModes {
		parsed, ok := impersonation.ParseMode(string(m))
		assert.True(t, ok,
			"mode %q is accepted by the CRD enum but pkg/impersonation cannot parse it; "+
				"a config valid at admission would be treated as malformed at runtime", m)
		assert.Equal(t, string(m), string(parsed))
	}

	// And the reverse direction: every runtime mode must be expressible in the CRD.
	runtimeModes := append([]impersonation.Mode{}, impersonation.ConstrainedModes...)
	runtimeModes = append(runtimeModes, impersonation.ModeLegacy)
	for _, m := range runtimeModes {
		assert.Contains(t, apiModes, breakglassv1alpha1.ImpersonationMode(m),
			"runtime mode %q has no CRD enum value, so operators cannot configure it", m)
	}
}

// TestAPIPackageIdentityResourcesMatch asserts the identity resource kinds agree.
// A kind known to only one side means either a DenyPolicy rule that admission
// rejects but the runtime would have honoured (a wrong-deny risk) or one that
// admission accepts and the runtime silently ignores (a wrong-allow risk).
func TestAPIPackageIdentityResourcesMatch(t *testing.T) {
	for _, r := range impersonation.IdentityResources {
		assert.True(t, breakglassv1alpha1.ExportedIsImpersonationIdentityResource(r),
			"identity resource %q is known to pkg/impersonation but rejected by api/v1alpha1 "+
				"validation, so a DenyPolicy naming it cannot be created", r)
	}

	for _, r := range breakglassv1alpha1.ExportedImpersonationIdentityResources() {
		assert.True(t, impersonation.IsIdentityResource(r),
			"identity resource %q is accepted at admission but unknown to the runtime, so a "+
				"DenyPolicy naming it would silently never match", r)
	}
}
