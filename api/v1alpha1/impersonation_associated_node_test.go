// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// associatedNodeConfig is the configuration under test: the mode this package now
// refuses to accept.
func associatedNodeConfig() *ImpersonationConfig {
	return &ImpersonationConfig{
		Mode:     ImpersonationModeAssociatedNode,
		UserName: "system:node:worker-1",
	}
}

// TestValidateImpersonationConstraints_AssociatedNodeRejected asserts the mode is
// refused at admission, with an actionable message.
//
// Why reject rather than implement: the API server only selects associated-node when
// the impersonated node name matches the REQUESTOR's own node, read from its
// authentication.kubernetes.io/node-name extra. Satisfying that means injecting the
// controller pod's node via the downward API — and the node this controller happens
// to be scheduled on is arbitrary with respect to the spoke cluster, the session and
// the target workload. Breakglass authorizes humans via OIDC, not node-bound
// ServiceAccounts, so a controller impersonating its own node grants nothing
// meaningful. Wiring it would convert a loud runtime failure into a silent fake
// success.
//
// Before this rejection the mode was accepted at admission and then failed at deploy
// time (NODE_NAME is never set on the breakglass pod), i.e. mid-incident. Now it
// fails at `kubectl apply`.
func TestValidateImpersonationConstraints_AssociatedNodeRejected(t *testing.T) {
	errs := validateImpersonationConstraints(
		associatedNodeConfig(), field.NewPath("spec", "impersonation"))

	require.NotEmpty(t, errs,
		"mode associated-node was accepted; it cannot work in the OIDC model and must be "+
			"refused at apply time rather than failing mid-incident at deploy time")

	joined := strings.ToLower(errorDetails(errs))

	// The message must name the mode and be actionable, not merely "invalid".
	assert.Contains(t, joined, "associated-node")
	assert.Contains(t, joined, "not supported",
		"the error should say the mode is unsupported by breakglass")
	assert.Contains(t, joined, "node-bound",
		"the error should explain WHY: breakglass has no node-bound identity")

	// It must point the operator at a mode that does work.
	assert.True(t,
		strings.Contains(joined, "arbitrary-node") ||
			strings.Contains(joined, "user-info") ||
			strings.Contains(joined, "serviceaccount"),
		"the error should suggest a supported alternative, got: %s", joined)

	// The offending field must be identified so kubectl points at it.
	assert.Equal(t, "spec.impersonation.mode", errs[0].Field)
}

// TestValidateImpersonationConstraints_OtherModesStillAccepted is the other half:
// rejecting associated-node must not collaterally break the three usable modes.
func TestValidateImpersonationConstraints_OtherModesStillAccepted(t *testing.T) {
	valid := []struct {
		name string
		ic   *ImpersonationConfig
	}{
		{"user-info", &ImpersonationConfig{Mode: ImpersonationModeUserInfo, UserName: "jane"}},
		{"serviceaccount", &ImpersonationConfig{
			Mode:     ImpersonationModeServiceAccount,
			UserName: "system:serviceaccount:kube-system:probe",
		}},
		{"arbitrary-node", &ImpersonationConfig{
			Mode:     ImpersonationModeArbitraryNode,
			UserName: "system:node:worker-1",
		}},
		{"legacy", &ImpersonationConfig{Mode: ImpersonationModeLegacy, UserName: "jane"}},
	}

	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateImpersonationConstraints(tc.ic, field.NewPath("spec", "impersonation"))
			assert.Empty(t, errs, "mode %s was rejected: %v", tc.name, errs)
		})
	}
}

// TestValidateDebugSessionTemplate_AssociatedNodeRejected drives the real admission
// entry point for DebugSessionTemplate, not just the internal helper, so a future
// refactor that stops calling the helper is caught.
func TestValidateDebugSessionTemplate_AssociatedNodeRejected(t *testing.T) {
	newTemplate := func(ic *ImpersonationConfig) *DebugSessionTemplate {
		return &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
			Spec: DebugSessionTemplateSpec{
				Mode:              DebugSessionModeWorkload,
				PodTemplateString: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: debug",
				Impersonation:     ic,
			},
		}
	}

	t.Run("associated-node is rejected", func(t *testing.T) {
		result := ValidateDebugSessionTemplate(newTemplate(associatedNodeConfig()))

		require.False(t, result.IsValid(),
			"a DebugSessionTemplate with mode associated-node was accepted; it would fail at "+
				"deploy time, mid-incident")
		assert.Contains(t, result.ErrorMessage(), "associated-node")
		assert.Contains(t, result.ErrorMessage(), "not supported")
	})

	t.Run("arbitrary-node is still accepted", func(t *testing.T) {
		result := ValidateDebugSessionTemplate(newTemplate(&ImpersonationConfig{
			Mode:     ImpersonationModeArbitraryNode,
			UserName: "system:node:worker-1",
		}))

		assert.True(t, result.IsValid(),
			"rejecting associated-node broke arbitrary-node: %s", result.ErrorMessage())
	})

	// The pre-existing shape: serviceAccountRef only, no explicit mode. This is what
	// templates created before the mode field existed look like, and it must keep
	// validating exactly as before.
	t.Run("serviceAccountRef-only config keeps working", func(t *testing.T) {
		result := ValidateDebugSessionTemplate(newTemplate(&ImpersonationConfig{
			ServiceAccountRef: &ServiceAccountReference{
				Name: "debug-deployer", Namespace: "breakglass-system",
			},
		}))

		assert.True(t, result.IsValid(),
			"a pre-existing serviceAccountRef-only template was broken: %s", result.ErrorMessage())
	})
}

// TestValidateDebugSessionClusterBinding_AssociatedNodeRejected is the same for the
// binding kind, which has its own validation entry point.
func TestValidateDebugSessionClusterBinding_AssociatedNodeRejected(t *testing.T) {
	newBinding := func(ic *ImpersonationConfig) *DebugSessionClusterBinding {
		return &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef:   &TemplateReference{Name: "test-template"},
				Clusters:      []string{"cluster-1"},
				Impersonation: ic,
			},
		}
	}

	t.Run("associated-node is rejected", func(t *testing.T) {
		result := ValidateDebugSessionClusterBinding(newBinding(associatedNodeConfig()))

		require.False(t, result.IsValid(),
			"a DebugSessionClusterBinding with mode associated-node was accepted")
		assert.Contains(t, result.ErrorMessage(), "associated-node")
		assert.Contains(t, result.ErrorMessage(), "not supported")
	})

	t.Run("other modes still accepted", func(t *testing.T) {
		for _, ic := range []*ImpersonationConfig{
			{Mode: ImpersonationModeUserInfo, UserName: "jane"},
			{Mode: ImpersonationModeArbitraryNode, UserName: "system:node:worker-1"},
			{ServiceAccountRef: &ServiceAccountReference{Name: "sa", Namespace: "ns"}},
		} {
			result := ValidateDebugSessionClusterBinding(newBinding(ic))
			assert.True(t, result.IsValid(),
				"config %+v was rejected: %s", ic, result.ErrorMessage())
		}
	})
}

// TestAssociatedNodeModeStillRecognisedForAuthorization guards the defence-in-depth
// requirement.
//
// Blocking operators from CONFIGURING the mode must not remove the system's knowledge
// of it. The mode stays a first-class value in the enum and in pkg/impersonation so
// that:
//
//   - the verb parser can still classify `impersonate:associated-node` and
//     `impersonate-on:associated-node:<verb>` rather than treating them as unknown
//     verbs, and
//   - a DenyPolicy can still name the mode to deny it.
//
// That matters if a grant is applied out-of-band: the authorization webhook must be
// able to recognise and deny the verb even though breakglass will never request it.
func TestAssociatedNodeModeStillRecognisedForAuthorization(t *testing.T) {
	// Still a valid enum value, so the CRD accepts it in DenyPolicy modes and the
	// parser has a constant to match.
	assert.True(t, validImpersonationModes[ImpersonationModeAssociatedNode],
		"associated-node was removed from the recognised modes; the verb parser and "+
			"DenyPolicy would stop recognising impersonate:associated-node, which turns a "+
			"deniable verb into an unknown one")

	// A DenyPolicy naming the mode must still validate — this is how an operator
	// defends against an out-of-band grant.
	errs := validateImpersonationDenyRules([]ImpersonationDenyRule{{
		Modes:             []ImpersonationMode{ImpersonationModeAssociatedNode, ImpersonationModeLegacy},
		IdentityResources: []string{"nodes"},
	}}, field.NewPath("spec", "impersonationRules"))

	assert.Empty(t, errs,
		"a DenyPolicy denying associated-node was rejected; operators must be able to deny "+
			"a mode breakglass itself cannot configure: %v", errs)
}

// errorDetails joins the details of a field.ErrorList for substring assertions.
func errorDetails(errs field.ErrorList) string {
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, e.Error())
	}
	return strings.Join(parts, " | ")
}
