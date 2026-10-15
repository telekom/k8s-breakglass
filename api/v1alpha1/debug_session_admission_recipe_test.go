// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func recipeTemplateSpec() *DebugSessionTemplateSpec {
	return &DebugSessionTemplateSpec{
		Approvers:   &DebugSessionApprovers{Groups: []string{"platform-approvers"}},
		Constraints: &DebugSessionConstraints{MaxDuration: "30m"},
		AdmissionRecipe: &DebugSessionAdmissionRecipe{
			Action: AdmissionRecipePolicyAudit,
			AllowedTargets: []AdmissionRecipeTarget{
				{Kind: "ValidatingPolicy", APIVersion: "policies.kyverno.io/v1", Name: "require-pod-probes"},
				{Kind: "ValidatingPolicy", APIVersion: "policies.kyverno.io/v1", Name: "require-labels"},
			},
			DeniedTargetLabels: []AdmissionRecipeDeniedLabel{{Key: "categories", ValuePattern: `(.+_)?(platform-)?critical(_.+)?`}},
		},
	}
}

func TestValidateAdmissionRecipeTemplate(t *testing.T) {
	require.NoError(t, ValidateAdmissionRecipeTemplate(recipeTemplateSpec()))
	for name, mutate := range map[string]func(*DebugSessionTemplateSpec){
		"pod template":       func(s *DebugSessionTemplateSpec) { s.PodTemplateString = "kind: Pod" },
		"auxiliary":          func(s *DebugSessionTemplateSpec) { s.AuxiliaryResources = []AuxiliaryResource{{Name: "x"}} },
		"kubectl debug mode": func(s *DebugSessionTemplateSpec) { s.Mode = DebugSessionModeKubectlDebug },
		"no approvers":       func(s *DebugSessionTemplateSpec) { s.Approvers = nil },
		"auto approve":       func(s *DebugSessionTemplateSpec) { s.Approvers.AutoApproveFor = &AutoApproveConfig{} },
		"self approval":      func(s *DebugSessionTemplateSpec) { s.BlockSelfApproval = new(bool) },
		"no max duration":    func(s *DebugSessionTemplateSpec) { s.Constraints.MaxDuration = "" },
		"too long":           func(s *DebugSessionTemplateSpec) { s.Constraints.MaxDuration = "3h" },
		"idle timeout":       func(s *DebugSessionTemplateSpec) { s.Constraints.IdleTimeout = "10m" },
		"renewal":            func(s *DebugSessionTemplateSpec) { s.Constraints.AllowRenewal = ptr(true) },
		"node maintenance":   func(s *DebugSessionTemplateSpec) { s.NodeMaintenance = &DebugSessionNodeMaintenance{} },
		"empty allowlist":    func(s *DebugSessionTemplateSpec) { s.AdmissionRecipe.AllowedTargets = nil },
		"duplicate": func(s *DebugSessionTemplateSpec) {
			s.AdmissionRecipe.AllowedTargets[1] = s.AdmissionRecipe.AllowedTargets[0]
		},
		"webhook kind for policy-audit": func(s *DebugSessionTemplateSpec) {
			s.AdmissionRecipe.AllowedTargets[0] = AdmissionRecipeTarget{Kind: "ValidatingWebhookConfiguration", Name: "x", Webhook: "w.example.com"}
		},
		"foreign api group": func(s *DebugSessionTemplateSpec) { s.AdmissionRecipe.AllowedTargets[0].APIVersion = "example.com/v1" },
		"bad pattern":       func(s *DebugSessionTemplateSpec) { s.AdmissionRecipe.DeniedTargetLabels[0].ValuePattern = "(" },
		"policy for webhook action": func(s *DebugSessionTemplateSpec) {
			s.AdmissionRecipe.Action = AdmissionRecipeWebhookFailOpen
		},
		"webhook without name": func(s *DebugSessionTemplateSpec) {
			s.AdmissionRecipe.Action = AdmissionRecipeWebhookFailOpen
			s.AdmissionRecipe.AllowedTargets = []AdmissionRecipeTarget{{Kind: "MutatingWebhookConfiguration", Name: "x"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := recipeTemplateSpec()
			mutate(spec)
			require.Error(t, ValidateAdmissionRecipeTemplate(spec))
		})
	}
	webhook := recipeTemplateSpec()
	webhook.AdmissionRecipe.Action = AdmissionRecipeWebhookFailOpen
	webhook.AdmissionRecipe.AllowedTargets = []AdmissionRecipeTarget{{Kind: "ValidatingWebhookConfiguration", Name: "ingress-nginx-admission", Webhook: "validate.nginx.ingress.kubernetes.io"}}
	require.NoError(t, ValidateAdmissionRecipeTemplate(webhook))
}

func TestValidateAdmissionRecipeSession(t *testing.T) {
	spec := recipeTemplateSpec()
	allowed := spec.AdmissionRecipe.AllowedTargets[0]
	request := &DebugSessionSpec{AdmissionRecipe: &AdmissionRecipeRequest{Targets: []AdmissionRecipeTarget{allowed}}}
	require.NoError(t, ValidateAdmissionRecipeSession(spec, request))

	notAllowed := *request.AdmissionRecipe
	notAllowed.Targets = []AdmissionRecipeTarget{{Kind: "ValidatingPolicy", APIVersion: "policies.kyverno.io/v1", Name: "disallow-host-path"}}
	require.ErrorContains(t, ValidateAdmissionRecipeSession(spec, &DebugSessionSpec{AdmissionRecipe: &notAllowed}), "not in the template allowlist")
	otherVersion := allowed
	otherVersion.APIVersion = "policies.kyverno.io/v1beta1"
	require.ErrorContains(t, ValidateAdmissionRecipeSession(spec, &DebugSessionSpec{AdmissionRecipe: &AdmissionRecipeRequest{Targets: []AdmissionRecipeTarget{otherVersion}}}), "not in the template allowlist")
	require.ErrorContains(t, ValidateAdmissionRecipeSession(spec, &DebugSessionSpec{AdmissionRecipe: &AdmissionRecipeRequest{Targets: []AdmissionRecipeTarget{allowed, allowed}}}), "duplicate")
	require.Error(t, ValidateAdmissionRecipeSession(spec, &DebugSessionSpec{}))
	withOverride := *request
	withOverride.ExtraDeployValues = map[string]apiextensionsv1.JSON{"x": {Raw: []byte(`"y"`)}}
	require.ErrorContains(t, ValidateAdmissionRecipeSession(spec, &withOverride), "only typed targets")
	require.ErrorContains(t, ValidateAdmissionRecipeSession(&DebugSessionTemplateSpec{}, request), "does not enable")
	require.NoError(t, ValidateAdmissionRecipeSession(&DebugSessionTemplateSpec{}, &DebugSessionSpec{}))
}

func TestAdmissionRecipeDeniedByMatchesFullLabelValue(t *testing.T) {
	rules := []AdmissionRecipeDeniedLabel{{Key: "categories", ValuePattern: `(.+_)?(platform-)?critical(_.+)?`}}
	for value, denied := range map[string]bool{
		"platform-critical":                    true,
		"critical_psa_platform-best-practices": true,
		"psa_platform-best-practices_critical": true,
		"platform-critical_psa":                true,
		"platform-best-practices":              false,
		"psa":                                  false,
		"noncritical":                          false,
		"critical-ish":                         false,
	} {
		_, got := AdmissionRecipeDeniedBy(rules, map[string]string{"categories": value})
		require.Equal(t, denied, got, value)
	}
	_, got := AdmissionRecipeDeniedBy(rules, map[string]string{})
	require.False(t, got)
}
