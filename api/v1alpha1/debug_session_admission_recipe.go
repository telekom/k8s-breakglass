// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"fmt"
	"regexp"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Admission recipe actions.
const (
	// AdmissionRecipePolicyAudit switches a Kyverno ValidatingPolicy from Deny to Audit.
	AdmissionRecipePolicyAudit = "policy-audit"
	// AdmissionRecipeWebhookFailOpen sets one admission webhook to failurePolicy Ignore.
	AdmissionRecipeWebhookFailOpen = "webhook-fail-open"
)

// Admission recipe target states recorded in DebugSession status.
const (
	// AdmissionRecipeTargetApplying is persisted before the target write.
	AdmissionRecipeTargetApplying = "applying"
	// AdmissionRecipeTargetApplied means the controller changed the field.
	AdmissionRecipeTargetApplied = "applied"
	// AdmissionRecipeTargetDrifted means someone else changed the field or annotation.
	AdmissionRecipeTargetDrifted = "drifted"
	// AdmissionRecipeTargetReverted means the original value was restored.
	AdmissionRecipeTargetReverted = "reverted"
	// AdmissionRecipeTargetRevertSkipped means the field was not ours anymore at revert time.
	AdmissionRecipeTargetRevertSkipped = "revert-skipped"
	// AdmissionRecipeTargetNotApplied means the target was never changed.
	AdmissionRecipeTargetNotApplied = "not-applied"
)

// Spoke annotations written by the admission recipe executor.
const (
	// AdmissionRecipeSessionAnnotation holds the owning DebugSession UID.
	AdmissionRecipeSessionAnnotation = "breakglass.t-caas.telekom.com/admission-recipe-session"
	// AdmissionRecipeExpiresAnnotation holds the RFC3339 revert deadline.
	AdmissionRecipeExpiresAnnotation = "breakglass.t-caas.telekom.com/admission-recipe-expires-at"
	// FluxHelmDriftDetectionAnnotation excludes one object from helm-controller drift correction.
	FluxHelmDriftDetectionAnnotation = "helm.toolkit.fluxcd.io/driftDetection"
	// FluxKustomizeReconcileAnnotation excludes one object from kustomize-controller apply and prune.
	FluxKustomizeReconcileAnnotation = "kustomize.toolkit.fluxcd.io/reconcile"
)

// AdmissionRecipeMaxDuration is the hard upper bound for one recipe session.
const AdmissionRecipeMaxDuration = 2 * time.Hour

// DebugSessionAdmissionRecipe is a typed, controller-executed admission change
// that is reverted when the session ends. Requesters select targets only from
// allowedTargets; the field transition is fixed by the action.
type DebugSessionAdmissionRecipe struct {
	// action selects the fixed field transition.
	// +kubebuilder:validation:Enum=policy-audit;webhook-fail-open
	Action string `json:"action"`
	// allowedTargets is an exact allowlist, not a selector or wildcard.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=atomic
	AllowedTargets []AdmissionRecipeTarget `json:"allowedTargets"`
	// deniedTargetLabels refuses a live target when one of its labels matches,
	// even if it is allowlisted. Evaluated on the spoke immediately before the write.
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	DeniedTargetLabels []AdmissionRecipeDeniedLabel `json:"deniedTargetLabels,omitempty"`
	// flux also sets the per-object Flux annotations that stop helm-controller
	// drift correction and kustomize-controller apply/prune for the window.
	// +optional
	Flux bool `json:"flux,omitempty"`
}

// AdmissionRecipeTarget names exactly one object (and webhook) on the spoke.
type AdmissionRecipeTarget struct {
	// kind is ValidatingPolicy for policy-audit, or ValidatingWebhookConfiguration
	// or MutatingWebhookConfiguration for webhook-fail-open.
	// +kubebuilder:validation:Enum=ValidatingPolicy;ValidatingWebhookConfiguration;MutatingWebhookConfiguration
	Kind string `json:"kind"`
	// apiVersion is the served version of a ValidatingPolicy (policies.kyverno.io/<version>).
	// It must be empty for webhook configurations (always admissionregistration.k8s.io/v1).
	// +optional
	// +kubebuilder:validation:MaxLength=63
	APIVersion string `json:"apiVersion,omitempty"`
	// name is the exact cluster-scoped object name.
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// webhook is the exact webhook name inside the configuration (webhook-fail-open only).
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Webhook string `json:"webhook,omitempty"`
}

// AdmissionRecipeDeniedLabel refuses targets whose label value matches valuePattern.
type AdmissionRecipeDeniedLabel struct {
	// key is the exact label key.
	// +kubebuilder:validation:MaxLength=317
	Key string `json:"key"`
	// valuePattern is an RE2 regular expression matched against the full label value.
	// +kubebuilder:validation:MaxLength=256
	ValuePattern string `json:"valuePattern"`
}

// AdmissionRecipeRequest is the requester's selection of allowlisted targets.
type AdmissionRecipeRequest struct {
	// targets must each equal an allowlist entry of the template.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	Targets []AdmissionRecipeTarget `json:"targets"`
}

// AdmissionRecipeStatus is the durable executor inventory of one session.
type AdmissionRecipeStatus struct {
	// operationID correlates audit events.
	OperationID string `json:"operationID"`
	// targets records each target's original value and state.
	// +optional
	// +listType=atomic
	Targets []AdmissionRecipeTargetStatus `json:"targets,omitempty"`
	// reverted is set after every target was reverted or skipped and audited.
	// +optional
	Reverted bool `json:"reverted,omitempty"`
}

// AdmissionRecipeTargetStatus is the per-target inventory.
type AdmissionRecipeTargetStatus struct {
	// target is the exact allowlisted target.
	Target AdmissionRecipeTarget `json:"target"`
	// state is the last known state.
	// +kubebuilder:validation:Enum=applying;applied;drifted;reverted;revert-skipped;not-applied
	State string `json:"state"`
	// original is the JSON value of the field before the change.
	// +optional
	Original string `json:"original,omitempty"`
	// applied is the JSON value written by the executor.
	// +optional
	Applied string `json:"applied,omitempty"`
	// originalAnnotations records the previous values of the Flux annotations
	// that the executor sets ("" = absent).
	// +optional
	OriginalAnnotations map[string]string `json:"originalAnnotations,omitempty"`
	// message explains refusals, drift and skipped reverts.
	// +optional
	Message string `json:"message,omitempty"`
}

var admissionRecipeVersionPattern = regexp.MustCompile(`^policies\.kyverno\.io/v[0-9]+((alpha|beta)[0-9]+)?$`)

// AdmissionRecipeTargetKey is a stable identity of a target.
func AdmissionRecipeTargetKey(target AdmissionRecipeTarget) string {
	return target.Kind + "/" + target.Name + "/" + target.Webhook
}

// ValidateAdmissionRecipeTarget rejects targets that do not fit the action.
func ValidateAdmissionRecipeTarget(action string, target *AdmissionRecipeTarget) error {
	if target == nil {
		return fmt.Errorf("admissionRecipe target is required")
	}
	if len(validation.IsDNS1123Subdomain(target.Name)) != 0 {
		return fmt.Errorf("admissionRecipe target %q needs an exact object name", target.Name)
	}
	switch action {
	case AdmissionRecipePolicyAudit:
		if target.Kind != "ValidatingPolicy" || !admissionRecipeVersionPattern.MatchString(target.APIVersion) || target.Webhook != "" {
			return fmt.Errorf("policy-audit targets must be Kyverno ValidatingPolicies with apiVersion policies.kyverno.io/<version> and no webhook")
		}
	case AdmissionRecipeWebhookFailOpen:
		if (target.Kind != "ValidatingWebhookConfiguration" && target.Kind != "MutatingWebhookConfiguration") ||
			target.APIVersion != "" ||
			len(validation.IsDNS1123Subdomain(target.Webhook)) != 0 {
			return fmt.Errorf("webhook-fail-open targets must name a webhook configuration and one exact webhook")
		}
	default:
		return fmt.Errorf("unsupported admission recipe action %q", action)
	}
	return nil
}

// ValidateAdmissionRecipeTemplate excludes generic rendering, interactive access and approval bypasses.
func ValidateAdmissionRecipeTemplate(spec *DebugSessionTemplateSpec) error {
	if spec.AdmissionRecipe == nil {
		return nil
	}
	recipe := spec.AdmissionRecipe
	if spec.NodeMaintenance != nil {
		return fmt.Errorf("admissionRecipe and nodeMaintenance are mutually exclusive")
	}
	if (spec.Mode != "" && spec.Mode != DebugSessionModeWorkload) || spec.WorkloadType != "" ||
		(spec.FailMode != "" && spec.FailMode != "closed") ||
		(spec.ExpirationBehavior != "" && spec.ExpirationBehavior != "terminate") {
		return fmt.Errorf("admissionRecipe requires workload mode without workloadType and closed termination")
	}
	if spec.PodTemplateRef != nil || spec.PodTemplateString != "" || spec.PodOverridesTemplate != "" ||
		spec.PodOverrides != nil || len(spec.ExtraDeployVariables) != 0 || spec.AffinityOverrides != nil ||
		len(spec.AdditionalTolerations) != 0 || spec.SchedulingConstraints != nil || spec.SchedulingOptions != nil ||
		spec.KubectlDebug != nil || spec.NamespaceConstraints != nil || spec.Impersonation != nil ||
		spec.TerminalSharing != nil || spec.ArtifactCollection != nil || len(spec.AuxiliaryResources) != 0 ||
		len(spec.RequiredAuxiliaryResourceCategories) != 0 ||
		len(spec.AuxiliaryResourceDefaults) != 0 || spec.PodDisruptionBudget != nil || spec.ResourceQuota != nil ||
		(spec.Audit != nil && spec.Audit.EnableTerminalRecording) {
		return fmt.Errorf("admissionRecipe cannot use workloads, scheduling, interactive access or auxiliary resources")
	}
	if spec.Approvers == nil || len(spec.Approvers.Users)+len(spec.Approvers.Groups) == 0 || spec.Approvers.AutoApproveFor != nil {
		return fmt.Errorf("admissionRecipe requires explicit independent approvers without auto-approval")
	}
	if spec.BlockSelfApproval != nil && !*spec.BlockSelfApproval {
		return fmt.Errorf("admissionRecipe requires blocked self-approval")
	}
	if spec.Constraints == nil || spec.Constraints.MaxDuration == "" {
		return fmt.Errorf("admissionRecipe requires an explicit bounded maxDuration")
	}
	if errs := validatePositiveDurationFormat(spec.Constraints.MaxDuration, field.NewPath("constraints", "maxDuration")); len(errs) > 0 {
		return fmt.Errorf("admissionRecipe requires a valid positive maxDuration: %w", errs[0])
	}
	if d, err := ParseDuration(spec.Constraints.MaxDuration); err != nil || d > AdmissionRecipeMaxDuration {
		return fmt.Errorf("admissionRecipe maxDuration must be at most %s", AdmissionRecipeMaxDuration)
	}
	if spec.Constraints.IdleTimeout != "" || spec.Constraints.AllowRenewal != nil && *spec.Constraints.AllowRenewal {
		return fmt.Errorf("admissionRecipe does not support idleTimeout or renewal; bound the session with maxDuration")
	}
	if len(recipe.AllowedTargets) == 0 || len(recipe.AllowedTargets) > 64 {
		return fmt.Errorf("admissionRecipe requires a nonempty bounded allowlist")
	}
	seen := map[string]bool{}
	for i := range recipe.AllowedTargets {
		if err := ValidateAdmissionRecipeTarget(recipe.Action, &recipe.AllowedTargets[i]); err != nil {
			return fmt.Errorf("invalid admissionRecipe allowlist: %w", err)
		}
		key := AdmissionRecipeTargetKey(recipe.AllowedTargets[i])
		if seen[key] {
			return fmt.Errorf("duplicate admissionRecipe allowlist entry %s", key)
		}
		seen[key] = true
	}
	for _, denied := range recipe.DeniedTargetLabels {
		if errs := validation.IsQualifiedName(denied.Key); len(errs) != 0 {
			return fmt.Errorf("invalid deniedTargetLabels key %q", denied.Key)
		}
		if _, err := regexp.Compile("^(?:" + denied.ValuePattern + ")$"); err != nil || denied.ValuePattern == "" {
			return fmt.Errorf("invalid deniedTargetLabels valuePattern %q", denied.ValuePattern)
		}
	}
	return nil
}

// ValidateAdmissionRecipeSession matches the request against the template and
// forbids generic workload inputs.
func ValidateAdmissionRecipeSession(spec *DebugSessionTemplateSpec, request *DebugSessionSpec) error {
	if spec.AdmissionRecipe == nil {
		if request.AdmissionRecipe != nil {
			return fmt.Errorf("template does not enable admissionRecipe")
		}
		return nil
	}
	if err := ValidateAdmissionRecipeTemplate(spec); err != nil {
		return err
	}
	if request.AdmissionRecipe == nil || len(request.AdmissionRecipe.Targets) == 0 || len(request.AdmissionRecipe.Targets) > 16 {
		return fmt.Errorf("admissionRecipe requires between 1 and 16 targets")
	}
	if request.NodeMaintenance != nil || len(request.ExtraDeployValues) != 0 || len(request.NodeSelector) != 0 ||
		request.SelectedSchedulingOption != "" || request.ResolvedSchedulingConstraints != nil ||
		len(request.SelectedAuxiliaryResources) != 0 || len(request.InvitedParticipants) != 0 {
		return fmt.Errorf("admissionRecipe accepts only typed targets, not generic workload overrides")
	}
	allowed := map[string]AdmissionRecipeTarget{}
	for _, target := range spec.AdmissionRecipe.AllowedTargets {
		allowed[AdmissionRecipeTargetKey(target)] = target
	}
	seen := map[string]bool{}
	for i := range request.AdmissionRecipe.Targets {
		target := request.AdmissionRecipe.Targets[i]
		if err := ValidateAdmissionRecipeTarget(spec.AdmissionRecipe.Action, &target); err != nil {
			return err
		}
		key := AdmissionRecipeTargetKey(target)
		if allowedTarget, ok := allowed[key]; !ok || allowedTarget != target {
			return fmt.Errorf("admissionRecipe target %s is not in the template allowlist", key)
		}
		if seen[key] {
			return fmt.Errorf("duplicate admissionRecipe target %s", key)
		}
		seen[key] = true
	}
	return nil
}

// AdmissionRecipeDeniedBy returns the first denied label rule that matches labels.
func AdmissionRecipeDeniedBy(rules []AdmissionRecipeDeniedLabel, labels map[string]string) (string, bool) {
	for _, rule := range rules {
		value, ok := labels[rule.Key]
		if !ok {
			continue
		}
		pattern, err := regexp.Compile("^(?:" + rule.ValuePattern + ")$")
		if err != nil || pattern.MatchString(value) {
			return rule.Key + "=" + value, true
		}
	}
	return "", false
}
