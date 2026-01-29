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

package v1alpha1

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// DebugSessionClusterBindingConditionType defines condition types for DebugSessionClusterBinding.
type DebugSessionClusterBindingConditionType string

const (
	// DebugSessionClusterBindingConditionReady indicates the binding is ready for use.
	DebugSessionClusterBindingConditionReady DebugSessionClusterBindingConditionType = "Ready"
	// DebugSessionClusterBindingConditionValid indicates the binding configuration is valid.
	DebugSessionClusterBindingConditionValid DebugSessionClusterBindingConditionType = "Valid"
	// DebugSessionClusterBindingConditionTemplateResolved indicates the referenced template(s) have been resolved.
	DebugSessionClusterBindingConditionTemplateResolved DebugSessionClusterBindingConditionType = "TemplateResolved"
	// DebugSessionClusterBindingConditionClustersResolved indicates the target clusters have been resolved.
	DebugSessionClusterBindingConditionClustersResolved DebugSessionClusterBindingConditionType = "ClustersResolved"
)

// DebugSessionClusterBindingSpec defines the desired state of DebugSessionClusterBinding.
// A binding provides delegated access to one or more DebugSessionTemplates on specific clusters
// with optional constraint overrides.
type DebugSessionClusterBindingSpec struct {
	// displayName is the human-readable name shown in UI.
	// If set, overrides the template's displayName for this binding.
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// displayNamePrefix is prepended to template display names when using templateSelector.
	// Only used with templateSelector, ignored with templateRef.
	// +optional
	DisplayNamePrefix string `json:"displayNamePrefix,omitempty"`

	// description provides additional context about this binding.
	// +optional
	Description string `json:"description,omitempty"`

	// templateRef references a single DebugSessionTemplate by name.
	// Mutually exclusive with templateSelector.
	// +optional
	TemplateRef *TemplateReference `json:"templateRef,omitempty"`

	// templateSelector matches multiple DebugSessionTemplates by labels.
	// Mutually exclusive with templateRef.
	// +optional
	TemplateSelector *metav1.LabelSelector `json:"templateSelector,omitempty"`

	// clusters is a list of cluster names (exact matches, no globs) this binding applies to.
	// +optional
	Clusters []string `json:"clusters,omitempty"`

	// clusterSelector matches clusters by labels on ClusterConfig resources.
	// Combined with clusters using OR logic.
	// +optional
	ClusterSelector *metav1.LabelSelector `json:"clusterSelector,omitempty"`

	// allowed specifies which users/groups can use this binding.
	// REPLACES the template's allowed for matched clusters.
	// +optional
	Allowed *DebugSessionAllowed `json:"allowed,omitempty"`

	// approvers specifies who can approve sessions created via this binding.
	// REPLACES the template's approvers for matched clusters.
	// +optional
	Approvers *DebugSessionApprovers `json:"approvers,omitempty"`

	// schedulingConstraints defines mandatory scheduling rules.
	// These constraints are ADDED to the template's constraints and cannot be overridden.
	// +optional
	SchedulingConstraints *SchedulingConstraints `json:"schedulingConstraints,omitempty"`

	// schedulingOptions offers users a choice of predefined scheduling configurations.
	// Each option can add additional constraints on top of schedulingConstraints.
	// +optional
	SchedulingOptions *SchedulingOptions `json:"schedulingOptions,omitempty"`

	// constraints are session constraints (stricter than template).
	// Values here can only be MORE restrictive than the template.
	// +optional
	Constraints *DebugSessionConstraints `json:"constraints,omitempty"`

	// namespaceConstraints defines where debug pods can be deployed.
	// Can only be MORE restrictive than the template's constraints.
	// +optional
	NamespaceConstraints *NamespaceConstraints `json:"namespaceConstraints,omitempty"`

	// impersonation configures ServiceAccount impersonation for deployment.
	// If set, overrides the template's impersonation configuration.
	// +optional
	Impersonation *ImpersonationConfig `json:"impersonation,omitempty"`

	// requiredAuxiliaryResourceCategories lists categories that MUST be enabled.
	// These cannot be disabled by the binding.
	// +optional
	RequiredAuxiliaryResourceCategories []string `json:"requiredAuxiliaryResourceCategories,omitempty"`

	// auxiliaryResourceOverrides enables or disables specific auxiliary resource categories.
	// Categories in requiredAuxiliaryResourceCategories cannot be disabled.
	// +optional
	AuxiliaryResourceOverrides map[string]bool `json:"auxiliaryResourceOverrides,omitempty"`

	// disabled temporarily disables this binding.
	// Sessions cannot be created using this binding while disabled.
	// +optional
	// +kubebuilder:default=false
	Disabled bool `json:"disabled,omitempty"`

	// notification overrides notification settings from the template.
	// +optional
	Notification *DebugSessionNotificationConfig `json:"notification,omitempty"`

	// requestReason overrides reason requirements from the template.
	// +optional
	RequestReason *DebugRequestReasonConfig `json:"requestReason,omitempty"`

	// approvalReason overrides approval reason requirements from the template.
	// +optional
	ApprovalReason *DebugApprovalReasonConfig `json:"approvalReason,omitempty"`

	// labels are additional labels applied to resources created via this binding.
	// Merged with template labels.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// annotations are additional annotations applied to resources created via this binding.
	// Merged with template annotations.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// priority overrides the template's priority for UI ordering.
	// +optional
	Priority *int32 `json:"priority,omitempty"`

	// hidden hides this binding from the UI but allows API usage.
	// +optional
	// +kubebuilder:default=false
	Hidden bool `json:"hidden,omitempty"`

	// expiresAt optionally sets an expiry time for this binding.
	// After this time, the binding becomes inactive automatically.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// effectiveFrom optionally sets when this binding becomes active.
	// Before this time, the binding cannot be used.
	// +optional
	EffectiveFrom *metav1.Time `json:"effectiveFrom,omitempty"`

	// maxActiveSessionsPerUser limits concurrent sessions per user via this binding.
	// +optional
	// +kubebuilder:validation:Minimum=1
	MaxActiveSessionsPerUser *int32 `json:"maxActiveSessionsPerUser,omitempty"`

	// maxActiveSessionsTotal limits total concurrent sessions via this binding.
	// +optional
	// +kubebuilder:validation:Minimum=1
	MaxActiveSessionsTotal *int32 `json:"maxActiveSessionsTotal,omitempty"`
}

// TemplateReference references a DebugSessionTemplate by name.
type TemplateReference struct {
	// name is the name of the DebugSessionTemplate.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// DebugSessionClusterBindingStatus defines the observed state of DebugSessionClusterBinding.
type DebugSessionClusterBindingStatus struct {
	// conditions represent the latest available observations of the binding's state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the generation last observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// resolvedTemplates lists the templates matched by this binding.
	// +optional
	ResolvedTemplates []ResolvedTemplateRef `json:"resolvedTemplates,omitempty"`

	// resolvedClusters lists the clusters matched by this binding.
	// +optional
	ResolvedClusters []ResolvedClusterRef `json:"resolvedClusters,omitempty"`

	// activeSessionCount is the number of active debug sessions using this binding.
	// +optional
	ActiveSessionCount int32 `json:"activeSessionCount,omitempty"`

	// lastUsed is the timestamp of the last session created using this binding.
	// +optional
	LastUsed *metav1.Time `json:"lastUsed,omitempty"`

	// nameCollisions lists any detected name collisions with other bindings.
	// A collision occurs when the same template+cluster produces the same effective name.
	// +optional
	NameCollisions []NameCollision `json:"nameCollisions,omitempty"`

	// pendingSessionCount is the number of sessions pending approval.
	// +optional
	PendingSessionCount int32 `json:"pendingSessionCount,omitempty"`

	// totalSessionCount is the total number of sessions ever created via this binding.
	// +optional
	TotalSessionCount int64 `json:"totalSessionCount,omitempty"`

	// activeByUser tracks active session counts per user.
	// Key is user email, value is active session count.
	// +optional
	ActiveByUser map[string]int32 `json:"activeByUser,omitempty"`

	// isActive indicates if this binding is currently active (not disabled, not expired, after effectiveFrom).
	// +optional
	IsActive bool `json:"isActive,omitempty"`

	// effectiveDisplayName shows the computed display name for this binding.
	// +optional
	EffectiveDisplayName string `json:"effectiveDisplayName,omitempty"`
}

// ResolvedTemplateRef contains information about a resolved template.
type ResolvedTemplateRef struct {
	// name is the template name.
	Name string `json:"name"`

	// displayName is the effective display name (may include prefix from binding).
	DisplayName string `json:"displayName,omitempty"`

	// ready indicates if the template is ready for use.
	Ready bool `json:"ready,omitempty"`
}

// ResolvedClusterRef contains information about a resolved cluster.
type ResolvedClusterRef struct {
	// name is the cluster name (from ClusterConfig).
	Name string `json:"name"`

	// ready indicates if the cluster is ready/reachable.
	Ready bool `json:"ready,omitempty"`

	// matchedBy indicates how this cluster was matched ("explicit" or "selector").
	MatchedBy string `json:"matchedBy,omitempty"`
}

// NameCollision records a detected name collision with another binding.
type NameCollision struct {
	// templateName is the name of the template involved in the collision.
	TemplateName string `json:"templateName"`

	// clusterName is the name of the cluster involved in the collision.
	ClusterName string `json:"clusterName"`

	// effectiveName is the effective display name that collides.
	EffectiveName string `json:"effectiveName"`

	// collidingBinding is the name of the other binding causing the collision.
	CollidingBinding string `json:"collidingBinding"`

	// collidingBindingNamespace is the namespace of the colliding binding.
	CollidingBindingNamespace string `json:"collidingBindingNamespace,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=dscb;debugbinding
// +kubebuilder:printcolumn:name="Template",type=string,JSONPath=`.spec.templateRef.name`
// +kubebuilder:printcolumn:name="Clusters",type=integer,JSONPath=`.status.resolvedClusters`
// +kubebuilder:printcolumn:name="Active",type=integer,JSONPath=`.status.activeSessionCount`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=='Ready')].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// DebugSessionClusterBinding binds DebugSessionTemplates to specific clusters
// with optional constraint overrides. This is a namespaced resource that enables
// RBAC delegation - teams can manage their own bindings in their namespace.
type DebugSessionClusterBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DebugSessionClusterBindingSpec   `json:"spec,omitempty"`
	Status DebugSessionClusterBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DebugSessionClusterBindingList contains a list of DebugSessionClusterBinding.
type DebugSessionClusterBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DebugSessionClusterBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DebugSessionClusterBinding{}, &DebugSessionClusterBindingList{})
}

// GetConditions returns the binding's conditions.
func (b *DebugSessionClusterBinding) GetConditions() []metav1.Condition {
	return b.Status.Conditions
}

// SetConditions sets the binding's conditions.
func (b *DebugSessionClusterBinding) SetConditions(conditions []metav1.Condition) {
	b.Status.Conditions = conditions
}

// SetCondition sets a condition on the binding.
func (b *DebugSessionClusterBinding) SetCondition(conditionType DebugSessionClusterBindingConditionType, status metav1.ConditionStatus, reason, message string) {
	apimeta.SetStatusCondition(&b.Status.Conditions, metav1.Condition{
		Type:               string(conditionType),
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: b.Generation,
	})
}

// IsReady returns true if the binding is in a ready state.
func (b *DebugSessionClusterBinding) IsReady() bool {
	condition := apimeta.FindStatusCondition(b.Status.Conditions, string(DebugSessionClusterBindingConditionReady))
	return condition != nil && condition.Status == metav1.ConditionTrue
}

// IsDisabled returns true if the binding is disabled.
func (b *DebugSessionClusterBinding) IsDisabled() bool {
	return b.Spec.Disabled
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-debugsessionclusterbinding,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=debugsessionclusterbindings,verbs=create;update,versions=v1alpha1,name=debugsessionclusterbinding.validation.breakglass.t-caas.telekom.com,admissionReviewVersions={v1,v1beta1}

// ValidateCreate implements webhook.CustomValidator for creation.
func (b *DebugSessionClusterBinding) ValidateCreate(ctx context.Context, obj *DebugSessionClusterBinding) (admission.Warnings, error) {
	result := ValidateDebugSessionClusterBinding(obj)

	// Check for name collisions with other bindings
	if result.IsValid() {
		collisions, err := CheckNameCollisions(ctx, obj)
		if err != nil {
			// Log error but don't fail validation - collision check is best-effort
			// The controller will detect and report collisions in status
		} else if len(collisions) > 0 {
			for _, c := range collisions {
				result.Errors = append(result.Errors, field.Invalid(
					field.NewPath("spec"),
					obj.Spec.DisplayName,
					"name collision: template '"+c.TemplateName+"' on cluster '"+c.ClusterName+
						"' would produce the same effective name '"+c.EffectiveName+
						"' as binding '"+c.CollidingBinding+"'",
				))
			}
		}

		// Structural validation of impersonation config
		if impErr := ValidateImpersonationRef(obj.Spec.Impersonation); impErr != nil {
			result.Errors = append(result.Errors, impErr)
		}
	}

	if result.IsValid() {
		return result.Warnings, nil
	}
	return result.Warnings, apierrors.NewInvalid(
		schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "DebugSessionClusterBinding"},
		obj.Name,
		result.Errors,
	)
}

// ValidateUpdate implements webhook.CustomValidator for updates.
func (b *DebugSessionClusterBinding) ValidateUpdate(ctx context.Context, oldObj, newObj *DebugSessionClusterBinding) (admission.Warnings, error) {
	result := ValidateDebugSessionClusterBinding(newObj)

	// Check for name collisions with other bindings
	if result.IsValid() {
		collisions, err := CheckNameCollisions(ctx, newObj)
		if err != nil {
			// Log error but don't fail validation - collision check is best-effort
			// The controller will detect and report collisions in status
		} else if len(collisions) > 0 {
			for _, c := range collisions {
				result.Errors = append(result.Errors, field.Invalid(
					field.NewPath("spec"),
					newObj.Spec.DisplayName,
					"name collision: template '"+c.TemplateName+"' on cluster '"+c.ClusterName+
						"' would produce the same effective name '"+c.EffectiveName+
						"' as binding '"+c.CollidingBinding+"'",
				))
			}
		}

		// Structural validation of impersonation config
		if impErr := ValidateImpersonationRef(newObj.Spec.Impersonation); impErr != nil {
			result.Errors = append(result.Errors, impErr)
		}
	}

	if result.IsValid() {
		return result.Warnings, nil
	}
	return result.Warnings, apierrors.NewInvalid(
		schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "DebugSessionClusterBinding"},
		newObj.Name,
		result.Errors,
	)
}

// ValidateDelete implements webhook.CustomValidator for deletion.
func (b *DebugSessionClusterBinding) ValidateDelete(ctx context.Context, obj *DebugSessionClusterBinding) (admission.Warnings, error) {
	return nil, nil
}

// SetupWebhookWithManager registers webhooks for DebugSessionClusterBinding.
func (b *DebugSessionClusterBinding) SetupWebhookWithManager(mgr ctrl.Manager) error {
	InitWebhookClient(mgr.GetClient(), mgr.GetCache())
	return ctrl.NewWebhookManagedBy(mgr, &DebugSessionClusterBinding{}).
		WithValidator(b).
		Complete()
}

// ValidateDebugSessionClusterBinding validates a DebugSessionClusterBinding.
func ValidateDebugSessionClusterBinding(binding *DebugSessionClusterBinding) *ValidationResult {
	result := &ValidationResult{}
	if binding == nil {
		return result
	}

	specPath := field.NewPath("spec")
	spec := &binding.Spec

	// templateRef and templateSelector are mutually exclusive
	if spec.TemplateRef != nil && spec.TemplateSelector != nil {
		result.Errors = append(result.Errors, field.Invalid(
			specPath.Child("templateRef"),
			spec.TemplateRef.Name,
			"templateRef and templateSelector are mutually exclusive; only one can be specified",
		))
	}

	// At least one of templateRef or templateSelector must be specified
	if spec.TemplateRef == nil && spec.TemplateSelector == nil {
		result.Errors = append(result.Errors, field.Required(
			specPath.Child("templateRef"),
			"either templateRef or templateSelector must be specified",
		))
	}

	// At least one cluster reference method must be specified
	if len(spec.Clusters) == 0 && spec.ClusterSelector == nil {
		result.Errors = append(result.Errors, field.Required(
			specPath.Child("clusters"),
			"either clusters or clusterSelector must be specified",
		))
	}

	// Validate constraints if specified
	if spec.Constraints != nil {
		constraintsPath := specPath.Child("constraints")
		if spec.Constraints.MaxDuration != "" {
			result.Errors = append(result.Errors, validateDurationFormat(spec.Constraints.MaxDuration, constraintsPath.Child("maxDuration"))...)
		}
		if spec.Constraints.DefaultDuration != "" {
			result.Errors = append(result.Errors, validateDurationFormat(spec.Constraints.DefaultDuration, constraintsPath.Child("defaultDuration"))...)
		}
	}

	// Validate schedulingOptions if specified
	if spec.SchedulingOptions != nil {
		result.Errors = append(result.Errors, validateSchedulingOptions(spec.SchedulingOptions, specPath.Child("schedulingOptions"))...)
	}

	// Validate namespaceConstraints if specified
	if spec.NamespaceConstraints != nil {
		result.Errors = append(result.Errors, validateNamespaceConstraints(spec.NamespaceConstraints, specPath.Child("namespaceConstraints"))...)
		// Bindings don't have a targetNamespace field, so pass empty string
		result.Warnings = append(result.Warnings, warnNamespaceConstraintIssues(spec.NamespaceConstraints, "")...)
	}

	// Validate impersonation config if specified
	if spec.Impersonation != nil {
		result.Errors = append(result.Errors, validateImpersonationConfig(spec.Impersonation, specPath.Child("impersonation"))...)
	}

	// Validate notification config if specified
	if spec.Notification != nil {
		result.Errors = append(result.Errors, validateDebugSessionNotificationConfig(spec.Notification, specPath.Child("notification"))...)
	}

	// Validate request reason config if specified
	if spec.RequestReason != nil {
		result.Errors = append(result.Errors, validateDebugRequestReasonConfig(spec.RequestReason, specPath.Child("requestReason"))...)
	}

	// Validate approval reason config if specified
	if spec.ApprovalReason != nil {
		result.Errors = append(result.Errors, validateDebugApprovalReasonConfig(spec.ApprovalReason, specPath.Child("approvalReason"))...)
	}

	// Validate time window (effectiveFrom/expiresAt)
	result.Errors = append(result.Errors, validateBindingTimeWindow(spec.EffectiveFrom, spec.ExpiresAt, specPath)...)

	return result
}

// GetEffectiveDisplayName computes the effective display name for a binding+template combination.
// Priority:
// 1. If binding.displayName is set: use binding.displayName
// 2. If binding.displayNamePrefix is set: use "{prefix} - {template.displayName}"
// 3. Otherwise: use template.displayName (or template.name as fallback)
func GetEffectiveDisplayName(binding *DebugSessionClusterBinding, templateDisplayName, templateName string) string {
	if binding.Spec.DisplayName != "" {
		return binding.Spec.DisplayName
	}
	// Use template's display name or fall back to template name
	effectiveName := templateDisplayName
	if effectiveName == "" {
		effectiveName = templateName
	}
	if binding.Spec.DisplayNamePrefix != "" {
		return binding.Spec.DisplayNamePrefix + " - " + effectiveName
	}
	return effectiveName
}

// CheckNameCollisions checks for name collisions between this binding and other bindings.
// A collision occurs when the same template+cluster produces the same effective display name.
// Returns a list of collisions found.
func CheckNameCollisions(ctx context.Context, binding *DebugSessionClusterBinding) ([]NameCollision, error) {
	client := GetWebhookClient()
	if client == nil {
		// No client available - skip collision check
		return nil, nil
	}

	// List all other bindings
	bindingList := &DebugSessionClusterBindingList{}
	if err := client.List(ctx, bindingList); err != nil {
		return nil, err
	}

	// Get template information for computing effective names
	templateList := &DebugSessionTemplateList{}
	if err := client.List(ctx, templateList); err != nil {
		return nil, err
	}

	// Build template name -> display name map
	templateDisplayNames := make(map[string]string)
	for _, t := range templateList.Items {
		displayName := t.Spec.DisplayName
		if displayName == "" {
			displayName = t.Name
		}
		templateDisplayNames[t.Name] = displayName
	}

	// Get the template names this binding references
	thisTemplateNames := getBindingTemplateNames(binding, templateList.Items)
	thisClusterNames := binding.Spec.Clusters

	var collisions []NameCollision

	for _, other := range bindingList.Items {
		// Skip self
		if other.Name == binding.Name && other.Namespace == binding.Namespace {
			continue
		}

		// Skip disabled bindings
		if other.Spec.Disabled {
			continue
		}

		otherTemplateNames := getBindingTemplateNames(&other, templateList.Items)
		otherClusterNames := other.Spec.Clusters

		// Check for overlapping template+cluster combinations
		for _, thisTemplate := range thisTemplateNames {
			for _, otherTemplate := range otherTemplateNames {
				if thisTemplate != otherTemplate {
					continue
				}

				// Same template - check for cluster overlap
				for _, thisCluster := range thisClusterNames {
					for _, otherCluster := range otherClusterNames {
						if thisCluster != otherCluster {
							continue
						}

						// Same template+cluster - check effective name
						templateDisplayName := templateDisplayNames[thisTemplate]
						thisEffectiveName := GetEffectiveDisplayName(binding, templateDisplayName, thisTemplate)
						otherEffectiveName := GetEffectiveDisplayName(&other, templateDisplayName, otherTemplate)

						if thisEffectiveName == otherEffectiveName {
							collisions = append(collisions, NameCollision{
								TemplateName:              thisTemplate,
								ClusterName:               thisCluster,
								EffectiveName:             thisEffectiveName,
								CollidingBinding:          other.Name,
								CollidingBindingNamespace: other.Namespace,
							})
						}
					}
				}
			}
		}
	}

	return collisions, nil
}

// getBindingTemplateNames returns the template names referenced by a binding.
func getBindingTemplateNames(binding *DebugSessionClusterBinding, templates []DebugSessionTemplate) []string {
	if binding.Spec.TemplateRef != nil {
		return []string{binding.Spec.TemplateRef.Name}
	}

	if binding.Spec.TemplateSelector == nil {
		return nil
	}

	// Match templates by selector
	selector, err := metav1.LabelSelectorAsSelector(binding.Spec.TemplateSelector)
	if err != nil {
		return nil
	}

	var names []string
	for _, t := range templates {
		// Convert labels to Set for matching
		labelset := labels.Set(t.Labels)
		if selector.Matches(labelset) {
			names = append(names, t.Name)
		}
	}

	return names
}

// ValidateImpersonationRef checks if impersonation config references valid SA fields.
// NOTE: This only validates the format/structure of the reference, NOT that the SA exists.
// The ServiceAccount is in the SPOKE cluster, not the hub, so it cannot be validated at webhook time.
// Runtime validation happens in the debug session controller when connecting to spoke clusters.
// Returns an error for structural issues (e.g., missing name/namespace when serviceAccountRef is set).
func ValidateImpersonationRef(imp *ImpersonationConfig) *field.Error {
	if imp == nil || imp.ServiceAccountRef == nil {
		return nil
	}

	// validateImpersonationConfig already validates structural issues
	// No additional hub-side validation possible since SA is in spoke cluster
	return nil
}
