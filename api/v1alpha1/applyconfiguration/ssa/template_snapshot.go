// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ac "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/api/v1alpha1"
)

func SchedulingConstraintsFrom(t *breakglassv1alpha1.SchedulingConstraints) *ac.SchedulingConstraintsApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.SchedulingConstraints()
	if t.RequiredNodeAffinity != nil {
		result.WithRequiredNodeAffinity(*t.RequiredNodeAffinity)
	}
	if t.PreferredNodeAffinity != nil {
		result.WithPreferredNodeAffinity(t.PreferredNodeAffinity...)
	}
	if t.RequiredPodAntiAffinity != nil {
		result.WithRequiredPodAntiAffinity(t.RequiredPodAntiAffinity...)
	}
	if t.PreferredPodAntiAffinity != nil {
		result.WithPreferredPodAntiAffinity(t.PreferredPodAntiAffinity...)
	}
	if t.NodeSelector != nil {
		result.WithNodeSelector(t.NodeSelector)
	}
	if t.Tolerations != nil {
		result.WithTolerations(t.Tolerations...)
	}
	if t.TopologySpreadConstraints != nil {
		result.WithTopologySpreadConstraints(t.TopologySpreadConstraints...)
	}
	if t.DeniedNodes != nil {
		result.WithDeniedNodes(t.DeniedNodes...)
	}
	if t.DeniedNodeLabels != nil {
		result.WithDeniedNodeLabels(t.DeniedNodeLabels)
	}
	return result
}

func SchedulingOptionFrom(t *breakglassv1alpha1.SchedulingOption) *ac.SchedulingOptionApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.SchedulingOption()
	result.WithName(t.Name)
	result.WithDisplayName(t.DisplayName)
	result.WithDescription(t.Description)
	result.WithDefault(t.Default)
	if t.SchedulingConstraints != nil {
		result.WithSchedulingConstraints(SchedulingConstraintsFrom(t.SchedulingConstraints))
	}
	if t.AllowedGroups != nil {
		result.WithAllowedGroups(t.AllowedGroups...)
	}
	if t.AllowedUsers != nil {
		result.WithAllowedUsers(t.AllowedUsers...)
	}
	return result
}

func SchedulingOptionsFrom(t *breakglassv1alpha1.SchedulingOptions) *ac.SchedulingOptionsApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.SchedulingOptions()
	result.WithRequired(t.Required)
	for i := range t.Options {
		result.WithOptions(SchedulingOptionFrom(&t.Options[i]))
	}
	return result
}

func NamespaceConstraintsFrom(t *breakglassv1alpha1.NamespaceConstraints) *ac.NamespaceConstraintsApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.NamespaceConstraints()
	if t.AllowedNamespaces != nil {
		result.WithAllowedNamespaces(NamespaceFilterFrom(t.AllowedNamespaces))
	}
	if t.DeniedNamespaces != nil {
		result.WithDeniedNamespaces(NamespaceFilterFrom(t.DeniedNamespaces))
	}
	result.WithDefaultNamespace(t.DefaultNamespace)
	result.WithAllowUserNamespace(t.AllowUserNamespace)
	result.WithDenyUserNamespace(t.DenyUserNamespace)
	result.WithCreateIfNotExists(t.CreateIfNotExists)
	if t.NamespaceLabels != nil {
		result.WithNamespaceLabels(t.NamespaceLabels)
	}
	return result
}

func ServiceAccountReferenceFrom(t *breakglassv1alpha1.ServiceAccountReference) *ac.ServiceAccountReferenceApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.ServiceAccountReference()
	result.WithName(t.Name)
	result.WithNamespace(t.Namespace)
	return result
}

func ImpersonationConfigFrom(t *breakglassv1alpha1.ImpersonationConfig) *ac.ImpersonationConfigApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.ImpersonationConfig()
	if t.ServiceAccountRef != nil {
		result.WithServiceAccountRef(ServiceAccountReferenceFrom(t.ServiceAccountRef))
	}
	if t.Mode != "" {
		result.WithMode(t.Mode)
	}
	result.WithUserName(t.UserName)
	result.WithUID(t.UID)
	if t.Groups != nil {
		result.WithGroups(t.Groups...)
	}
	if t.Extra != nil {
		result.WithExtra(t.Extra)
	}
	if t.AllowedIdentities != nil {
		result.WithAllowedIdentities(t.AllowedIdentities...)
	}
	if t.ActionVerbs != nil {
		result.WithActionVerbs(t.ActionVerbs...)
	}
	return result
}

func AuxiliaryResourceFrom(t *breakglassv1alpha1.AuxiliaryResource) *ac.AuxiliaryResourceApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.AuxiliaryResource()
	result.WithName(t.Name)
	result.WithDescription(t.Description)
	result.WithCategory(t.Category)
	result.WithTemplateString(t.TemplateString)
	result.WithTemplate(t.Template)
	result.WithCreateBefore(t.CreateBefore)
	result.WithDeleteAfter(t.DeleteAfter)
	if t.FailurePolicy != "" {
		result.WithFailurePolicy(t.FailurePolicy)
	}
	result.WithOptional(t.Optional)
	return result
}

func NotificationExclusionsFrom(t *breakglassv1alpha1.NotificationExclusions) *ac.NotificationExclusionsApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.NotificationExclusions()
	if t.Users != nil {
		result.WithUsers(t.Users...)
	}
	if t.Groups != nil {
		result.WithGroups(t.Groups...)
	}
	return result
}

func DebugSessionNotificationConfigFrom(t *breakglassv1alpha1.DebugSessionNotificationConfig) *ac.DebugSessionNotificationConfigApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.DebugSessionNotificationConfig()
	result.WithEnabled(t.Enabled)
	result.WithNotifyOnRequest(t.NotifyOnRequest)
	result.WithNotifyOnApproval(t.NotifyOnApproval)
	result.WithNotifyOnExpiry(t.NotifyOnExpiry)
	result.WithNotifyOnTermination(t.NotifyOnTermination)
	if t.AdditionalRecipients != nil {
		result.WithAdditionalRecipients(t.AdditionalRecipients...)
	}
	if t.ExcludedRecipients != nil {
		result.WithExcludedRecipients(NotificationExclusionsFrom(t.ExcludedRecipients))
	}
	return result
}

func DebugRequestReasonConfigFrom(t *breakglassv1alpha1.DebugRequestReasonConfig) *ac.DebugRequestReasonConfigApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.DebugRequestReasonConfig()
	result.WithMandatory(t.Mandatory)
	result.WithMinLength(t.MinLength)
	result.WithMaxLength(t.MaxLength)
	result.WithDescription(t.Description)
	if t.SuggestedReasons != nil {
		result.WithSuggestedReasons(t.SuggestedReasons...)
	}
	return result
}

func DebugApprovalReasonConfigFrom(t *breakglassv1alpha1.DebugApprovalReasonConfig) *ac.DebugApprovalReasonConfigApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.DebugApprovalReasonConfig()
	result.WithMandatory(t.Mandatory)
	result.WithMandatoryForRejection(t.MandatoryForRejection)
	result.WithMinLength(t.MinLength)
	result.WithDescription(t.Description)
	return result
}

func DebugResourceQuotaConfigFrom(t *breakglassv1alpha1.DebugResourceQuotaConfig) *ac.DebugResourceQuotaConfigApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.DebugResourceQuotaConfig()
	if t.MaxPods != nil {
		result.WithMaxPods(*t.MaxPods)
	}
	result.WithMaxCPU(t.MaxCPU)
	result.WithMaxMemory(t.MaxMemory)
	result.WithMaxStorage(t.MaxStorage)
	result.WithEnforceResourceRequests(t.EnforceResourceRequests)
	result.WithEnforceResourceLimits(t.EnforceResourceLimits)
	return result
}

func DebugPDBConfigFrom(t *breakglassv1alpha1.DebugPDBConfig) *ac.DebugPDBConfigApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.DebugPDBConfig()
	result.WithEnabled(t.Enabled)
	if t.MinAvailable != nil {
		result.WithMinAvailable(*t.MinAvailable)
	}
	if t.MaxUnavailable != nil {
		result.WithMaxUnavailable(*t.MaxUnavailable)
	}
	return result
}
