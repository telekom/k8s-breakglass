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
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidationResult holds the result of a validation operation.
// This is designed to be used by both webhooks (synchronous) and reconcilers (async).
// The result includes all validation errors, which can be used to:
// - Return an error from a webhook
// - Update status conditions in a reconciler
// - Emit events for validation failures
//
// +kubebuilder:object:generate=false
type ValidationResult struct {
	// Errors contains all validation errors found
	Errors field.ErrorList
	// Warnings contains non-fatal validation warnings
	Warnings []string
}

// IsValid returns true if no errors were found during validation
func (vr *ValidationResult) IsValid() bool {
	return len(vr.Errors) == 0
}

// ErrorMessage returns a human-readable error message combining all errors
func (vr *ValidationResult) ErrorMessage() string {
	if len(vr.Errors) == 0 {
		return ""
	}
	var msgs []string
	for _, e := range vr.Errors {
		msgs = append(msgs, e.Error())
	}
	return strings.Join(msgs, "; ")
}

// AsError returns the validation result as an error if there are errors, nil otherwise
func (vr *ValidationResult) AsError() error {
	if vr.IsValid() {
		return nil
	}
	return fmt.Errorf("validation failed: %s", vr.ErrorMessage())
}

// ==================== BreakglassEscalation Validation ====================

// ValidateBreakglassEscalation performs comprehensive validation on a BreakglassEscalation.
// This function is used by both webhooks and reconcilers to ensure consistent validation.
// It checks:
// - Required fields are present and non-empty
// - Field formats are valid (identifiers, durations, etc.)
// - List fields have no duplicates or empty entries
// - Timeout relationships are valid
// - IDP field combinations are valid
//
// Note: Reference validation (ClusterConfig, IdentityProvider, etc.) should be done
// separately using ValidateBreakglassEscalationRefs which requires a k8s client.
func ValidateBreakglassEscalation(escalation *BreakglassEscalation) *ValidationResult {
	result := &ValidationResult{
		Errors:   field.ErrorList{},
		Warnings: []string{},
	}

	if escalation == nil {
		result.Errors = append(result.Errors, field.Required(field.NewPath(""), "escalation cannot be nil"))
		return result
	}

	specPath := field.NewPath("spec")

	// Validate required fields
	if escalation.Spec.EscalatedGroup == "" {
		result.Errors = append(result.Errors, field.Required(specPath.Child("escalatedGroup"), "escalatedGroup is required"))
	} else {
		result.Errors = append(result.Errors, validateIdentifierFormat(escalation.Spec.EscalatedGroup, specPath.Child("escalatedGroup"))...)
	}

	// Validate allowed section
	allowedGroupsPath := specPath.Child("allowed").Child("groups")
	allowedClustersPath := specPath.Child("allowed").Child("clusters")

	clustersProvided := len(escalation.Spec.Allowed.Clusters) > 0 || len(escalation.Spec.ClusterConfigRefs) > 0
	if len(escalation.Spec.Allowed.Groups) == 0 && !clustersProvided {
		result.Errors = append(result.Errors, field.Required(specPath.Child("allowed"), "either groups or cluster targets (allowed.clusters or clusterConfigRefs) must be specified"))
	}

	// Warn if groups are specified but no cluster targets - escalation won't match cluster-specific requests
	if len(escalation.Spec.Allowed.Groups) > 0 && !clustersProvided {
		result.Warnings = append(result.Warnings,
			"escalation has allowed.groups but no cluster targets (allowed.clusters or clusterConfigRefs); it won't match any cluster-specific session requests - consider adding cluster targets or using '*' glob pattern for global access")
	}

	// Validate allowed groups
	result.Errors = append(result.Errors, validateStringListEntriesNotEmpty(escalation.Spec.Allowed.Groups, allowedGroupsPath)...)
	result.Errors = append(result.Errors, validateStringListNoDuplicates(escalation.Spec.Allowed.Groups, allowedGroupsPath)...)
	for i, grp := range escalation.Spec.Allowed.Groups {
		result.Errors = append(result.Errors, validateIdentifierFormat(grp, allowedGroupsPath.Index(i))...)
	}

	// Validate allowed clusters
	result.Errors = append(result.Errors, validateStringListEntriesNotEmpty(escalation.Spec.Allowed.Clusters, allowedClustersPath)...)
	result.Errors = append(result.Errors, validateStringListNoDuplicates(escalation.Spec.Allowed.Clusters, allowedClustersPath)...)
	for i, cluster := range escalation.Spec.Allowed.Clusters {
		result.Errors = append(result.Errors, validateIdentifierFormat(cluster, allowedClustersPath.Index(i))...)
	}

	// Validate approvers
	approverGroupsPath := specPath.Child("approvers").Child("groups")
	approverUsersPath := specPath.Child("approvers").Child("users")

	if len(escalation.Spec.Approvers.Groups) == 0 && len(escalation.Spec.Approvers.Users) == 0 {
		result.Errors = append(result.Errors, field.Required(specPath.Child("approvers"), "either users or groups must be specified as approvers"))
	}

	result.Errors = append(result.Errors, validateStringListEntriesNotEmpty(escalation.Spec.Approvers.Groups, approverGroupsPath)...)
	result.Errors = append(result.Errors, validateStringListNoDuplicates(escalation.Spec.Approvers.Groups, approverGroupsPath)...)
	for i, grp := range escalation.Spec.Approvers.Groups {
		result.Errors = append(result.Errors, validateIdentifierFormat(grp, approverGroupsPath.Index(i))...)
	}

	result.Errors = append(result.Errors, validateStringListEntriesNotEmpty(escalation.Spec.Approvers.Users, approverUsersPath)...)
	result.Errors = append(result.Errors, validateStringListNoDuplicates(escalation.Spec.Approvers.Users, approverUsersPath)...)
	for i, user := range escalation.Spec.Approvers.Users {
		result.Errors = append(result.Errors, validateIdentifierFormat(user, approverUsersPath.Index(i))...)
	}

	// Validate additional list fields
	result.Errors = append(result.Errors, validateBreakglassEscalationAdditionalLists(&escalation.Spec, specPath)...)

	// Validate email domains
	if len(escalation.Spec.AllowedApproverDomains) > 0 {
		result.Errors = append(result.Errors, validateEmailDomainList(escalation.Spec.AllowedApproverDomains, specPath.Child("allowedApproverDomains"))...)
	}

	// Validate optional mail provider reference format
	result.Errors = append(result.Errors, validateIdentifierFormat(escalation.Spec.MailProvider, specPath.Child("mailProvider"))...)

	// Validate timeout relationships
	result.Errors = append(result.Errors, validateTimeoutRelationships(&escalation.Spec, specPath)...)

	// Multi-IDP validations
	result.Errors = append(result.Errors, validateIdentityProviderRefsFormat(escalation.Spec.AllowedIdentityProviders, specPath.Child("allowedIdentityProviders"))...)
	result.Errors = append(result.Errors, validateIDPFieldCombinations(&escalation.Spec, specPath)...)
	result.Errors = append(result.Errors, validateIdentityProviderRefsFormat(escalation.Spec.AllowedIdentityProvidersForRequests, specPath.Child("allowedIdentityProvidersForRequests"))...)
	result.Errors = append(result.Errors, validateIdentityProviderRefsFormat(escalation.Spec.AllowedIdentityProvidersForApprovers, specPath.Child("allowedIdentityProvidersForApprovers"))...)

	return result
}

// ==================== BreakglassSession Validation ====================

// ValidateBreakglassSession performs comprehensive validation on a BreakglassSession.
// This function is used by both webhooks and reconcilers to ensure consistent validation.
// It checks:
// - Required fields are present and non-empty (cluster, user, grantedGroup)
// - ScheduledStartTime is valid (if provided)
//
// Note: IDP validation and authorization checks should be done separately using
// ValidateBreakglassSessionWithContext which requires a k8s client.
func ValidateBreakglassSession(session *BreakglassSession) *ValidationResult {
	result := &ValidationResult{
		Errors:   field.ErrorList{},
		Warnings: []string{},
	}

	if session == nil {
		result.Errors = append(result.Errors, field.Required(field.NewPath(""), "session cannot be nil"))
		return result
	}

	specPath := field.NewPath("spec")

	// Validate required fields
	if session.Spec.Cluster == "" {
		result.Errors = append(result.Errors, field.Required(specPath.Child("cluster"), "cluster is required"))
	}
	if session.Spec.User == "" {
		result.Errors = append(result.Errors, field.Required(specPath.Child("user"), "user is required"))
	}
	if session.Spec.GrantedGroup == "" {
		result.Errors = append(result.Errors, field.Required(specPath.Child("grantedGroup"), "grantedGroup is required"))
	}

	return result
}

// ValidateBreakglassSessionWithContext performs validation that requires a k8s client.
// This includes IDP field validation and session authorization checks.
func ValidateBreakglassSessionWithContext(ctx context.Context, session *BreakglassSession) *ValidationResult {
	// Start with basic validation
	result := ValidateBreakglassSession(session)
	if session == nil {
		return result
	}

	specPath := field.NewPath("spec")

	// Validate IDP tracking fields
	result.Errors = append(result.Errors, validateIdentityProviderFields(
		ctx,
		session.Spec.IdentityProviderName,
		session.Spec.IdentityProviderIssuer,
		specPath.Child("identityProviderName"),
		specPath.Child("identityProviderIssuer"),
	)...)

	// Validate IDP is allowed by matching escalation
	result.Errors = append(result.Errors, validateSessionIdentityProviderAuthorization(
		ctx,
		session.Spec.Cluster,
		session.Spec.GrantedGroup,
		session.Spec.IdentityProviderName,
		specPath.Child("identityProviderName"),
	)...)

	return result
}

// ==================== IdentityProvider Validation ====================

// ValidateIdentityProvider performs comprehensive validation on an IdentityProvider.
// This function is used by both webhooks and reconcilers to ensure consistent validation.
func ValidateIdentityProvider(idp *IdentityProvider) *ValidationResult {
	result := &ValidationResult{
		Errors:   field.ErrorList{},
		Warnings: []string{},
	}

	if idp == nil {
		result.Errors = append(result.Errors, field.Required(field.NewPath(""), "identityProvider cannot be nil"))
		return result
	}

	specPath := field.NewPath("spec")
	oidcPath := specPath.Child("oidc")

	// Validate required OIDC fields
	if idp.Spec.OIDC.Authority == "" {
		result.Errors = append(result.Errors, field.Required(oidcPath.Child("authority"), "OIDC authority is required"))
	} else {
		result.Errors = append(result.Errors, validateURLFormat(idp.Spec.OIDC.Authority, oidcPath.Child("authority"))...)
		result.Errors = append(result.Errors, validateHTTPSURL(idp.Spec.OIDC.Authority, oidcPath.Child("authority"))...)
	}

	if idp.Spec.OIDC.ClientID == "" {
		result.Errors = append(result.Errors, field.Required(oidcPath.Child("clientID"), "OIDC clientID is required"))
	} else {
		// Validate clientID format (should not contain spaces or special chars)
		result.Errors = append(result.Errors, validateIdentifierFormat(idp.Spec.OIDC.ClientID, oidcPath.Child("clientID"))...)
	}

	// Validate JWKS endpoint if provided
	if idp.Spec.OIDC.JWKSEndpoint != "" {
		jwksPath := oidcPath.Child("jwksEndpoint")
		result.Errors = append(result.Errors, validateURLFormat(idp.Spec.OIDC.JWKSEndpoint, jwksPath)...)
		result.Errors = append(result.Errors, validateHTTPSURL(idp.Spec.OIDC.JWKSEndpoint, jwksPath)...)
	}

	// Validate optional issuer field
	if idp.Spec.Issuer != "" {
		issuerPath := specPath.Child("issuer")
		result.Errors = append(result.Errors, validateURLFormat(idp.Spec.Issuer, issuerPath)...)
		result.Errors = append(result.Errors, validateHTTPSURL(idp.Spec.Issuer, issuerPath)...)
	}

	// Validate Keycloak config if groupSyncProvider is Keycloak
	if idp.Spec.GroupSyncProvider == GroupSyncProviderKeycloak {
		if idp.Spec.Keycloak == nil {
			result.Errors = append(result.Errors, field.Required(specPath.Child("keycloak"), "keycloak configuration is required when groupSyncProvider is Keycloak"))
		} else {
			keycloakPath := specPath.Child("keycloak")
			if idp.Spec.Keycloak.BaseURL == "" {
				result.Errors = append(result.Errors, field.Required(keycloakPath.Child("baseURL"), "keycloak baseURL is required"))
			} else {
				result.Errors = append(result.Errors, validateURLFormat(idp.Spec.Keycloak.BaseURL, keycloakPath.Child("baseURL"))...)
				result.Errors = append(result.Errors, validateHTTPSURL(idp.Spec.Keycloak.BaseURL, keycloakPath.Child("baseURL"))...)
			}
			if idp.Spec.Keycloak.Realm == "" {
				result.Errors = append(result.Errors, field.Required(keycloakPath.Child("realm"), "keycloak realm is required"))
			} else {
				result.Errors = append(result.Errors, validateIdentifierFormat(idp.Spec.Keycloak.Realm, keycloakPath.Child("realm"))...)
			}
			if idp.Spec.Keycloak.ClientID == "" {
				result.Errors = append(result.Errors, field.Required(keycloakPath.Child("clientID"), "keycloak clientID is required"))
			} else {
				result.Errors = append(result.Errors, validateIdentifierFormat(idp.Spec.Keycloak.ClientID, keycloakPath.Child("clientID"))...)
			}
			// Validate clientSecretRef is complete when Keycloak is configured
			secretRefPath := keycloakPath.Child("clientSecretRef")
			if idp.Spec.Keycloak.ClientSecretRef.Name == "" {
				result.Errors = append(result.Errors, field.Required(secretRefPath.Child("name"), "secret name is required"))
			}
			if idp.Spec.Keycloak.ClientSecretRef.Namespace == "" {
				result.Errors = append(result.Errors, field.Required(secretRefPath.Child("namespace"), "secret namespace is required"))
			}
			// Validate cacheTTL duration if provided
			if idp.Spec.Keycloak.CacheTTL != "" {
				if _, err := time.ParseDuration(idp.Spec.Keycloak.CacheTTL); err != nil {
					result.Errors = append(result.Errors, field.Invalid(keycloakPath.Child("cacheTTL"), idp.Spec.Keycloak.CacheTTL, fmt.Sprintf("invalid duration: %v", err)))
				}
			}
			// Validate requestTimeout duration if provided
			if idp.Spec.Keycloak.RequestTimeout != "" {
				if _, err := time.ParseDuration(idp.Spec.Keycloak.RequestTimeout); err != nil {
					result.Errors = append(result.Errors, field.Invalid(keycloakPath.Child("requestTimeout"), idp.Spec.Keycloak.RequestTimeout, fmt.Sprintf("invalid duration: %v", err)))
				}
			}
		}
	} else if idp.Spec.Keycloak != nil {
		result.Errors = append(result.Errors, field.Invalid(specPath.Child("keycloak"), idp.Spec.Keycloak, "groupSyncProvider must be set to 'Keycloak' when keycloak configuration is provided"))
	}

	return result
}

// ==================== ClusterConfig Validation ====================

// ValidateClusterConfig performs comprehensive validation on a ClusterConfig.
// This function is used by both webhooks and reconcilers to ensure consistent validation.
func ValidateClusterConfig(cc *ClusterConfig) *ValidationResult {
	result := &ValidationResult{
		Errors:   field.ErrorList{},
		Warnings: []string{},
	}

	if cc == nil {
		result.Errors = append(result.Errors, field.Required(field.NewPath(""), "clusterConfig cannot be nil"))
		return result
	}

	specPath := field.NewPath("spec")

	// Validate auth config (includes kubeconfigSecretRef or OIDC)
	result.Errors = append(result.Errors, validateClusterAuthConfig(cc.Spec, specPath)...)

	// Validate QPS/Burst if specified
	if cc.Spec.QPS != nil && *cc.Spec.QPS < 1 {
		result.Errors = append(result.Errors, field.Invalid(specPath.Child("qps"), *cc.Spec.QPS, "qps must be at least 1"))
	}
	if cc.Spec.Burst != nil && *cc.Spec.Burst < 1 {
		result.Errors = append(result.Errors, field.Invalid(specPath.Child("burst"), *cc.Spec.Burst, "burst must be at least 1"))
	}

	// Validate IdentityProviderRefs format
	result.Errors = append(result.Errors, validateIdentityProviderRefsFormat(cc.Spec.IdentityProviderRefs, specPath.Child("identityProviderRefs"))...)

	// Validate approver domains format and duplicates
	result.Errors = append(result.Errors, validateEmailDomainList(cc.Spec.AllowedApproverDomains, specPath.Child("allowedApproverDomains"))...)

	// Validate optional mail provider reference format
	result.Errors = append(result.Errors, validateIdentifierFormat(cc.Spec.MailProvider, specPath.Child("mailProvider"))...)

	return result
}

// ==================== DenyPolicy Validation ====================

// ValidateDenyPolicy performs comprehensive validation on a DenyPolicy.
// This function is used by both webhooks and reconcilers to ensure consistent validation.
func ValidateDenyPolicy(dp *DenyPolicy) *ValidationResult {
	result := &ValidationResult{
		Errors:   field.ErrorList{},
		Warnings: []string{},
	}

	if dp == nil {
		result.Errors = append(result.Errors, field.Required(field.NewPath(""), "denyPolicy cannot be nil"))
		return result
	}

	specPath := field.NewPath("spec")

	// Validate rules
	for i, rule := range dp.Spec.Rules {
		rulePath := specPath.Child("rules").Index(i)
		if len(rule.Verbs) == 0 {
			result.Errors = append(result.Errors, field.Required(rulePath.Child("verbs"), "verbs are required"))
		}
		if len(rule.APIGroups) == 0 {
			result.Errors = append(result.Errors, field.Required(rulePath.Child("apiGroups"), "apiGroups are required"))
		}
		if len(rule.Resources) == 0 {
			result.Errors = append(result.Errors, field.Required(rulePath.Child("resources"), "resources are required"))
		}
	}

	if dp.Spec.Precedence != nil && *dp.Spec.Precedence < 0 {
		result.Errors = append(result.Errors, field.Invalid(specPath.Child("precedence"), *dp.Spec.Precedence, "precedence must be non-negative"))
	}

	// Validate podSecurityRules thresholds if specified
	if dp.Spec.PodSecurityRules != nil {
		for i, threshold := range dp.Spec.PodSecurityRules.Thresholds {
			thresholdPath := specPath.Child("podSecurityRules").Child("thresholds").Index(i)
			if threshold.MaxScore < 0 {
				result.Errors = append(result.Errors, field.Invalid(thresholdPath.Child("maxScore"), threshold.MaxScore, "maxScore must be non-negative"))
			}
		}
	}

	return result
}

// ==================== MailProvider Validation ====================

// ValidateMailProvider performs comprehensive validation on a MailProvider.
// This function is used by both webhooks and reconcilers to ensure consistent validation.
func ValidateMailProvider(mp *MailProvider) *ValidationResult {
	result := &ValidationResult{
		Errors:   field.ErrorList{},
		Warnings: []string{},
	}

	if mp == nil {
		result.Errors = append(result.Errors, field.Required(field.NewPath(""), "mailProvider cannot be nil"))
		return result
	}

	specPath := field.NewPath("spec")
	smtpPath := specPath.Child("smtp")
	senderPath := specPath.Child("sender")

	// Validate SMTP config
	if mp.Spec.SMTP.Host == "" {
		result.Errors = append(result.Errors, field.Required(smtpPath.Child("host"), "SMTP host is required"))
	}
	if mp.Spec.SMTP.Port < 1 || mp.Spec.SMTP.Port > 65535 {
		result.Errors = append(result.Errors, field.Invalid(smtpPath.Child("port"), mp.Spec.SMTP.Port, "port must be between 1 and 65535"))
	}

	// Validate sender config
	if mp.Spec.Sender.Address == "" {
		result.Errors = append(result.Errors, field.Required(senderPath.Child("address"), "sender address is required"))
	}

	return result
}

// ==================== AuditConfig Validation ====================

// ValidateAuditConfig performs comprehensive validation on an AuditConfig.
// This function is used by both webhooks and reconcilers to ensure consistent validation.
func ValidateAuditConfig(ac *AuditConfig) *ValidationResult {
	result := &ValidationResult{
		Errors:   field.ErrorList{},
		Warnings: []string{},
	}

	if ac == nil {
		result.Errors = append(result.Errors, field.Required(field.NewPath(""), "auditConfig cannot be nil"))
		return result
	}

	specPath := field.NewPath("spec")

	// Validate at least one sink is configured
	if len(ac.Spec.Sinks) == 0 {
		result.Errors = append(result.Errors, field.Required(specPath.Child("sinks"), "at least one audit sink must be configured"))
	}

	// Track sink names for duplicate detection
	seenNames := make(map[string]bool)

	// Validate each sink
	sinksPath := specPath.Child("sinks")
	for i, sink := range ac.Spec.Sinks {
		sinkPath := sinksPath.Index(i)
		if sink.Type == "" {
			result.Errors = append(result.Errors, field.Required(sinkPath.Child("type"), "sink type is required"))
		}
		if sink.Name == "" {
			result.Errors = append(result.Errors, field.Required(sinkPath.Child("name"), "sink name is required"))
		} else {
			// Check for duplicate sink names
			if seenNames[sink.Name] {
				result.Errors = append(result.Errors, field.Duplicate(sinkPath.Child("name"), sink.Name))
			}
			seenNames[sink.Name] = true
		}

		// Validate sink-specific configuration based on type
		switch sink.Type {
		case AuditSinkTypeKafka:
			result.Errors = append(result.Errors, validateKafkaSink(sink.Kafka, sinkPath)...)
		case AuditSinkTypeWebhook:
			result.Errors = append(result.Errors, validateWebhookSink(sink.Webhook, sinkPath)...)
		case AuditSinkTypeLog:
			result.Errors = append(result.Errors, validateLogSink(sink.Log, sinkPath)...)
		case AuditSinkTypeKubernetes:
			// KubernetesSink has no required fields, all optional
		}
	}

	return result
}

// validateKafkaSink validates Kafka sink configuration
func validateKafkaSink(kafka *KafkaSinkSpec, sinkPath *field.Path) field.ErrorList {
	var errs field.ErrorList
	kafkaPath := sinkPath.Child("kafka")

	if kafka == nil {
		errs = append(errs, field.Required(kafkaPath, "kafka configuration is required when type is 'kafka'"))
		return errs
	}

	// Required fields
	if len(kafka.Brokers) == 0 {
		errs = append(errs, field.Required(kafkaPath.Child("brokers"), "at least one broker must be specified"))
	}
	if kafka.Topic == "" {
		errs = append(errs, field.Required(kafkaPath.Child("topic"), "topic is required"))
	}

	// SASL validation - if mechanism is set, credentials must be provided
	if kafka.SASL != nil {
		saslPath := kafkaPath.Child("sasl")
		if kafka.SASL.Mechanism == "" {
			errs = append(errs, field.Required(saslPath.Child("mechanism"), "SASL mechanism is required when SASL is configured"))
		}
		if kafka.SASL.CredentialsSecretRef.Name == "" {
			errs = append(errs, field.Required(saslPath.Child("credentialsSecretRef", "name"), "credentials secret name is required for SASL"))
		}
		if kafka.SASL.CredentialsSecretRef.Namespace == "" {
			errs = append(errs, field.Required(saslPath.Child("credentialsSecretRef", "namespace"), "credentials secret namespace is required for SASL"))
		}
	}

	return errs
}

// validateWebhookSink validates webhook sink configuration
func validateWebhookSink(webhook *WebhookSinkSpec, sinkPath *field.Path) field.ErrorList {
	var errs field.ErrorList
	webhookPath := sinkPath.Child("webhook")

	if webhook == nil {
		errs = append(errs, field.Required(webhookPath, "webhook configuration is required when type is 'webhook'"))
		return errs
	}

	// Required fields
	if webhook.URL == "" {
		errs = append(errs, field.Required(webhookPath.Child("url"), "URL is required for webhook sink"))
	}

	// Validate secret ref if provided
	if webhook.AuthSecretRef != nil {
		authPath := webhookPath.Child("authSecretRef")
		if webhook.AuthSecretRef.Name == "" {
			errs = append(errs, field.Required(authPath.Child("name"), "secret name is required when authSecretRef is specified"))
		}
		if webhook.AuthSecretRef.Namespace == "" {
			errs = append(errs, field.Required(authPath.Child("namespace"), "secret namespace is required when authSecretRef is specified"))
		}
	}

	// Validate TLS secret ref if provided
	if webhook.TLS != nil && webhook.TLS.CASecretRef != nil {
		tlsPath := webhookPath.Child("tls", "caSecretRef")
		if webhook.TLS.CASecretRef.Name == "" {
			errs = append(errs, field.Required(tlsPath.Child("name"), "CA secret name is required when caSecretRef is specified"))
		}
		if webhook.TLS.CASecretRef.Namespace == "" {
			errs = append(errs, field.Required(tlsPath.Child("namespace"), "CA secret namespace is required when caSecretRef is specified"))
		}
	}

	return errs
}

// validateLogSink validates log sink configuration (all fields are optional with defaults)
func validateLogSink(log *LogSinkSpec, sinkPath *field.Path) field.ErrorList {
	// LogSinkSpec has all optional fields with kubebuilder defaults, no validation needed
	return nil
}

// ==================== DebugSession Validation ====================

// ValidateDebugSession performs comprehensive validation on a DebugSession.
// This function is used by both webhooks and reconcilers to ensure consistent validation.
// It checks:
// - Required fields are present and non-empty
// - Field formats are valid
func ValidateDebugSession(ds *DebugSession) *ValidationResult {
	result := &ValidationResult{
		Errors:   field.ErrorList{},
		Warnings: []string{},
	}

	if ds == nil {
		result.Errors = append(result.Errors, field.Required(field.NewPath(""), "debugSession cannot be nil"))
		return result
	}

	specPath := field.NewPath("spec")

	// Validate required fields
	if ds.Spec.Cluster == "" {
		result.Errors = append(result.Errors, field.Required(specPath.Child("cluster"), "cluster is required"))
	}

	if ds.Spec.TemplateRef == "" {
		result.Errors = append(result.Errors, field.Required(specPath.Child("templateRef"), "templateRef is required"))
	}

	if ds.Spec.RequestedBy == "" {
		result.Errors = append(result.Errors, field.Required(specPath.Child("requestedBy"), "requestedBy is required"))
	}

	// Validate duration format if specified
	if ds.Spec.RequestedDuration != "" {
		result.Errors = append(result.Errors, validateDurationFormat(ds.Spec.RequestedDuration, specPath.Child("requestedDuration"))...)
	}

	return result
}

// ==================== DebugPodTemplate Validation ====================

// ValidateDebugPodTemplate performs comprehensive validation on a DebugPodTemplate.
// This function is used by both webhooks and reconcilers to ensure consistent validation.
func ValidateDebugPodTemplate(template *DebugPodTemplate) *ValidationResult {
	result := &ValidationResult{
		Errors:   field.ErrorList{},
		Warnings: []string{},
	}

	if template == nil {
		result.Errors = append(result.Errors, field.Required(field.NewPath(""), "debugPodTemplate cannot be nil"))
		return result
	}

	specPath := field.NewPath("spec")

	// Validate containers are specified
	if len(template.Spec.Template.Spec.Containers) == 0 {
		result.Errors = append(result.Errors, field.Required(specPath.Child("template").Child("spec").Child("containers"), "at least one container is required"))
	}

	// Validate container names are unique
	containerNames := make(map[string]bool)
	for i, c := range template.Spec.Template.Spec.Containers {
		containerPath := specPath.Child("template").Child("spec").Child("containers").Index(i)
		if c.Name == "" {
			result.Errors = append(result.Errors, field.Required(containerPath.Child("name"), "container name is required"))
		} else if containerNames[c.Name] {
			result.Errors = append(result.Errors, field.Duplicate(containerPath.Child("name"), c.Name))
		} else {
			containerNames[c.Name] = true
		}
	}

	return result
}

// ==================== DebugSessionTemplate Validation ====================

// ValidateDebugSessionTemplate performs comprehensive validation on a DebugSessionTemplate.
// This function is used by both webhooks and reconcilers to ensure consistent validation.
func ValidateDebugSessionTemplate(template *DebugSessionTemplate) *ValidationResult {
	result := &ValidationResult{
		Errors:   field.ErrorList{},
		Warnings: []string{},
	}

	if template == nil {
		result.Errors = append(result.Errors, field.Required(field.NewPath(""), "debugSessionTemplate cannot be nil"))
		return result
	}

	specPath := field.NewPath("spec")

	// Validate mode-dependent requirements
	mode := template.Spec.Mode
	if mode == "" {
		mode = DebugSessionModeWorkload // default
	}

	// For workload or hybrid mode, podTemplateRef is required
	if (mode == DebugSessionModeWorkload || mode == DebugSessionModeHybrid) && template.Spec.PodTemplateRef == nil {
		result.Errors = append(result.Errors, field.Required(specPath.Child("podTemplateRef"), "podTemplateRef is required for workload or hybrid mode"))
	}

	// For kubectl-debug or hybrid mode, kubectlDebug config is required
	if (mode == DebugSessionModeKubectlDebug || mode == DebugSessionModeHybrid) && template.Spec.KubectlDebug == nil {
		result.Errors = append(result.Errors, field.Required(specPath.Child("kubectlDebug"), "kubectlDebug is required for kubectl-debug or hybrid mode"))
	}

	// Validate constraints if specified
	if template.Spec.Constraints != nil {
		if template.Spec.Constraints.MaxDuration != "" {
			result.Errors = append(result.Errors, validateDurationFormat(template.Spec.Constraints.MaxDuration, specPath.Child("constraints").Child("maxDuration"))...)
		}
		if template.Spec.Constraints.DefaultDuration != "" {
			result.Errors = append(result.Errors, validateDurationFormat(template.Spec.Constraints.DefaultDuration, specPath.Child("constraints").Child("defaultDuration"))...)
		}
	}

	return result
}

// ==================== BreakglassSession Validation ====================

// ValidateBreakglassSessionForReconciler performs validation on a BreakglassSession
// for use in reconcilers. This catches malformed resources that bypassed the webhook.
// It validates structural integrity, not reference validity.
func ValidateBreakglassSessionForReconciler(session *BreakglassSession) *ValidationResult {
	result := &ValidationResult{
		Errors:   field.ErrorList{},
		Warnings: []string{},
	}

	if session == nil {
		result.Errors = append(result.Errors, field.Required(field.NewPath(""), "session cannot be nil"))
		return result
	}

	specPath := field.NewPath("spec")

	// Validate required fields
	if session.Spec.Cluster == "" {
		result.Errors = append(result.Errors, field.Required(specPath.Child("cluster"), "cluster is required"))
	}

	if session.Spec.User == "" {
		result.Errors = append(result.Errors, field.Required(specPath.Child("user"), "user is required"))
	}

	if session.Spec.GrantedGroup == "" {
		result.Errors = append(result.Errors, field.Required(specPath.Child("grantedGroup"), "grantedGroup is required"))
	}

	return result
}

// ==================== Condition Constants ====================

// ValidationConditionType is the condition type used to indicate validation status
const ValidationConditionType = "Validated"

// ValidationConditionReasons provides standard reasons for validation conditions
var ValidationConditionReasons = struct {
	Valid             string
	Invalid           string
	MissingFields     string
	MalformedResource string
}{
	Valid:             "ValidationPassed",
	Invalid:           "ValidationFailed",
	MissingFields:     "MissingRequiredFields",
	MalformedResource: "MalformedResource",
}
