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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/yaml"
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
		result.Errors = append(result.Errors, field.Required(specPath.Child("approvers"), "at least one approver (user or group) must be specified"))
	}

	// Validate blockSelfApproval constraints (mirrors CEL rules)
	if escalation.Spec.BlockSelfApproval != nil && *escalation.Spec.BlockSelfApproval {
		if len(escalation.Spec.Approvers.Groups) == 0 {
			result.Errors = append(result.Errors, field.Invalid(
				specPath.Child("blockSelfApproval"), true,
				"blockSelfApproval requires at least one approver group"))
		}
		for _, g := range escalation.Spec.Approvers.Groups {
			if g == escalation.Spec.EscalatedGroup {
				result.Errors = append(result.Errors, field.Invalid(
					specPath.Child("approvers").Child("groups"), g,
					"escalatedGroup cannot be an approver group when blockSelfApproval is enabled"))
			}
		}
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

	// Validate sessionLimitsOverride exclusivity (mirrors CEL rule)
	if escalation.Spec.SessionLimitsOverride != nil && escalation.Spec.SessionLimitsOverride.Unlimited {
		if escalation.Spec.SessionLimitsOverride.MaxActiveSessionsPerUser != nil ||
			escalation.Spec.SessionLimitsOverride.MaxActiveSessionsTotal != nil {
			result.Errors = append(result.Errors, field.Invalid(
				specPath.Child("sessionLimitsOverride").Child("unlimited"), true,
				"unlimited=true is mutually exclusive with maxActiveSessionsPerUser and maxActiveSessionsTotal"))
		}
	}

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

	// Validate idleTimeout if set
	if session.Spec.IdleTimeout != "" {
		idleTimeout, err := ParseDuration(session.Spec.IdleTimeout)
		if err != nil {
			result.Errors = append(result.Errors, field.Invalid(specPath.Child("idleTimeout"), session.Spec.IdleTimeout, fmt.Sprintf("invalid duration: %v", err)))
		} else if idleTimeout <= 0 {
			result.Errors = append(result.Errors, field.Invalid(specPath.Child("idleTimeout"), session.Spec.IdleTimeout, "idleTimeout must be positive"))
		} else if idleTimeout < time.Minute {
			// Minimum 1 minute to avoid premature expiry from the 30s activity flush buffer.
			// Activity is flushed to status every ~30s; shorter idle timeouts would race with the buffer.
			result.Errors = append(result.Errors, field.Invalid(specPath.Child("idleTimeout"), session.Spec.IdleTimeout, "idleTimeout must be at least 1m"))
		} else if session.Spec.MaxValidFor != "" {
			maxValid, mvErr := ParseDuration(session.Spec.MaxValidFor)
			if mvErr == nil && idleTimeout > maxValid {
				result.Errors = append(result.Errors, field.Invalid(specPath.Child("idleTimeout"), session.Spec.IdleTimeout,
					fmt.Sprintf("idleTimeout (%s) must not exceed maxValidFor (%s)", session.Spec.IdleTimeout, session.Spec.MaxValidFor)))
			}
		}
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
			// Validate cacheTTL duration if provided (supports day units like "7d")
			if idp.Spec.Keycloak.CacheTTL != "" {
				if _, err := ParseDuration(idp.Spec.Keycloak.CacheTTL); err != nil {
					result.Errors = append(result.Errors, field.Invalid(keycloakPath.Child("cacheTTL"), idp.Spec.Keycloak.CacheTTL, fmt.Sprintf("invalid duration: %v", err)))
				}
			}
			// Validate requestTimeout duration if provided (supports day units like "7d")
			if idp.Spec.Keycloak.RequestTimeout != "" {
				if _, err := ParseDuration(idp.Spec.Keycloak.RequestTimeout); err != nil {
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

	// Validate at least one rule type is specified (mirrors CEL rule)
	if len(dp.Spec.Rules) == 0 && dp.Spec.PodSecurityRules == nil {
		result.Errors = append(result.Errors, field.Required(specPath, "at least one deny rule or podSecurityRules must be specified"))
	}

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

	// Template and TemplateString are mutually exclusive - one must be specified
	hasTemplate := template.Spec.Template != nil
	hasTemplateString := template.Spec.TemplateString != ""

	if !hasTemplate && !hasTemplateString {
		result.Errors = append(result.Errors, field.Required(specPath, "either template or templateString must be specified"))
		return result
	}

	if hasTemplate && hasTemplateString {
		result.Errors = append(result.Errors, field.Invalid(specPath, "both specified", "template and templateString are mutually exclusive"))
		return result
	}

	// If using templateString, validate its syntax then validate the first document format
	if hasTemplateString {
		if err := validateGoTemplateSyntax(template.Spec.TemplateString); err != nil {
			result.Errors = append(result.Errors, field.Invalid(specPath.Child("templateString"), "",
				fmt.Sprintf("invalid Go template syntax: %v", err)))
		}

		// Validate the first-document format (must be bare PodSpec, Pod, Deployment, or DaemonSet)
		result.Errors = append(result.Errors, validateTemplateStringFormat(template.Spec.TemplateString, specPath.Child("templateString"))...)

		// Dry-run render for templates with Go directives to catch execution issues early
		result.Warnings = append(result.Warnings, tryRenderTemplateString(template.Spec.TemplateString, nil)...)

		return result
	}

	// Validate static template containers are specified
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

	// For workload or hybrid mode, either podTemplateRef or podTemplateString is required
	hasPodTemplateRef := template.Spec.PodTemplateRef != nil
	hasPodTemplateString := template.Spec.PodTemplateString != ""
	if (mode == DebugSessionModeWorkload || mode == DebugSessionModeHybrid) && !hasPodTemplateRef && !hasPodTemplateString {
		result.Errors = append(result.Errors, field.Required(specPath.Child("podTemplateRef"),
			"either podTemplateRef or podTemplateString is required for workload or hybrid mode"))
	}

	// Validate podTemplateString syntax if present
	if hasPodTemplateString {
		if err := validateGoTemplateSyntax(template.Spec.PodTemplateString); err != nil {
			result.Errors = append(result.Errors, field.Invalid(specPath.Child("podTemplateString"), "",
				fmt.Sprintf("invalid Go template syntax: %v", err)))
		}

		// Validate the first-document format (must be bare PodSpec, Pod, Deployment, or DaemonSet)
		result.Errors = append(result.Errors, validateTemplateStringFormat(template.Spec.PodTemplateString, specPath.Child("podTemplateString"))...)

		// Warn if workload kind doesn't match configured workloadType
		if template.Spec.WorkloadType != "" {
			result.Warnings = append(result.Warnings, warnTemplateStringWorkloadMismatch(template.Spec.PodTemplateString, template.Spec.WorkloadType)...)
		}

		// Dry-run render for templates with Go directives.
		// Populate Vars from ExtraDeployVariables defaults if available.
		dryRunVars := map[string]string{}
		for _, v := range template.Spec.ExtraDeployVariables {
			if v.Default != nil {
				// Extract string value from *apiextensionsv1.JSON
				raw := string(v.Default.Raw)
				// JSON strings are quoted, strip quotes for template vars
				if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
					raw = raw[1 : len(raw)-1]
				}
				dryRunVars[v.Name] = raw
			} else {
				// Variable has no default; use placeholder so template doesn't fail
				dryRunVars[v.Name] = "PLACEHOLDER"
			}
		}
		result.Warnings = append(result.Warnings, tryRenderTemplateString(template.Spec.PodTemplateString, dryRunVars)...)
	}

	// Validate podOverridesTemplate syntax if present
	if template.Spec.PodOverridesTemplate != "" {
		if err := validateGoTemplateSyntax(template.Spec.PodOverridesTemplate); err != nil {
			result.Errors = append(result.Errors, field.Invalid(specPath.Child("podOverridesTemplate"), "",
				fmt.Sprintf("invalid Go template syntax: %v", err)))
		}
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

	// Validate schedulingOptions if specified
	if template.Spec.SchedulingOptions != nil {
		result.Errors = append(result.Errors, validateSchedulingOptions(template.Spec.SchedulingOptions, specPath.Child("schedulingOptions"))...)
	}

	// Validate namespaceConstraints if specified
	if template.Spec.NamespaceConstraints != nil {
		result.Errors = append(result.Errors, validateNamespaceConstraints(template.Spec.NamespaceConstraints, specPath.Child("namespaceConstraints"))...)
		result.Warnings = append(result.Warnings, warnNamespaceConstraintIssues(template.Spec.NamespaceConstraints, template.Spec.TargetNamespace)...)
	}

	// Validate impersonation config if specified
	if template.Spec.Impersonation != nil {
		result.Errors = append(result.Errors, validateImpersonationConfig(template.Spec.Impersonation, specPath.Child("impersonation"))...)
	}

	// Validate notification config if specified
	if template.Spec.Notification != nil {
		result.Errors = append(result.Errors, validateDebugSessionNotificationConfig(template.Spec.Notification, specPath.Child("notification"))...)
	}

	// Validate request reason config if specified
	if template.Spec.RequestReason != nil {
		result.Errors = append(result.Errors, validateDebugRequestReasonConfig(template.Spec.RequestReason, specPath.Child("requestReason"))...)
	}

	// Validate approval reason config if specified
	if template.Spec.ApprovalReason != nil {
		result.Errors = append(result.Errors, validateDebugApprovalReasonConfig(template.Spec.ApprovalReason, specPath.Child("approvalReason"))...)
	}

	// Validate resource quota config if specified
	if template.Spec.ResourceQuota != nil {
		result.Errors = append(result.Errors, validateDebugResourceQuotaConfig(template.Spec.ResourceQuota, specPath.Child("resourceQuota"))...)
	}

	// Validate PDB config if specified
	if template.Spec.PodDisruptionBudget != nil {
		result.Errors = append(result.Errors, validateDebugPDBConfig(template.Spec.PodDisruptionBudget, specPath.Child("podDisruptionBudget"))...)
	}

	// Validate gracePeriodBeforeExpiry is a valid duration
	if template.Spec.GracePeriodBeforeExpiry != "" {
		result.Errors = append(result.Errors, validateDurationFormat(template.Spec.GracePeriodBeforeExpiry, specPath.Child("gracePeriodBeforeExpiry"))...)
	}

	// Validate auxiliary resources
	if len(template.Spec.AuxiliaryResources) > 0 {
		result.Errors = append(result.Errors, validateAuxiliaryResources(template.Spec.AuxiliaryResources, specPath.Child("auxiliaryResources"))...)
	}

	// Add deprecation warning if template is deprecated
	if template.Spec.Deprecated {
		msg := "This template is deprecated"
		if template.Spec.DeprecationMessage != "" {
			msg = template.Spec.DeprecationMessage
		}
		result.Warnings = append(result.Warnings, msg)
	}

	return result
}

// ==================== BreakglassSession Validation ====================

// tryRenderTemplateString performs a best-effort dry-run render of a Go template string.
// It builds a sample AuxiliaryResourceContext with placeholder values, executes the template,
// and checks that the rendered output is valid YAML. Returns warnings (never errors) because
// the sample data may not satisfy all template conditions.
// vars provides extra deploy variable defaults to populate .Vars in the context.
func tryRenderTemplateString(templateStr string, vars map[string]string) []string {
	if templateStr == "" || !strings.Contains(templateStr, "{{") {
		return nil // Not a templated string, nothing to dry-run
	}

	// Build sample context matching AuxiliaryResourceContext
	sampleCtx := AuxiliaryResourceContext{
		Session: AuxiliaryResourceSessionContext{
			Name:        "validation-session",
			Namespace:   "breakglass-system",
			Cluster:     "validation-cluster",
			RequestedBy: "user@example.com",
			ApprovedBy:  "approver@example.com",
			Reason:      "validation dry-run",
			ExpiresAt:   time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		},
		Target: AuxiliaryResourceTargetContext{
			Namespace:   "debug-namespace",
			ClusterName: "validation-cluster",
		},
		Labels: map[string]string{
			"app.kubernetes.io/managed-by":          "breakglass",
			"breakglass.t-caas.telekom.com/session": "validation-session",
		},
		Annotations: map[string]string{
			"breakglass.t-caas.telekom.com/cluster": "validation-cluster",
		},
		Template: AuxiliaryResourceTemplateContext{
			Name:        "validation-template",
			DisplayName: "Validation Template",
		},
		Binding: AuxiliaryResourceBindingContext{
			Name:      "validation-binding",
			Namespace: "breakglass-system",
		},
		Vars: map[string]string{},
		Now:  time.Now().Format(time.RFC3339),
	}

	// Populate Vars from provided defaults
	for k, v := range vars {
		sampleCtx.Vars[k] = v
	}

	// Convert to map[string]interface{} to match runtime rendering
	ctxJSON, err := json.Marshal(sampleCtx)
	if err != nil {
		return []string{fmt.Sprintf("dry-run: failed to build sample context: %v", err)}
	}
	var ctxMap map[string]interface{}
	if err := json.Unmarshal(ctxJSON, &ctxMap); err != nil {
		return []string{fmt.Sprintf("dry-run: failed to build sample context: %v", err)}
	}

	// Build function map matching the runtime renderer
	funcMap := sprig.FuncMap()
	funcMap["yamlQuote"] = func(s string) string { return "\"" + s + "\"" }
	funcMap["toYaml"] = func(v interface{}) string { return "" }
	funcMap["fromYaml"] = func(s string) map[string]interface{} { return nil }
	funcMap["resourceQuantity"] = func(s string) string { return s }
	funcMap["truncName"] = func(maxLen int, s string) string {
		if len(s) <= maxLen {
			return s
		}
		return s[:maxLen]
	}
	funcMap["k8sName"] = func(s string) string { return strings.ToLower(s) }
	funcMap["parseQuantity"] = func(s string) interface{} { return s }
	funcMap["formatQuantity"] = func(q interface{}) string { return "" }
	// required must return a placeholder value (not nil) so piped operations succeed
	funcMap["required"] = func(args ...interface{}) (interface{}, error) {
		return "PLACEHOLDER", nil
	}
	funcMap["indent"] = func(spaces int, s string) string {
		if spaces <= 0 {
			return s
		}
		padding := strings.Repeat(" ", spaces)
		return padding + strings.ReplaceAll(s, "\n", "\n"+padding)
	}
	funcMap["nindent"] = func(spaces int, s string) string {
		if spaces <= 0 {
			return "\n" + s
		}
		padding := strings.Repeat(" ", spaces)
		return "\n" + padding + strings.ReplaceAll(s, "\n", "\n"+padding)
	}
	funcMap["yamlSafe"] = func(v interface{}) interface{} { return v }

	// Parse template
	tmpl, err := template.New("dry-run").Funcs(funcMap).Parse(templateStr)
	if err != nil {
		// Parse errors are already caught by validateGoTemplateSyntax
		return nil
	}

	// Execute template with sample context
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctxMap); err != nil {
		return []string{fmt.Sprintf("dry-run render warning: template execution failed with sample data: %v", err)}
	}

	// Validate that each rendered YAML document is valid
	var warnings []string
	rendered := buf.String()
	if strings.TrimSpace(rendered) == "" {
		return nil // Empty output is fine (conditionals may suppress all content)
	}

	documents := yamlDocSeparator.Split(rendered, -1)
	for i, doc := range documents {
		trimmed := strings.TrimSpace(doc)
		if trimmed == "" {
			continue
		}
		var obj map[string]interface{}
		if err := yaml.Unmarshal([]byte(trimmed), &obj); err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"dry-run render warning: document %d produced invalid YAML with sample data: %v", i+1, err))
		}
	}

	return warnings
}

// validateTemplateStringFormat validates the first YAML document in a templateString
// to ensure it uses a supported format: bare PodSpec, Pod, Deployment, or DaemonSet.
// This validation is best-effort because Go templates may produce dynamic content,
// so it only checks templates where the first document can be statically analyzed.
// yamlDocSeparator matches a YAML document separator line (--- optionally followed by whitespace).
// This must match the regex used in the reconciler's renderPodTemplateStringMultiDoc.
var yamlDocSeparator = regexp.MustCompile(`(?m)^---\s*$`)

func validateTemplateStringFormat(templateStr string, fldPath *field.Path) field.ErrorList {
	errs := field.ErrorList{}

	// Split on YAML document separator (--- on its own line) to get the first document.
	// Use the same regex as the reconciler to avoid discrepancies.
	documents := yamlDocSeparator.Split(templateStr, 2)
	firstDoc := strings.TrimSpace(documents[0])
	if firstDoc == "" {
		return errs // empty first doc handled elsewhere
	}

	// Skip format validation if the template uses Go template directives that
	// would make the apiVersion/kind dynamic (e.g., conditional kind selection)
	if strings.Contains(firstDoc, "{{") {
		// Templates with Go directives can't be statically validated for format.
		// The runtime renderer will catch format issues.
		return errs
	}

	// Try to unmarshal as a generic map to check for apiVersion/kind
	var probe map[string]interface{}
	if err := yaml.Unmarshal([]byte(firstDoc), &probe); err != nil {
		// Non-templated YAML that fails to parse should be rejected at admission time.
		errs = append(errs, field.Invalid(fldPath, firstDoc, fmt.Sprintf("invalid YAML in first document: %v", err)))
		return errs
	}

	apiVersion, hasAPIVersion := probe["apiVersion"]
	kind, hasKind := probe["kind"]

	if !hasAPIVersion && !hasKind {
		// Bare PodSpec format — valid
		return errs
	}

	if hasAPIVersion != hasKind {
		errs = append(errs, field.Invalid(fldPath, "",
			"first YAML document has apiVersion but no kind (or vice versa)"))
		return errs
	}

	kindStr, _ := kind.(string)
	apiVersionStr, _ := apiVersion.(string)

	switch kindStr {
	case "Pod":
		if apiVersionStr != "v1" {
			errs = append(errs, field.Invalid(fldPath, apiVersionStr,
				fmt.Sprintf("Pod requires apiVersion v1, got %q", apiVersionStr)))
		}
	case "Deployment", "DaemonSet":
		if apiVersionStr != "apps/v1" {
			errs = append(errs, field.Invalid(fldPath, apiVersionStr,
				fmt.Sprintf("%s requires apiVersion apps/v1, got %q", kindStr, apiVersionStr)))
		}
	default:
		errs = append(errs, field.Invalid(fldPath, kindStr,
			fmt.Sprintf("unsupported kind %q: only bare PodSpec, Pod, Deployment, and DaemonSet are supported", kindStr)))
	}

	return errs
}

// warnTemplateStringWorkloadMismatch checks if a templateString produces a full workload
// (Deployment or DaemonSet) that doesn't match the configured workloadType.
// Returns warnings (not errors) since the runtime will enforce this more strictly.
func warnTemplateStringWorkloadMismatch(templateStr string, workloadType DebugWorkloadType) []string {
	var warnings []string

	// Split to get first document using same regex as reconciler
	documents := yamlDocSeparator.Split(templateStr, 2)
	firstDoc := strings.TrimSpace(documents[0])
	if firstDoc == "" || strings.Contains(firstDoc, "{{") {
		return warnings
	}

	var probe map[string]interface{}
	if err := yaml.Unmarshal([]byte(firstDoc), &probe); err != nil {
		return warnings
	}

	kind, hasKind := probe["kind"]
	if !hasKind {
		return warnings
	}

	kindStr, _ := kind.(string)
	// Only check for Deployment/DaemonSet manifests
	if kindStr != "Deployment" && kindStr != "DaemonSet" {
		return warnings
	}

	if DebugWorkloadType(kindStr) != workloadType {
		warnings = append(warnings, fmt.Sprintf(
			"templateString produces a %s but workloadType is %s: these must match at runtime",
			kindStr, workloadType))
	}

	return warnings
}

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
