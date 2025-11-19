package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// getWebhookReader returns the preferred client.Reader for webhook validations.
// It prioritizes the shared cache when available to minimize API calls.
func getWebhookReader() client.Reader {
	if webhookCache != nil {
		return webhookCache
	}
	return webhookClient
}

// ensureClusterWideUniqueName enforces cluster-wide name uniqueness by checking
// whether another object with the same name exists in a different namespace.
// list should be an empty typed list (e.g., &BreakglassSessionList{}).
func ensureClusterWideUniqueName(
	ctx context.Context,
	list client.ObjectList,
	namespace, name string,
	path *field.Path,
) field.ErrorList {
	reader := getWebhookReader()
	if reader == nil || list == nil || path == nil || name == "" {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if err := listObjectsByName(ctx, reader, list, name); err != nil {
		return field.ErrorList{field.InternalError(path, err)}
	}

	var errs field.ErrorList
	stopErr := errors.New("cluster name conflict detected")
	if err := meta.EachListItem(list, func(obj runtime.Object) error {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return err
		}
		if accessor.GetName() != name {
			return nil
		}
		if accessor.GetNamespace() == namespace {
			return nil
		}
		msg := fmt.Sprintf("name must be unique cluster-wide; conflicting namespace=%s", accessor.GetNamespace())
		errs = append(errs, field.Duplicate(path, msg))
		return stopErr
	}); err != nil && !errors.Is(err, stopErr) {
		errs = append(errs, field.InternalError(path, err))
	}

	return errs
}

// listObjectsByName attempts to narrow the query using a metadata.name field
// selector. When the underlying cache does not have the index, it falls back to
// a full list.
func listObjectsByName(ctx context.Context, reader client.Reader, list client.ObjectList, name string) error {
	if name == "" {
		return nil
	}

	if err := reader.List(ctx, list, client.MatchingFields{"metadata.name": name}); err != nil {
		if fallbackErr := reader.List(ctx, list); fallbackErr != nil {
			return fmt.Errorf("list by name for %T failed: %v; fallback list failed: %w", list, err, fallbackErr)
		}
	}

	return nil
}

// ensureClusterWideUniqueIssuer enforces cluster-wide issuer uniqueness for IdentityProviders.
// It validates that the Issuer field is unique and no other IdentityProvider uses the same issuer.
func ensureClusterWideUniqueIssuer(
	ctx context.Context,
	issuer string,
	currentName string,
	path *field.Path,
) field.ErrorList {
	if issuer == "" {
		return nil
	}

	// Validate issuer is a valid URL format
	if _, err := url.Parse(issuer); err != nil {
		return field.ErrorList{field.Invalid(path, issuer, "issuer must be a valid URL")}
	}

	reader := getWebhookReader()
	if reader == nil || path == nil {
		return nil
	}

	// Use provided context, or TODO context if nil (explicit workaround marker)
	// This indicates validation is being called outside proper request context
	if ctx == nil {
		ctx = context.TODO()
	}

	// List all IdentityProviders and check for issuer conflicts
	list := &IdentityProviderList{}
	if err := reader.List(ctx, list); err != nil {
		return field.ErrorList{field.InternalError(path, err)}
	}

	var errs field.ErrorList
	if err := meta.EachListItem(list, func(obj runtime.Object) error {
		idp, ok := obj.(*IdentityProvider)
		if !ok {
			return nil
		}
		// Skip self
		if idp.Name == currentName {
			return nil
		}
		// Check for issuer conflict
		if idp.Spec.Issuer != "" && idp.Spec.Issuer == issuer {
			msg := fmt.Sprintf("issuer must be unique cluster-wide; conflicting IdentityProvider=%s", idp.Name)
			errs = append(errs, field.Duplicate(path, msg))
			return errors.New("issuer conflict detected")
		}
		return nil
	}); err != nil && err.Error() != "issuer conflict detected" {
		errs = append(errs, field.InternalError(path, err))
	}

	return errs
}

// validateIdentityProviderRefs ensures that all referenced IdentityProviders exist and are enabled.
// Empty refs list is valid (means accept all enabled IDPs).
func validateIdentityProviderRefs(
	ctx context.Context,
	refs []string,
	path *field.Path,
) field.ErrorList {
	if len(refs) == 0 {
		// Empty refs is valid - means accept all enabled IDPs
		return nil
	}

	reader := getWebhookReader()
	if reader == nil || path == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// List all IdentityProviders
	idpList := &IdentityProviderList{}
	if err := reader.List(ctx, idpList); err != nil {
		return field.ErrorList{field.InternalError(path, err)}
	}

	// Build map of available enabled providers
	enabledProviders := make(map[string]bool)
	for i := range idpList.Items {
		idp := &idpList.Items[i]
		if !idp.Spec.Disabled {
			enabledProviders[idp.Name] = true
		}
	}

	// Check that all refs point to valid, enabled providers
	var errs field.ErrorList
	for i, ref := range refs {
		if !enabledProviders[ref] {
			errs = append(errs, field.NotFound(path.Index(i), ref))
		}
	}

	return errs
}

// validateIDPFieldCombinations ensures that the new multi-IDP fields are used correctly.
// Rules:
// 1. Cannot mix AllowedIdentityProviders with AllowedIdentityProvidersForRequests (mutually exclusive)
// 2. Cannot mix AllowedIdentityProviders with AllowedIdentityProvidersForApprovers (mutually exclusive)
// 3. If AllowedIdentityProvidersForRequests is set, AllowedIdentityProvidersForApprovers must also be set (or both empty)
func validateIDPFieldCombinations(spec *BreakglassEscalationSpec, specPath *field.Path) field.ErrorList {
	var errs field.ErrorList

	hasOldField := len(spec.AllowedIdentityProviders) > 0
	hasRequestField := len(spec.AllowedIdentityProvidersForRequests) > 0
	hasApproverField := len(spec.AllowedIdentityProvidersForApprovers) > 0

	// Check mutual exclusivity: can't mix old field with new fields
	if hasOldField && hasRequestField {
		errs = append(errs, field.Invalid(
			specPath.Child("allowedIdentityProvidersForRequests"),
			spec.AllowedIdentityProvidersForRequests,
			"cannot use allowedIdentityProvidersForRequests together with allowedIdentityProviders (use one or the other)",
		))
	}

	if hasOldField && hasApproverField {
		errs = append(errs, field.Invalid(
			specPath.Child("allowedIdentityProvidersForApprovers"),
			spec.AllowedIdentityProvidersForApprovers,
			"cannot use allowedIdentityProvidersForApprovers together with allowedIdentityProviders (use one or the other)",
		))
	}

	// Check symmetry: if one of the new fields is set, the other must be set too
	if hasRequestField && !hasApproverField {
		errs = append(errs, field.Required(
			specPath.Child("allowedIdentityProvidersForApprovers"),
			"allowedIdentityProvidersForApprovers must be set when allowedIdentityProvidersForRequests is set (or leave both empty)",
		))
	}

	if hasApproverField && !hasRequestField {
		errs = append(errs, field.Required(
			specPath.Child("allowedIdentityProvidersForRequests"),
			"allowedIdentityProvidersForRequests must be set when allowedIdentityProvidersForApprovers is set (or leave both empty)",
		))
	}

	return errs
}

// validateIdentityProviderFields ensures that IDP tracking fields (Name and Issuer) are consistent if both are set.
// These fields are typically populated during session creation and are optional for manual creation.
// Note: namePath and issuerPath must be non-nil field paths (typically provided by the webhook framework).
func validateIdentityProviderFields(
	ctx context.Context,
	idpName string,
	idpIssuer string,
	namePath *field.Path,
	issuerPath *field.Path,
) field.ErrorList {
	// If both fields are empty, that's valid (IDP not yet set during session lifecycle)
	if idpName == "" && idpIssuer == "" {
		return nil
	}

	// Validate that field paths are provided (required precondition)
	if namePath == nil || issuerPath == nil {
		return nil
	}

	reader := getWebhookReader()
	if reader == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	var errs field.ErrorList

	// If name is set, verify the IDP exists and is enabled
	if idpName != "" {
		idp := &IdentityProvider{}
		if err := reader.Get(ctx, client.ObjectKey{Name: idpName}, idp); err != nil {
			errs = append(errs, field.NotFound(namePath, idpName))
		} else if idp.Spec.Disabled {
			errs = append(errs, field.Invalid(namePath, idpName, "referenced IdentityProvider is disabled"))
		} else if idpIssuer != "" && idp.Spec.Issuer != idpIssuer {
			// If both name and issuer are set, they must match
			errs = append(errs, field.Invalid(issuerPath, idpIssuer, fmt.Sprintf("issuer does not match IdentityProvider %s (expected %s)", idpName, idp.Spec.Issuer)))
		}
	}

	return errs
}

// validateTimeoutRelationships ensures that timeout values have proper relationships:
// - approvalTimeout must be less than maxValidFor (if both are set)
// - idleTimeout must be less than maxValidFor (if both are set)
// - All timeout values must be positive durations
func validateTimeoutRelationships(spec *BreakglassEscalationSpec, specPath *field.Path) field.ErrorList {
	var errs field.ErrorList

	// Get durations - these have defaults ("1h") in the spec comments
	maxValidFor := spec.MaxValidFor
	approvalTimeout := spec.ApprovalTimeout
	idleTimeout := spec.IdleTimeout

	// Helper to parse and validate duration string
	parseDuration := func(durationStr string, fieldName string, path *field.Path) (time.Duration, *field.Error) {
		if durationStr == "" {
			return 0, nil // Not set, return zero
		}

		duration, err := time.ParseDuration(durationStr)
		if err != nil {
			return 0, field.Invalid(path, durationStr, fmt.Sprintf("invalid duration format: %v", err))
		}

		if duration <= 0 {
			return 0, field.Invalid(path, durationStr, fieldName+" must be greater than 0")
		}

		return duration, nil
	}

	// Parse and validate maxValidFor
	maxValidForDuration, maxValidForErr := parseDuration(maxValidFor, "maxValidFor", specPath.Child("maxValidFor"))
	if maxValidForErr != nil {
		errs = append(errs, maxValidForErr)
		return errs // Can't compare if maxValidFor is invalid
	}

	// Parse and validate approvalTimeout
	approvalTimeoutDuration, approvalTimeoutErr := parseDuration(approvalTimeout, "approvalTimeout", specPath.Child("approvalTimeout"))
	if approvalTimeoutErr != nil {
		errs = append(errs, approvalTimeoutErr)
	} else if approvalTimeout != "" && approvalTimeoutDuration >= maxValidForDuration {
		errs = append(errs, field.Invalid(
			specPath.Child("approvalTimeout"),
			approvalTimeout,
			fmt.Sprintf("approvalTimeout (%v) must be less than maxValidFor (%v)", approvalTimeout, maxValidFor),
		))
	}

	// Parse and validate idleTimeout
	idleTimeoutDuration, idleTimeoutErr := parseDuration(idleTimeout, "idleTimeout", specPath.Child("idleTimeout"))
	if idleTimeoutErr != nil {
		errs = append(errs, idleTimeoutErr)
	} else if idleTimeout != "" && idleTimeoutDuration >= maxValidForDuration {
		errs = append(errs, field.Invalid(
			specPath.Child("idleTimeout"),
			idleTimeout,
			fmt.Sprintf("idleTimeout (%v) must be less than maxValidFor (%v)", idleTimeout, maxValidFor),
		))
	}

	return errs
}

// the session is allowed by the associated escalation rule.
// This is Session Authorization Webhook validation.
//
// Rules:
// - If session.identityProviderName is not set, authorization passes (single-IDP or manual creation)
// - Finds all escalations that match the session's cluster and grantedGroup
// - If any matching escalation has allowedIdentityProviders set, verifies session's IDP is in the list
// - If all matching escalations have empty allowedIdentityProviders, authorization passes (all IDPs allowed)
//
// This prevents users from using escalations that don't allow their IDP and provides
// defense-in-depth against IDP spoofing attempts.
func validateSessionIdentityProviderAuthorization(
	ctx context.Context,
	sessionCluster string,
	sessionGrantedGroup string,
	sessionIDPName string,
	path *field.Path,
) field.ErrorList {
	// If no IDP name is set, skip authorization check
	// (either single-IDP mode or manually created session)
	if sessionIDPName == "" {
		return nil
	}

	reader := getWebhookReader()
	if reader == nil || path == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Load all escalations to find those matching this session's cluster and group
	escalationList := &BreakglassEscalationList{}
	if err := reader.List(ctx, escalationList); err != nil {
		// If we can't list escalations, we can't validate - let it pass
		// The normal escalation validation will catch issues
		return nil
	}

	// Find escalations that match this session's cluster and grantedGroup
	var relevantEscalations []*BreakglassEscalation
	for i := range escalationList.Items {
		esc := &escalationList.Items[i]

		// Check if escalation's escalatedGroup matches session's grantedGroup
		if esc.Spec.EscalatedGroup != sessionGrantedGroup {
			continue
		}

		// Check if escalation's clusters include this session's cluster
		clusterMatches := false
		for _, allowedCluster := range esc.Spec.Allowed.Clusters {
			if allowedCluster == sessionCluster {
				clusterMatches = true
				break
			}
		}

		if clusterMatches {
			relevantEscalations = append(relevantEscalations, esc)
		}
	}

	// If no escalations match this session, that's an error but should be caught elsewhere
	// We're only validating IDP authorization here
	if len(relevantEscalations) == 0 {
		return nil
	}

	// Check if ANY matching escalation disallows this IDP
	var errs field.ErrorList
	for _, esc := range relevantEscalations {
		// If escalation has no allowed IDPs list, all enabled IDPs are allowed - short-circuit to success
		if len(esc.Spec.AllowedIdentityProviders) == 0 {
			// At least one escalation allows all IDPs (unrestricted), so authorization passes
			// This is a short-circuit: if any escalation is unrestricted for this user, they're authorized
			return nil
		}

		// Check if session's IDP is in escalation's allowed list
		found := false
		for _, allowedIDP := range esc.Spec.AllowedIdentityProviders {
			if allowedIDP == sessionIDPName {
				found = true
				break
			}
		}

		if !found {
			// This matching escalation doesn't allow this IDP
			errs = append(errs, field.Forbidden(
				path,
				fmt.Sprintf("IdentityProvider %q is not allowed by escalation %q (allowed IDPs: %v)",
					sessionIDPName, esc.Name, esc.Spec.AllowedIdentityProviders),
			))
		}
	}

	return errs
}

// validateIdentifierFormat validates that an identifier (like group name, user email, cluster name) follows reasonable patterns
func validateIdentifierFormat(value string, fieldPath *field.Path) field.ErrorList {
	if value == "" {
		return nil
	}

	var errs field.ErrorList

	// Check length limits
	if len(value) > 253 {
		errs = append(errs, field.TooLong(fieldPath, value, 253))
	}

	// Check for valid characters (alphanumeric, dots, dashes, underscores, @)
	// Allows email-like formats and standard identifiers
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@:/"
	for _, ch := range value {
		found := false
		for _, valid := range validChars {
			if ch == valid {
				found = true
				break
			}
		}
		if !found {
			// Check if it's another allowed special character
			if !isValidSpecialCharForID(ch) {
				errs = append(errs, field.Invalid(fieldPath, value, "contains invalid characters"))
				break
			}
		}
	}

	return errs
}

// isValidSpecialCharForID validates special characters allowed in identifiers
func isValidSpecialCharForID(ch rune) bool {
	validSpecial := []rune{'*', '?', '[', ']', '(', ')', '+', '|', '^', '$', '\\'}
	for _, v := range validSpecial {
		if ch == v {
			return true
		}
	}
	return false
}

// validateURLFormat validates that a string is a valid URL
func validateURLFormat(urlStr string, fieldPath *field.Path) field.ErrorList {
	if urlStr == "" {
		return nil
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return field.ErrorList{field.Invalid(fieldPath, urlStr, fmt.Sprintf("invalid URL format: %v", err))}
	}

	var errs field.ErrorList

	// Require scheme
	if u.Scheme == "" {
		errs = append(errs, field.Invalid(fieldPath, urlStr, "URL must include scheme (http or https)"))
	}

	// Only allow http and https
	if u.Scheme != "http" && u.Scheme != "https" {
		errs = append(errs, field.Invalid(fieldPath, urlStr, "only http and https schemes are allowed"))
	}

	// Require host
	if u.Host == "" {
		errs = append(errs, field.Invalid(fieldPath, urlStr, "URL must include a host"))
	}

	return errs
}

// validateEmailDomainList validates that email domains are reasonable
func validateEmailDomainList(domains []string, fieldPath *field.Path) field.ErrorList {
	if len(domains) == 0 {
		return nil
	}

	var errs field.ErrorList
	seenDomains := make(map[string]bool)

	for i, domain := range domains {
		// Check for duplicates
		if seenDomains[domain] {
			errs = append(errs, field.Duplicate(fieldPath.Index(i), domain))
			continue
		}
		seenDomains[domain] = true

		// Validate domain format
		if len(domain) == 0 || len(domain) > 253 {
			errs = append(errs, field.Invalid(fieldPath.Index(i), domain, "domain must be between 1 and 253 characters"))
			continue
		}

		// Basic domain validation - should have at least one dot
		if !containsDot(domain) && domain != "localhost" {
			errs = append(errs, field.Invalid(fieldPath.Index(i), domain, "domain should include a dot (e.g., example.com)"))
		}

		// Check for valid characters in domain
		for _, ch := range domain {
			if !isValidDomainChar(ch) {
				errs = append(errs, field.Invalid(fieldPath.Index(i), domain, "domain contains invalid characters"))
				break
			}
		}
	}

	return errs
}

// containsDot checks if a string contains a dot
func containsDot(s string) bool {
	for _, ch := range s {
		if ch == '.' {
			return true
		}
	}
	return false
}

// isValidDomainChar checks if a character is valid in a domain name
func isValidDomainChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '.' || ch == '-'
}

// validateStringListNoDuplicates validates that a string list has no duplicates
func validateStringListNoDuplicates(values []string, fieldPath *field.Path) field.ErrorList {
	if len(values) == 0 {
		return nil
	}

	var errs field.ErrorList
	seen := make(map[string]bool)

	for i, val := range values {
		if seen[val] {
			errs = append(errs, field.Duplicate(fieldPath.Index(i), val))
		}
		seen[val] = true
	}

	return errs
}

// validateNonEmptyStringList validates that a list is not empty and contains non-empty strings
func validateNonEmptyStringList(values []string, fieldPath *field.Path, minItems int) field.ErrorList {
	if len(values) < minItems {
		return field.ErrorList{field.Required(fieldPath, fmt.Sprintf("must have at least %d items", minItems))}
	}

	var errs field.ErrorList
	for i, val := range values {
		if val == "" {
			errs = append(errs, field.Required(fieldPath.Index(i), "string cannot be empty"))
		}
	}

	return errs
}
