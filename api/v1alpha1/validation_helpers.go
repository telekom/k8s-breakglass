package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// dayPattern matches duration strings with day units (e.g., "90d", "7d", "1d12h")
var dayPattern = regexp.MustCompile(`^(\d+)d(.*)$`)

// ParseDuration parses a duration string with extended support for day units.
// Go's time.ParseDuration only supports up to hours (h), but this function
// also accepts days (d) where 1d = 24h.
//
// Examples:
//   - "90d" -> 90 days (2160 hours)
//   - "7d" -> 7 days (168 hours)
//   - "1d12h" -> 1 day and 12 hours (36 hours)
//   - "2h30m" -> 2 hours and 30 minutes (standard Go duration)
//
// Returns an error if the duration string is invalid.
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}

	// Check if the duration contains day units
	if matches := dayPattern.FindStringSubmatch(s); matches != nil {
		days, err := strconv.Atoi(matches[1])
		if err != nil {
			return 0, fmt.Errorf("invalid day value: %w", err)
		}

		// Convert days to hours
		daysDuration := time.Duration(days) * 24 * time.Hour

		// Parse the remainder if present (e.g., "12h" in "1d12h")
		remainder := matches[2]
		if remainder != "" {
			remainderDuration, err := time.ParseDuration(remainder)
			if err != nil {
				return 0, fmt.Errorf("invalid duration after days: %w", err)
			}
			return daysDuration + remainderDuration, nil
		}

		return daysDuration, nil
	}

	// No day units, use standard Go parsing
	return time.ParseDuration(s)
}

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
		zap.S().Warnw("ensureClusterWideUniqueName called without context, using fallback")
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

	// Validate issuer is a valid HTTPS URL
	if errs := validateHTTPSURL(issuer, path); len(errs) > 0 {
		return errs
	}

	reader := getWebhookReader()
	if reader == nil || path == nil {
		return nil
	}

	// Use provided context with timeout boundary for webhook operations
	// Webhooks must respond within 10 seconds per Kubernetes admission webhook requirements
	if ctx == nil {
		zap.S().Errorw("CRITICAL: ensureClusterWideUniqueIssuer called without context - creating timeout-bounded fallback")
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
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

	var errs field.ErrorList
	errs = append(errs, validateStringListNoDuplicates(refs, path)...)

	for i, ref := range refs {
		if ref == "" {
			errs = append(errs, field.Required(path.Index(i), "identity provider reference cannot be empty"))
		}
	}

	reader := getWebhookReader()
	if reader == nil || path == nil {
		return errs
	}

	if ctx == nil {
		zap.S().Warnw("validateIdentityProviderRefs called without context, using fallback")
		ctx = context.Background()
	}

	// List all IdentityProviders
	idpList := &IdentityProviderList{}
	if err := reader.List(ctx, idpList); err != nil {
		errs = append(errs, field.InternalError(path, err))
		return errs
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
	for i, ref := range refs {
		if ref == "" {
			continue
		}
		if !enabledProviders[ref] {
			errs = append(errs, field.NotFound(path.Index(i), ref))
		}
	}

	return errs
}

func validateIdentityProviderRefsFormat(refs []string, path *field.Path) field.ErrorList {
	if len(refs) == 0 || path == nil {
		return nil
	}

	var errs field.ErrorList
	errs = append(errs, validateStringListNoDuplicates(refs, path)...)
	for i, ref := range refs {
		if strings.TrimSpace(ref) == "" {
			errs = append(errs, field.Required(path.Index(i), "identity provider reference cannot be empty"))
		}
	}
	return errs
}

// validateMailProviderReference currently no-ops during admission. Runtime reconcilers surface
// missing/disabled MailProviders via conditions and events to avoid blocking CR creation.
func validateMailProviderReference(ctx context.Context, mailProvider string, path *field.Path) field.ErrorList {
	if mailProvider == "" || path == nil {
		return nil
	}

	reader := getWebhookReader()
	if reader == nil {
		return nil
	}

	if ctx == nil {
		zap.S().Warnw("validateMailProviderReference called without context, using fallback")
		ctx = context.Background()
	}

	mailProviderObj := &MailProvider{}
	if err := reader.Get(ctx, client.ObjectKey{Name: mailProvider}, mailProviderObj); err != nil {
		if apierrors.IsNotFound(err) {
			return field.ErrorList{field.NotFound(path, mailProvider)}
		}
		return field.ErrorList{field.InternalError(path, err)}
	}

	if mailProviderObj.Spec.Disabled {
		return field.ErrorList{field.Invalid(path, mailProvider, "referenced MailProvider is disabled")}
	}

	return nil
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
		zap.S().Warnw("validateIdentityProviderFields called without context, using fallback")
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
		} else if idpIssuer != "" {
			// If both name and issuer are set, verify they match the IDP's issuer or authority
			// Normalize for comparison (remove trailing slashes)
			issuerNorm := strings.TrimRight(idpIssuer, "/")
			idpIssuerNorm := strings.TrimRight(idp.Spec.Issuer, "/")
			idpAuthorityNorm := strings.TrimRight(idp.Spec.OIDC.Authority, "/")

			// Match if issuer matches Spec.Issuer (when set) OR OIDC.Authority (as fallback)
			// This mirrors the runtime behavior in identity_provider_loader.go
			issuerMatch := (idp.Spec.Issuer != "" && idpIssuerNorm == issuerNorm) ||
				(idpAuthorityNorm == issuerNorm)

			if !issuerMatch {
				expectedIssuer := idp.Spec.Issuer
				if expectedIssuer == "" {
					expectedIssuer = idp.Spec.OIDC.Authority
				}
				errs = append(errs, field.Invalid(issuerPath, idpIssuer, fmt.Sprintf("issuer does not match IdentityProvider %s (expected %s)", idpName, expectedIssuer)))
			}
		}
	}

	return errs
}

// validateTimeoutRelationships ensures that timeout values have proper relationships:
// - approvalTimeout must be less than or equal to maxValidFor (if both are set)
// - All timeout values must be positive durations
func validateTimeoutRelationships(spec *BreakglassEscalationSpec, specPath *field.Path) field.ErrorList {
	var errs field.ErrorList

	// Get durations - these have defaults ("1h") in the spec comments
	maxValidFor := spec.MaxValidFor
	approvalTimeout := spec.ApprovalTimeout

	// Helper to parse and validate duration string (supports day units like "7d", "90d")
	parseDuration := func(durationStr string, fieldName string, path *field.Path) (time.Duration, *field.Error) {
		if durationStr == "" {
			return 0, nil // Not set, return zero
		}

		duration, err := ParseDuration(durationStr)
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
	} else if approvalTimeout != "" && approvalTimeoutDuration > maxValidForDuration {
		errs = append(errs, field.Invalid(
			specPath.Child("approvalTimeout"),
			approvalTimeout,
			fmt.Sprintf("approvalTimeout (%v) must be less than or equal to maxValidFor (%v)", approvalTimeout, maxValidFor),
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
		zap.S().Warnw("validateSessionIdentityProviderAuthorization called without context, using fallback")
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

// validateHTTPSURL ensures a URL is valid and uses HTTPS scheme
func validateHTTPSURL(urlStr string, fieldPath *field.Path) field.ErrorList {
	if urlStr == "" {
		return nil
	}

	if errs := validateURLFormat(urlStr, fieldPath); len(errs) > 0 {
		return errs
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return field.ErrorList{field.Invalid(fieldPath, urlStr, fmt.Sprintf("invalid URL format: %v", err))}
	}

	var errs field.ErrorList
	if u.Scheme != "https" {
		errs = append(errs, field.Invalid(fieldPath, urlStr, "only https scheme is allowed"))
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

// validateStringListEntriesNotEmpty ensures that when a list is provided, none of the entries are empty or only whitespace.
func validateStringListEntriesNotEmpty(values []string, fieldPath *field.Path) field.ErrorList {
	if len(values) == 0 {
		return nil
	}

	var errs field.ErrorList
	for i, val := range values {
		if strings.TrimSpace(val) == "" {
			errs = append(errs, field.Required(fieldPath.Index(i), "value cannot be empty"))
		}
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

// validateDurationFormat validates that a string is a valid duration format.
// Supports extended duration units including days (e.g., "7d", "90d", "1d12h").
func validateDurationFormat(duration string, fieldPath *field.Path) field.ErrorList {
	if duration == "" || fieldPath == nil {
		return nil
	}

	if _, err := ParseDuration(duration); err != nil {
		return field.ErrorList{field.Invalid(fieldPath, duration, fmt.Sprintf("invalid duration format: %v", err))}
	}

	return nil
}

// validateClusterAuthConfig validates that exactly one authentication method is configured
// for a ClusterConfig. Either kubeconfigSecretRef OR oidcAuth/oidcFromIdentityProvider must be specified, but not both.
func validateClusterAuthConfig(spec ClusterConfigSpec, specPath *field.Path) field.ErrorList {
	var errs field.ErrorList

	hasKubeconfig := spec.KubeconfigSecretRef != nil
	hasOIDC := spec.OIDCAuth != nil
	hasOIDCFromIDP := spec.OIDCFromIdentityProvider != nil

	// Check that at least one auth method is specified
	if !hasKubeconfig && !hasOIDC && !hasOIDCFromIDP {
		errs = append(errs, field.Required(specPath,
			"either kubeconfigSecretRef, oidcAuth, or oidcFromIdentityProvider must be specified for cluster authentication"))
		return errs
	}

	// Check that only one auth method is specified (mutually exclusive)
	if hasKubeconfig && (hasOIDC || hasOIDCFromIDP) {
		errs = append(errs, field.Invalid(specPath, nil,
			"kubeconfigSecretRef is mutually exclusive with oidcAuth and oidcFromIdentityProvider"))
		return errs
	}

	// oidcAuth and oidcFromIdentityProvider are mutually exclusive
	if hasOIDC && hasOIDCFromIDP {
		errs = append(errs, field.Invalid(specPath, nil,
			"oidcAuth and oidcFromIdentityProvider are mutually exclusive"))
		return errs
	}

	// Validate authType matches the provided auth configuration
	if hasKubeconfig {
		if spec.AuthType != "" && spec.AuthType != ClusterAuthTypeKubeconfig {
			errs = append(errs, field.Invalid(specPath.Child("authType"), spec.AuthType,
				"authType must be 'Kubeconfig' when kubeconfigSecretRef is specified"))
		}
		// Validate kubeconfigSecretRef fields
		if spec.KubeconfigSecretRef.Name == "" {
			errs = append(errs, field.Required(specPath.Child("kubeconfigSecretRef", "name"),
				"secret name is required"))
		}
		if spec.KubeconfigSecretRef.Namespace == "" {
			errs = append(errs, field.Required(specPath.Child("kubeconfigSecretRef", "namespace"),
				"secret namespace is required"))
		}
	}

	if hasOIDC || hasOIDCFromIDP {
		if spec.AuthType != "" && spec.AuthType != ClusterAuthTypeOIDC {
			errs = append(errs, field.Invalid(specPath.Child("authType"), spec.AuthType,
				"authType must be 'OIDC' when oidcAuth or oidcFromIdentityProvider is specified"))
		}
		if hasOIDC {
			errs = append(errs, validateOIDCAuthConfig(spec.OIDCAuth, specPath.Child("oidcAuth"))...)
		}
		if hasOIDCFromIDP {
			errs = append(errs, validateOIDCFromIdentityProviderConfig(spec.OIDCFromIdentityProvider, specPath.Child("oidcFromIdentityProvider"))...)
		}
	}

	return errs
}

// validateOIDCFromIdentityProviderConfig validates the OIDC-from-IDP configuration.
func validateOIDCFromIdentityProviderConfig(cfg *OIDCFromIdentityProviderConfig, fieldPath *field.Path) field.ErrorList {
	if cfg == nil {
		return nil
	}

	var errs field.ErrorList

	// Validate required fields
	if cfg.Name == "" {
		errs = append(errs, field.Required(fieldPath.Child("name"), "IdentityProvider name is required"))
	}

	if cfg.Server == "" {
		errs = append(errs, field.Required(fieldPath.Child("server"), "cluster API server URL is required"))
	} else {
		errs = append(errs, validateHTTPSURL(cfg.Server, fieldPath.Child("server"))...)
	}

	// Validate clientSecretRef if provided
	if cfg.ClientSecretRef != nil {
		if cfg.ClientSecretRef.Name == "" {
			errs = append(errs, field.Required(fieldPath.Child("clientSecretRef", "name"), "secret name is required"))
		}
		if cfg.ClientSecretRef.Namespace == "" {
			errs = append(errs, field.Required(fieldPath.Child("clientSecretRef", "namespace"), "secret namespace is required"))
		}
	}

	// Validate caSecretRef if provided
	if cfg.CASecretRef != nil {
		if cfg.CASecretRef.Name == "" {
			errs = append(errs, field.Required(fieldPath.Child("caSecretRef", "name"), "secret name is required"))
		}
		if cfg.CASecretRef.Namespace == "" {
			errs = append(errs, field.Required(fieldPath.Child("caSecretRef", "namespace"), "secret namespace is required"))
		}
	}

	return errs
}

// validateOIDCAuthConfig validates the OIDC authentication configuration for a cluster.
func validateOIDCAuthConfig(oidc *OIDCAuthConfig, fieldPath *field.Path) field.ErrorList {
	if oidc == nil {
		return nil
	}

	var errs field.ErrorList

	// Validate required fields
	if oidc.IssuerURL == "" {
		errs = append(errs, field.Required(fieldPath.Child("issuerURL"), "OIDC issuer URL is required"))
	} else {
		errs = append(errs, validateHTTPSURL(oidc.IssuerURL, fieldPath.Child("issuerURL"))...)
	}

	if oidc.ClientID == "" {
		errs = append(errs, field.Required(fieldPath.Child("clientID"), "OIDC client ID is required"))
	}

	if oidc.Server == "" {
		errs = append(errs, field.Required(fieldPath.Child("server"), "cluster API server URL is required"))
	} else {
		errs = append(errs, validateHTTPSURL(oidc.Server, fieldPath.Child("server"))...)
	}

	// Validate clientSecretRef if provided
	if oidc.ClientSecretRef != nil {
		if oidc.ClientSecretRef.Name == "" {
			errs = append(errs, field.Required(fieldPath.Child("clientSecretRef", "name"), "secret name is required"))
		}
		if oidc.ClientSecretRef.Namespace == "" {
			errs = append(errs, field.Required(fieldPath.Child("clientSecretRef", "namespace"), "secret namespace is required"))
		}
	}

	// Validate caSecretRef if provided
	if oidc.CASecretRef != nil {
		if oidc.CASecretRef.Name == "" {
			errs = append(errs, field.Required(fieldPath.Child("caSecretRef", "name"), "secret name is required"))
		}
		if oidc.CASecretRef.Namespace == "" {
			errs = append(errs, field.Required(fieldPath.Child("caSecretRef", "namespace"), "secret namespace is required"))
		}
	}

	// Validate token exchange config if provided
	if oidc.TokenExchange != nil && oidc.TokenExchange.Enabled {
		// Token exchange requires client secret for authentication
		if oidc.ClientSecretRef == nil {
			errs = append(errs, field.Required(fieldPath.Child("clientSecretRef"),
				"clientSecretRef is required when token exchange is enabled"))
		}

		// Token exchange requires a subject token secret reference
		if oidc.TokenExchange.SubjectTokenSecretRef == nil {
			errs = append(errs, field.Required(fieldPath.Child("tokenExchange", "subjectTokenSecretRef"),
				"subjectTokenSecretRef is required when token exchange is enabled"))
		} else {
			// Validate the subject token secret reference
			if oidc.TokenExchange.SubjectTokenSecretRef.Name == "" {
				errs = append(errs, field.Required(fieldPath.Child("tokenExchange", "subjectTokenSecretRef", "name"),
					"secret name is required"))
			}
		}

		// Validate actor token secret reference if provided
		if oidc.TokenExchange.ActorTokenSecretRef != nil && oidc.TokenExchange.ActorTokenSecretRef.Name == "" {
			errs = append(errs, field.Required(fieldPath.Child("tokenExchange", "actorTokenSecretRef", "name"),
				"secret name is required"))
		}
	}

	// Validate scopes - check for duplicates
	if len(oidc.Scopes) > 0 {
		errs = append(errs, validateStringListNoDuplicates(oidc.Scopes, fieldPath.Child("scopes"))...)
	}

	return errs
}

// validateSchedulingOptions validates SchedulingOptions configuration.
func validateSchedulingOptions(opts *SchedulingOptions, fieldPath *field.Path) field.ErrorList {
	if opts == nil {
		return nil
	}

	var errs field.ErrorList

	if len(opts.Options) == 0 {
		errs = append(errs, field.Required(fieldPath.Child("options"), "at least one scheduling option is required"))
		return errs
	}

	// Track option names for uniqueness
	seenNames := make(map[string]bool)
	// Track if a default is already set
	defaultCount := 0

	for i, opt := range opts.Options {
		optPath := fieldPath.Child("options").Index(i)

		// Validate name is set
		if opt.Name == "" {
			errs = append(errs, field.Required(optPath.Child("name"), "option name is required"))
		} else {
			// Check for duplicate names
			if seenNames[opt.Name] {
				errs = append(errs, field.Duplicate(optPath.Child("name"), opt.Name))
			}
			seenNames[opt.Name] = true
		}

		// Validate displayName is set
		if opt.DisplayName == "" {
			errs = append(errs, field.Required(optPath.Child("displayName"), "displayName is required"))
		}

		// Count defaults
		if opt.Default {
			defaultCount++
		}
	}

	// Only one option can be marked as default
	if defaultCount > 1 {
		errs = append(errs, field.Invalid(fieldPath.Child("options"), defaultCount,
			"only one option can be marked as default"))
	}

	return errs
}

// validateNamespaceConstraints validates the NamespaceConstraints configuration.
func validateNamespaceConstraints(nc *NamespaceConstraints, fieldPath *field.Path) field.ErrorList {
	if nc == nil {
		return nil
	}

	var errs field.ErrorList

	// Validate allowed namespaces filter - use existing validator
	if nc.AllowedNamespaces != nil && nc.AllowedNamespaces.IsEmpty() {
		errs = append(errs, field.Required(fieldPath.Child("allowedNamespaces"),
			"at least one of patterns or selectorTerms must be specified"))
	}

	// Validate denied namespaces filter - use existing validator
	if nc.DeniedNamespaces != nil && nc.DeniedNamespaces.IsEmpty() {
		errs = append(errs, field.Required(fieldPath.Child("deniedNamespaces"),
			"at least one of patterns or selectorTerms must be specified"))
	}

	// Validate default namespace if specified
	if nc.DefaultNamespace != "" {
		// Default namespace should be allowed if allowedNamespaces is specified
		if nc.AllowedNamespaces != nil && nc.AllowedNamespaces.HasPatterns() {
			found := false
			for _, pattern := range nc.AllowedNamespaces.Patterns {
				// Exact match check (patterns may contain wildcards, so only check exact matches)
				if pattern == nc.DefaultNamespace {
					found = true
					break
				}
			}
			// Note: We can't reliably check wildcard patterns or selector terms at validation time
			// Those require runtime evaluation against actual namespace resources
			if !found && !nc.AllowedNamespaces.HasSelectorTerms() {
				// Check if any pattern could be a wildcard that matches
				hasWildcard := false
				for _, pattern := range nc.AllowedNamespaces.Patterns {
					if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
						hasWildcard = true
						break
					}
				}
				if !hasWildcard {
					errs = append(errs, field.Invalid(fieldPath.Child("defaultNamespace"),
						nc.DefaultNamespace, "default namespace must be in the allowed namespaces patterns"))
				}
			}
		}

		// Default namespace should not be denied
		if nc.DeniedNamespaces != nil && nc.DeniedNamespaces.HasPatterns() {
			for _, pattern := range nc.DeniedNamespaces.Patterns {
				if pattern == nc.DefaultNamespace {
					errs = append(errs, field.Invalid(fieldPath.Child("defaultNamespace"),
						nc.DefaultNamespace, "default namespace cannot be in the denied namespaces patterns"))
					break
				}
			}
		}
	}

	return errs
}

// warnNamespaceConstraintIssues returns warnings for potential namespace constraint configuration issues.
// These are not errors but could lead to unexpected behavior at runtime.
func warnNamespaceConstraintIssues(nc *NamespaceConstraints, targetNamespace string) []string {
	if nc == nil {
		return nil
	}

	var warnings []string

	// Warn if allowUserNamespace is false but no defaultNamespace is set
	// This means users can't specify a namespace and there's no default,
	// so the API will fall back to "breakglass-debug"
	if !nc.AllowUserNamespace && nc.DefaultNamespace == "" {
		warnings = append(warnings,
			"namespaceConstraints.allowUserNamespace is false but no defaultNamespace is set; "+
				"sessions will use 'breakglass-debug' as fallback. Consider setting an explicit defaultNamespace.")
	}

	// Warn if allowUserNamespace is false but allowedNamespaces patterns are set
	// This is confusing configuration - patterns are useless if users can't specify namespaces
	if !nc.AllowUserNamespace && nc.AllowedNamespaces != nil && nc.AllowedNamespaces.HasPatterns() {
		warnings = append(warnings,
			"namespaceConstraints.allowedNamespaces patterns are set but allowUserNamespace is false; "+
				"the patterns will be ignored since users cannot specify namespaces.")
	}

	// Warn if allowUserNamespace is true but no defaultNamespace is set
	// If a user doesn't specify a namespace, what happens?
	if nc.AllowUserNamespace && nc.DefaultNamespace == "" {
		warnings = append(warnings,
			"namespaceConstraints.allowUserNamespace is true but no defaultNamespace is set; "+
				"sessions without an explicit namespace will use 'breakglass-debug' as fallback.")
	}

	// Warn if there's a targetNamespace at spec level but also namespaceConstraints
	// This could be confusing about which takes precedence
	if targetNamespace != "" && nc.DefaultNamespace != "" && targetNamespace != nc.DefaultNamespace {
		warnings = append(warnings,
			"Both spec.targetNamespace and namespaceConstraints.defaultNamespace are set with different values; "+
				"namespaceConstraints.defaultNamespace takes precedence when namespaceConstraints is configured.")
	}

	return warnings
}

// validateImpersonationConfig validates the ImpersonationConfig configuration.
func validateImpersonationConfig(ic *ImpersonationConfig, fieldPath *field.Path) field.ErrorList {
	if ic == nil {
		return nil
	}

	var errs field.ErrorList

	// Validate service account reference
	if ic.ServiceAccountRef != nil {
		if ic.ServiceAccountRef.Name == "" {
			errs = append(errs, field.Required(
				fieldPath.Child("serviceAccountRef").Child("name"),
				"service account name is required"))
		}
		if ic.ServiceAccountRef.Namespace == "" {
			errs = append(errs, field.Required(
				fieldPath.Child("serviceAccountRef").Child("namespace"),
				"service account namespace is required"))
		}
	}

	return errs
}

// validateAuxiliaryResources validates auxiliary resource definitions.
func validateAuxiliaryResources(resources []AuxiliaryResource, fieldPath *field.Path) field.ErrorList {
	var errs field.ErrorList
	names := make(map[string]bool)

	for i, res := range resources {
		resPath := fieldPath.Index(i)

		// Name is required
		if res.Name == "" {
			errs = append(errs, field.Required(resPath.Child("name"), "name is required"))
		} else {
			// Check for duplicates
			if names[res.Name] {
				errs = append(errs, field.Duplicate(resPath.Child("name"), res.Name))
			}
			names[res.Name] = true
		}

		// Either template or templateString is required (mutually exclusive)
		hasTemplate := len(res.Template.Raw) > 0 || res.Template.Object != nil
		hasTemplateString := res.TemplateString != ""
		if !hasTemplate && !hasTemplateString {
			errs = append(errs, field.Required(resPath.Child("template"),
				"either template or templateString is required"))
		} else if hasTemplate && hasTemplateString {
			errs = append(errs, field.Invalid(resPath.Child("templateString"), "",
				"template and templateString are mutually exclusive"))
		}

		// Category validation - these are common categories, but others are allowed
		// Only validate format, not specific values, to allow extensibility
		if res.Category != "" {
			// Check for valid DNS label format (lowercase alphanumeric with hyphens)
			if len(res.Category) > 63 {
				errs = append(errs, field.TooLong(resPath.Child("category"), res.Category, 63))
			}
			// Validate category format - should be lowercase alphanumeric with hyphens
			for _, ch := range res.Category {
				if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
					errs = append(errs, field.Invalid(resPath.Child("category"), res.Category,
						"category must be lowercase alphanumeric with hyphens (e.g., 'network-policy', 'monitoring')"))
					break
				}
			}
		}
	}

	return errs
}

// validateDebugSessionNotificationConfig validates notification configuration.
func validateDebugSessionNotificationConfig(cfg *DebugSessionNotificationConfig, fieldPath *field.Path) field.ErrorList {
	if cfg == nil {
		return nil
	}

	var errs field.ErrorList

	// Validate email formats in additionalRecipients
	for i, email := range cfg.AdditionalRecipients {
		if email == "" {
			errs = append(errs, field.Required(fieldPath.Child("additionalRecipients").Index(i), "email cannot be empty"))
		} else if !strings.Contains(email, "@") {
			errs = append(errs, field.Invalid(fieldPath.Child("additionalRecipients").Index(i), email, "must be a valid email address"))
		}
	}

	// Validate excluded recipients
	if cfg.ExcludedRecipients != nil {
		errs = append(errs, validateStringListEntriesNotEmpty(cfg.ExcludedRecipients.Users, fieldPath.Child("excludedRecipients", "users"))...)
		errs = append(errs, validateStringListEntriesNotEmpty(cfg.ExcludedRecipients.Groups, fieldPath.Child("excludedRecipients", "groups"))...)
	}

	return errs
}

// validateDebugRequestReasonConfig validates request reason configuration.
func validateDebugRequestReasonConfig(cfg *DebugRequestReasonConfig, fieldPath *field.Path) field.ErrorList {
	if cfg == nil {
		return nil
	}

	var errs field.ErrorList

	// Validate minLength <= maxLength
	if cfg.MinLength > cfg.MaxLength {
		errs = append(errs, field.Invalid(fieldPath.Child("minLength"), cfg.MinLength,
			fmt.Sprintf("minLength (%d) cannot be greater than maxLength (%d)", cfg.MinLength, cfg.MaxLength)))
	}

	// Validate suggestedReasons are not empty
	errs = append(errs, validateStringListEntriesNotEmpty(cfg.SuggestedReasons, fieldPath.Child("suggestedReasons"))...)
	errs = append(errs, validateStringListNoDuplicates(cfg.SuggestedReasons, fieldPath.Child("suggestedReasons"))...)

	return errs
}

// validateDebugApprovalReasonConfig validates approval reason configuration.
func validateDebugApprovalReasonConfig(cfg *DebugApprovalReasonConfig, fieldPath *field.Path) field.ErrorList {
	if cfg == nil {
		return nil
	}

	var errs field.ErrorList

	// Validate minLength is reasonable
	if cfg.MinLength < 0 {
		errs = append(errs, field.Invalid(fieldPath.Child("minLength"), cfg.MinLength, "minLength cannot be negative"))
	}

	return errs
}

// validateDebugResourceQuotaConfig validates resource quota configuration.
func validateDebugResourceQuotaConfig(cfg *DebugResourceQuotaConfig, fieldPath *field.Path) field.ErrorList {
	if cfg == nil {
		return nil
	}

	var errs field.ErrorList

	// Validate resource quantities
	if cfg.MaxCPU != "" {
		if _, err := parseResourceQuantity(cfg.MaxCPU); err != nil {
			errs = append(errs, field.Invalid(fieldPath.Child("maxCPU"), cfg.MaxCPU,
				fmt.Sprintf("invalid CPU quantity: %v", err)))
		}
	}

	if cfg.MaxMemory != "" {
		if _, err := parseResourceQuantity(cfg.MaxMemory); err != nil {
			errs = append(errs, field.Invalid(fieldPath.Child("maxMemory"), cfg.MaxMemory,
				fmt.Sprintf("invalid memory quantity: %v", err)))
		}
	}

	if cfg.MaxStorage != "" {
		if _, err := parseResourceQuantity(cfg.MaxStorage); err != nil {
			errs = append(errs, field.Invalid(fieldPath.Child("maxStorage"), cfg.MaxStorage,
				fmt.Sprintf("invalid storage quantity: %v", err)))
		}
	}

	return errs
}

// parseResourceQuantity validates a Kubernetes resource quantity string.
func parseResourceQuantity(q string) (int64, error) {
	if q == "" {
		return 0, nil
	}
	// Simple validation - more complex parsing done by k8s at runtime
	// This catches obvious errors like invalid suffixes
	// Order matters: check longer suffixes first
	validSuffixes := []string{"Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "k", "M", "G", "T", "P", "E", "m", ""}
	hasValidSuffix := false
	for _, suffix := range validSuffixes {
		if strings.HasSuffix(q, suffix) {
			numPart := strings.TrimSuffix(q, suffix)
			if numPart == "" && suffix != "" {
				return 0, fmt.Errorf("empty numeric value")
			}
			if numPart == "" && suffix == "" {
				return 0, fmt.Errorf("empty quantity")
			}
			_, err := strconv.ParseFloat(numPart, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid numeric value: %v", err)
			}
			hasValidSuffix = true
			break
		}
	}
	if !hasValidSuffix {
		return 0, fmt.Errorf("invalid resource suffix")
	}
	return 0, nil
}

// validateDebugPDBConfig validates PodDisruptionBudget configuration.
func validateDebugPDBConfig(cfg *DebugPDBConfig, fieldPath *field.Path) field.ErrorList {
	if cfg == nil {
		return nil
	}

	var errs field.ErrorList

	// At most one of minAvailable or maxUnavailable can be set
	if cfg.MinAvailable != nil && cfg.MaxUnavailable != nil {
		errs = append(errs, field.Invalid(fieldPath, nil,
			"only one of minAvailable or maxUnavailable can be set"))
	}

	// Values must be positive
	if cfg.MinAvailable != nil && *cfg.MinAvailable < 0 {
		errs = append(errs, field.Invalid(fieldPath.Child("minAvailable"), *cfg.MinAvailable,
			"minAvailable must be non-negative"))
	}
	if cfg.MaxUnavailable != nil && *cfg.MaxUnavailable < 0 {
		errs = append(errs, field.Invalid(fieldPath.Child("maxUnavailable"), *cfg.MaxUnavailable,
			"maxUnavailable must be non-negative"))
	}

	return errs
}

// validateBindingTimeWindow validates expiresAt and effectiveFrom fields.
func validateBindingTimeWindow(effectiveFrom, expiresAt *metav1.Time, fieldPath *field.Path) field.ErrorList {
	var errs field.ErrorList

	if effectiveFrom != nil && expiresAt != nil {
		if !effectiveFrom.Before(expiresAt) {
			errs = append(errs, field.Invalid(fieldPath.Child("expiresAt"), expiresAt,
				"expiresAt must be after effectiveFrom"))
		}
	}

	return errs
}

// validateExtraDeployVariables validates extra deploy variables configuration.
func validateExtraDeployVariables(vars []ExtraDeployVariable, fieldPath *field.Path) field.ErrorList {
	if len(vars) == 0 {
		return nil
	}

	var errs field.ErrorList
	names := make(map[string]bool)

	for i, v := range vars {
		varPath := fieldPath.Index(i)

		// Check for duplicate variable names
		if names[v.Name] {
			errs = append(errs, field.Duplicate(varPath.Child("name"), v.Name))
		}
		names[v.Name] = true

		// Validate name is a valid Go identifier
		if !isValidGoIdentifier(v.Name) {
			errs = append(errs, field.Invalid(varPath.Child("name"), v.Name,
				"must be a valid Go identifier (letters, digits, underscores, starting with letter)"))
		}

		// Validate options are provided for select/multiSelect types
		if (v.InputType == InputTypeSelect || v.InputType == InputTypeMultiSelect) && len(v.Options) == 0 {
			errs = append(errs, field.Required(varPath.Child("options"),
				"options are required for select and multiSelect input types"))
		}

		// Validate options have unique values
		if len(v.Options) > 0 {
			optionValues := make(map[string]bool)
			for j, opt := range v.Options {
				if optionValues[opt.Value] {
					errs = append(errs, field.Duplicate(varPath.Child("options").Index(j).Child("value"), opt.Value))
				}
				optionValues[opt.Value] = true
			}
		}

		// Validate validation rules match input type
		if v.Validation != nil {
			errs = append(errs, validateVariableValidation(v.Validation, v.InputType, varPath.Child("validation"))...)
		}
	}

	return errs
}

// isValidGoIdentifier checks if a string is a valid Go identifier.
func isValidGoIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
				return false
			}
		} else {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
				return false
			}
		}
	}
	return true
}

// validateVariableValidation validates validation rules for a variable.
func validateVariableValidation(v *VariableValidation, inputType ExtraDeployInputType, fieldPath *field.Path) field.ErrorList {
	if v == nil {
		return nil
	}

	var errs field.ErrorList

	// Validate pattern is a valid regex for text inputs
	if v.Pattern != "" {
		if inputType != InputTypeText {
			errs = append(errs, field.Invalid(fieldPath.Child("pattern"), v.Pattern,
				"pattern validation is only valid for text input type"))
		} else if _, err := regexp.Compile(v.Pattern); err != nil {
			errs = append(errs, field.Invalid(fieldPath.Child("pattern"), v.Pattern,
				fmt.Sprintf("invalid regex pattern: %v", err)))
		}
	}

	// Validate minLength/maxLength for text inputs
	if v.MinLength != nil || v.MaxLength != nil {
		if inputType != InputTypeText {
			errs = append(errs, field.Invalid(fieldPath, nil,
				"minLength/maxLength validation is only valid for text input type"))
		}
		if v.MinLength != nil && v.MaxLength != nil && *v.MinLength > *v.MaxLength {
			errs = append(errs, field.Invalid(fieldPath.Child("maxLength"), *v.MaxLength,
				"maxLength must be greater than or equal to minLength"))
		}
	}

	// Validate min/max for number inputs
	if v.Min != "" || v.Max != "" {
		if inputType != InputTypeNumber {
			errs = append(errs, field.Invalid(fieldPath, nil,
				"min/max validation is only valid for number input type"))
		} else {
			// Validate format of min and max individually
			var minVal, maxVal float64
			var minErr, maxErr error
			if v.Min != "" {
				minVal, minErr = strconv.ParseFloat(v.Min, 64)
				if minErr != nil {
					errs = append(errs, field.Invalid(fieldPath.Child("min"), v.Min,
						fmt.Sprintf("invalid number format: %v", minErr)))
				}
			}
			if v.Max != "" {
				maxVal, maxErr = strconv.ParseFloat(v.Max, 64)
				if maxErr != nil {
					errs = append(errs, field.Invalid(fieldPath.Child("max"), v.Max,
						fmt.Sprintf("invalid number format: %v", maxErr)))
				}
			}
			// Compare min/max if both are valid
			if v.Min != "" && v.Max != "" && minErr == nil && maxErr == nil && minVal > maxVal {
				errs = append(errs, field.Invalid(fieldPath.Child("max"), v.Max,
					"max must be greater than or equal to min"))
			}
		}
	}

	// Validate minStorage/maxStorage for storageSize inputs
	if v.MinStorage != "" || v.MaxStorage != "" {
		if inputType != InputTypeStorageSize {
			errs = append(errs, field.Invalid(fieldPath, nil,
				"minStorage/maxStorage validation is only valid for storageSize input type"))
		}
	}

	// Validate minItems/maxItems for multiSelect inputs
	if v.MinItems != nil || v.MaxItems != nil {
		if inputType != InputTypeMultiSelect {
			errs = append(errs, field.Invalid(fieldPath, nil,
				"minItems/maxItems validation is only valid for multiSelect input type"))
		}
		if v.MinItems != nil && v.MaxItems != nil && *v.MinItems > *v.MaxItems {
			errs = append(errs, field.Invalid(fieldPath.Child("maxItems"), *v.MaxItems,
				"maxItems must be greater than or equal to minItems"))
		}
	}

	return errs
}
