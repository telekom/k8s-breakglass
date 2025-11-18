package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"net/url"

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

// validateSessionIdentityProviderAuthorization ensures that the IdentityProvider used to create
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
